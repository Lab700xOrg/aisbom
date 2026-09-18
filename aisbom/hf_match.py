"""Match local model files back to the Hugging Face repo they came from.

An ``hf://`` scan knows its repo, so its components get a ``modelCard``. A
local copy of the very same model used to get nothing, which is a difference
in what the scanner looked up rather than in the model. This module closes
that gap without guessing.

A wrong match is worse than no match: it puts one model's card on another
model's component, in a compliance artifact. So a match takes two things:

1. **A candidate repo from local evidence.** Either the Hugging Face cache
   layout (``models--<org>--<name>/snapshots/<commit>/…``), which the hub
   client writes and which names both the repo and the revision, or a
   ``config.json`` beside the weights whose ``_name_or_path`` has the shape of
   a repo id. File names are never used.
2. **Proof from the repo's own file listing.** The local file's SHA-256 must
   equal an LFS object id in that repo, or, for a small file stored directly
   in git, its git blob id must equal a listed ``oid``. This is what rejects a
   fine-tune whose config still names its base model: the name matches, the
   bytes do not.

If two different repos both prove out, the file gets no card; if nothing
proves out, it gets no card. Every network failure also means no card and
nothing else, the same best-effort contract as the ``hf://`` card fetch.

What is sent: repo ids and commit revisions taken from the evidence above,
and nothing else. Hashes are compared locally against the listing; paths,
file names and hashes never leave the machine. A ``_name_or_path`` that looks
like a local path, or names a directory that exists, is not a candidate, so a
checkpoint folder name cannot be leaked by asking the Hub about it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from . import remote

DISABLE_ENV_VAR = "AISBOM_NO_HF_LOOKUP"

# Recorded on the modelCard so a reader can tell an inferred link from an
# `hf://` scan, and what the link rested on.
MATCH_PROPERTY = "aisbom:hf:match"
SOURCE_CACHE = "hf-cache"
SOURCE_CONFIG = "config-name-or-path"

_CACHE_PREFIX = "models--"
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# A config.json is a few kilobytes. Anything this large is not one worth
# parsing for a single string.
_CONFIG_MAX_BYTES = 1 << 20

# Hugging Face stores every file above 10 MB in LFS, where the listing gives a
# SHA-256. Below that a file may live directly in git, where only the git blob
# id is listed, and computing that means reading the file once more.
_GIT_BLOB_MAX_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True)
class Candidate:
    repo_id: str
    revision: Optional[str]
    source: str


@dataclass(frozen=True)
class Match:
    card: Dict[str, Any]
    source: str


@dataclass
class MatchOutcome:
    matches: Dict[int, Match] = field(default_factory=dict)
    # Local model files that had at least one candidate, i.e. that caused a lookup.
    considered: int = 0
    ambiguous: int = 0

    @property
    def matched(self) -> int:
        return len(self.matches)


def disabled_by_env(environ: Mapping[str, str] = os.environ) -> bool:
    return bool(environ.get(DISABLE_ENV_VAR))


def git_blob_oid_of(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _repo_id_from_segments(segments: Sequence[str]) -> Optional[str]:
    if not 1 <= len(segments) <= 2:
        return None
    if not all(_SEGMENT_RE.match(s) and ".." not in s for s in segments):
        return None
    return "/".join(segments)


def _cache_candidate(path: Path) -> Optional[Candidate]:
    parts = path.parts
    for i, part in enumerate(parts[:-2]):
        if not part.startswith(_CACHE_PREFIX) or parts[i + 1] != "snapshots":
            continue
        # The hub client writes `org/name` as `org--name`; legacy canonical
        # models with no org have a single segment.
        repo_id = _repo_id_from_segments(part[len(_CACHE_PREFIX):].split("--"))
        if repo_id is None:
            return None
        revision = parts[i + 2] if _COMMIT_RE.match(parts[i + 2]) else None
        return Candidate(repo_id, revision, SOURCE_CACHE)
    return None


def _config_candidate(path: Path) -> Optional[Candidate]:
    config = path.parent / "config.json"
    try:
        if not config.is_file() or config.stat().st_size > _CONFIG_MAX_BYTES:
            return None
        value = json.loads(config.read_text(encoding="utf-8")).get("_name_or_path")
    except (OSError, ValueError, AttributeError):
        return None
    if not isinstance(value, str):
        return None

    # Two segments only. A bare single name is as likely to be a directory
    # the user saved to as a legacy repo id, and asking the Hub about it
    # would send that name off the machine.
    segments = value.split("/")
    if len(segments) != 2 or "--" in value:
        return None
    repo_id = _repo_id_from_segments(segments)
    if repo_id is None:
        return None
    # `outputs/final` is shaped like a repo id and is also where Trainer
    # saves; when it exists on disk, it is a path.
    if (path.parent / value).exists() or Path(value).exists():
        return None
    return Candidate(repo_id, None, SOURCE_CONFIG)


def candidates_for(path: Path) -> List[Candidate]:
    """Candidate repos for one local file, strongest evidence first."""
    found: List[Candidate] = []
    for candidate in (_cache_candidate(path), _config_candidate(path)):
        if candidate and all(c.repo_id != candidate.repo_id for c in found):
            found.append(candidate)
    return found


def _listed_ids(entries: Any) -> Optional[set]:
    """Every content id in a tree listing: LFS SHA-256s and git blob oids."""
    if not isinstance(entries, list):
        return None
    ids = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        oid = entry.get("oid")
        if isinstance(oid, str):
            ids.add(oid)
        lfs = entry.get("lfs")
        if isinstance(lfs, dict) and isinstance(lfs.get("oid"), str):
            ids.add(lfs["oid"])
    return ids


class _LocalIds:
    """The local file's content ids, computed at most once and only if needed."""

    def __init__(self, artifact: Dict[str, Any], path: Path):
        self._path = path
        digest = artifact.get("hash")
        self._sha256 = digest if isinstance(digest, str) and _SHA256_RE.match(digest) else None
        self._git_oid: Optional[str] = None
        self._git_done = False

    def sha256(self) -> Optional[str]:
        if self._sha256 is None:
            try:
                h = hashlib.sha256()
                with open(self._path, "rb") as f:
                    for block in iter(lambda: f.read(65536), b""):
                        h.update(block)
                self._sha256 = h.hexdigest()
            except OSError:
                return None
        return self._sha256

    def git_oid(self) -> Optional[str]:
        if not self._git_done:
            self._git_done = True
            try:
                if self._path.stat().st_size <= _GIT_BLOB_MAX_BYTES:
                    self._git_oid = git_blob_oid_of(self._path.read_bytes())
            except OSError:
                pass
        return self._git_oid

    def found_in(self, ids: set) -> bool:
        sha = self.sha256()
        if sha and sha in ids:
            return True
        oid = self.git_oid()
        return bool(oid and oid in ids)


def match_local_artifacts(
    artifacts: Sequence[Dict[str, Any]],
    paths: Sequence[Optional[Path]],
    fetch_index: Callable[..., Any] = None,
    fetch_card: Callable[..., Any] = None,
) -> MatchOutcome:
    """Match each local artifact to at most one HF repo, by index.

    ``paths[i]`` is where ``artifacts[i]`` was read from, or None for a remote
    artifact. Listings and cards are fetched once per repo and revision.
    """
    fetch_index = fetch_index or remote.fetch_huggingface_file_index
    fetch_card = fetch_card or remote.fetch_huggingface_model_card

    listings: Dict[tuple, Optional[set]] = {}
    cards: Dict[tuple, Optional[Dict[str, Any]]] = {}
    outcome = MatchOutcome()

    for index, (artifact, path) in enumerate(zip(artifacts, paths)):
        if path is None:
            continue
        candidates = candidates_for(Path(path))
        if not candidates:
            continue
        outcome.considered += 1

        local = _LocalIds(artifact, Path(path))
        verified: List[Candidate] = []
        for candidate in candidates:
            key = (candidate.repo_id, candidate.revision)
            if key not in listings:
                listings[key] = _listed_ids(fetch_index(candidate.repo_id, candidate.revision))
            ids = listings[key]
            if ids and local.found_in(ids):
                verified.append(candidate)

        if len(verified) > 1:
            outcome.ambiguous += 1
            continue
        if not verified:
            continue

        winner = verified[0]
        key = (winner.repo_id, winner.revision)
        if key not in cards:
            card = fetch_card(winner.repo_id, winner.revision)
            cards[key] = card if isinstance(card, dict) else None
        if cards[key] is not None:
            outcome.matches[index] = Match(cards[key], winner.source)

    return outcome
