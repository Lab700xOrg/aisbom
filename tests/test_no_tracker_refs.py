"""Code and docs cite their reasons in words, not bare issue numbers.

A bare `#NN` in this repo's source reads as a link to this repo's own issues
and pull requests, which it almost never meant: the numbers came from a
separate planning tracker, so in the public repo they point at unrelated
threads. This guard keeps new ones from landing.

Allowed:
  * `PR #NN` — a pull request in this repository (e.g. where a review caught
    something). Those resolve correctly.
  * single-digit `#N` — counters and ordinals in prose ("failure #1").
  * CSS hex colours (`#93a1a1`) — the match requires a word boundary after
    the digits.

CHANGELOG.md is outside the guarded directories on purpose: its generated
entries link this repo's own pull requests.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GUARDED_DIRS = ("aisbom", "tests", "action", "docs")
TEXT_SUFFIXES = {".py", ".sh", ".md", ".yml", ".yaml", ".toml", ".txt", ".cfg"}

# Two or more digits after `#`, not glued to a preceding word or `&`
# (HTML entities), and not introduced by "PR ".
TRACKER_REF = re.compile(r"(?<![\w&/])(?<!PR )#\d{2,}\b")


def find_tracker_refs(text: str) -> list[str]:
    return TRACKER_REF.findall(text)


def _guarded_files() -> list[Path]:
    files = []
    for name in GUARDED_DIRS:
        root = REPO_ROOT / name
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in TEXT_SUFFIXES:
                files.append(path)
    return sorted(files)


def test_guard_flags_a_planted_reference():
    # Assembled at runtime so this file doesn't trip its own guard.
    ref = "#" + "142"
    planted = f"    # Fixed the parser crash ({ref}).\n"
    assert find_tracker_refs(planted) == [ref]
    assert find_tracker_refs(f"Parent: aisbom-ops {ref}.") == [ref]


@pytest.mark.parametrize(
    "allowed",
    [
        "Caught by the review on PR #115.",
        "so the next failure is #1 again",
        '.com{color:#93a1a1}.str{color:#2aa198}',
        "model #1.safetensors",
        "&#39;quoted&#39;",
    ],
)
def test_guard_allows_legitimate_hashes(allowed):
    assert find_tracker_refs(allowed) == []


def test_no_tracker_refs_in_guarded_dirs():
    offenders = []
    for path in _guarded_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if find_tracker_refs(line):
                rel = path.relative_to(REPO_ROOT)
                offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert not offenders, (
        "Bare #NN references found. Say what the change was in words, or "
        "write `PR #NN` for a pull request in this repo:\n"
        + "\n".join(offenders)
    )
