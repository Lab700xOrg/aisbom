"""Matching local model files back to their Hugging Face repo.

A match puts one repo's model card on a local component, so a wrong match is
worse than none: it is the card-on-the-wrong-model failure the modelCard
injection already had to fix once. Every test here is about evidence — what
counts as a candidate, what proves it, and what must never leave the machine.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aisbom import hf_match

REV = "a" * 40
OTHER_REV = "b" * 40


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_oid(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _artifact(path: Path) -> dict:
    return {
        "name": path.name,
        "type": "machine-learning-model",
        "hash": _sha256(path.read_bytes()),
        "details": {},
    }


def _cache_file(root: Path, repo: str, name: str, data: bytes, rev: str = REV) -> Path:
    snapshot = root / "hub" / f"models--{repo.replace('/', '--')}" / "snapshots" / rev
    snapshot.mkdir(parents=True, exist_ok=True)
    path = snapshot / name
    path.write_bytes(data)
    return path


def _plain_file(root: Path, name: str, data: bytes, name_or_path=None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    path.write_bytes(data)
    if name_or_path is not None:
        (root / "config.json").write_text(json.dumps({"_name_or_path": name_or_path}))
    return path


class FakeHub:
    """Stands in for the two HF API calls and records every request made."""

    def __init__(self, repos=None, cards=None):
        # repo_id -> list of file entries as the tree API returns them
        self.repos = repos or {}
        self.cards = cards or {}
        self.index_calls = []
        self.card_calls = []

    def lfs_file(self, repo, path, data):
        self.repos.setdefault(repo, []).append({
            "type": "file", "path": path, "oid": _git_oid(b"pointer"),
            "size": len(data), "lfs": {"oid": _sha256(data), "size": len(data)},
        })

    def small_file(self, repo, path, data):
        self.repos.setdefault(repo, []).append({
            "type": "file", "path": path, "oid": _git_oid(data), "size": len(data),
        })

    def fetch_index(self, repo_id, revision=None):
        self.index_calls.append((repo_id, revision))
        return self.repos.get(repo_id)

    def fetch_card(self, repo_id, revision=None):
        self.card_calls.append((repo_id, revision))
        return self.cards.get(repo_id)

    def match(self, artifacts, paths):
        return hf_match.match_local_artifacts(
            artifacts, paths, fetch_index=self.fetch_index, fetch_card=self.fetch_card
        )


BERT_CARD = {"id": "google-bert/bert-base-uncased", "pipeline_tag": "fill-mask",
             "config": {"model_type": "bert"}}


# -- candidates -------------------------------------------------------------

def test_hf_cache_layout_yields_repo_and_revision(tmp_path):
    path = _cache_file(tmp_path, "google-bert/bert-base-uncased", "model.safetensors", b"w")
    assert hf_match.candidates_for(path) == [
        hf_match.Candidate("google-bert/bert-base-uncased", REV, hf_match.SOURCE_CACHE)
    ]


def test_hf_cache_layout_in_a_nested_snapshot_subdirectory(tmp_path):
    snapshot = tmp_path / "models--org--model" / "snapshots" / REV / "onnx"
    snapshot.mkdir(parents=True)
    path = snapshot / "model.onnx"
    path.write_bytes(b"x")
    assert hf_match.candidates_for(path)[0].repo_id == "org/model"


def test_a_non_commit_snapshot_name_is_not_trusted_as_a_revision(tmp_path):
    path = _cache_file(tmp_path, "org/model", "m.safetensors", b"w", rev="main")
    assert hf_match.candidates_for(path) == [
        hf_match.Candidate("org/model", None, hf_match.SOURCE_CACHE)
    ]


def test_config_name_or_path_yields_a_candidate(tmp_path):
    path = _plain_file(tmp_path / "dl", "model.safetensors", b"w", "org/model")
    assert hf_match.candidates_for(path) == [
        hf_match.Candidate("org/model", None, hf_match.SOURCE_CONFIG)
    ]


@pytest.mark.parametrize("value", [
    "bert-base-uncased",          # single segment: could be any directory name
    "/home/me/checkpoints/run1",  # an absolute local path
    "./outputs/final",            # a relative local path
    "checkpoints/run1/final",     # three segments is a path, not a repo id
    "org/../etc",
    "org--x/model",
    "",
    42,
])
def test_config_values_that_are_not_repo_ids_are_never_candidates(tmp_path, value):
    path = _plain_file(tmp_path / "dl", "model.safetensors", b"w", value)
    assert hf_match.candidates_for(path) == []


def test_a_config_value_naming_an_existing_local_directory_is_not_sent(tmp_path):
    """`outputs/final` beside the weights is a path the user saved to, not a repo."""
    root = tmp_path / "dl"
    path = _plain_file(root, "model.safetensors", b"w", "outputs/final")
    (root / "outputs" / "final").mkdir(parents=True)
    assert hf_match.candidates_for(path) == []


def test_malformed_or_huge_config_is_ignored(tmp_path):
    root = tmp_path / "dl"
    path = _plain_file(root, "model.safetensors", b"w")
    (root / "config.json").write_text("{not json")
    assert hf_match.candidates_for(path) == []
    (root / "config.json").write_text(json.dumps({"_name_or_path": "org/model", "pad": "x" * (2 << 20)}))
    assert hf_match.candidates_for(path) == []


def test_no_evidence_no_candidates(tmp_path):
    assert hf_match.candidates_for(_plain_file(tmp_path, "model.safetensors", b"w")) == []


# -- matching -----------------------------------------------------------------

def test_lfs_sha256_in_the_repo_listing_is_a_match(tmp_path):
    data = b"weights" * 100
    path = _cache_file(tmp_path, "google-bert/bert-base-uncased", "model.safetensors", data)
    hub = FakeHub(cards={"google-bert/bert-base-uncased": BERT_CARD})
    hub.lfs_file("google-bert/bert-base-uncased", "model.safetensors", data)

    outcome = hub.match([_artifact(path)], [path])

    assert outcome.matches == {0: hf_match.Match(BERT_CARD, hf_match.SOURCE_CACHE)}
    assert outcome.considered == 1 and outcome.matched == 1
    assert hub.index_calls == [("google-bert/bert-base-uncased", REV)]
    assert hub.card_calls == [("google-bert/bert-base-uncased", REV)]


def test_a_renamed_file_still_matches_on_content(tmp_path):
    data = b"weights" * 100
    path = _plain_file(tmp_path / "dl", "my-copy.safetensors", data, "org/model")
    hub = FakeHub(cards={"org/model": {"id": "org/model"}})
    hub.lfs_file("org/model", "model.safetensors", data)
    assert hub.match([_artifact(path)], [path]).matched == 1


def test_small_non_lfs_file_matches_on_git_blob_oid(tmp_path):
    data = b"tiny pickle"
    path = _plain_file(tmp_path / "dl", "model.pkl", data, "org/model")
    hub = FakeHub(cards={"org/model": {"id": "org/model"}})
    hub.small_file("org/model", "model.pkl", data)
    assert hub.match([_artifact(path)], [path]).matched == 1


def test_fine_tune_naming_its_base_model_gets_no_card(tmp_path):
    """The failure the issue warns about: config names the base, bytes differ."""
    path = _plain_file(tmp_path / "ft", "model.safetensors", b"fine-tuned", "google-bert/bert-base-uncased")
    hub = FakeHub(cards={"google-bert/bert-base-uncased": BERT_CARD})
    hub.lfs_file("google-bert/bert-base-uncased", "model.safetensors", b"base weights")

    outcome = hub.match([_artifact(path)], [path])

    assert outcome.matches == {}
    assert outcome.considered == 1 and outcome.matched == 0
    assert hub.card_calls == []  # no card is fetched for an unproven candidate


def test_two_repos_both_verifying_is_ambiguous_and_gets_no_card(tmp_path):
    data = b"mirrored weights"
    path = _cache_file(tmp_path, "org/original", "model.safetensors", data)
    (path.parent / "config.json").write_text(json.dumps({"_name_or_path": "mirror/copy"}))
    hub = FakeHub(cards={"org/original": {"id": "org/original"}, "mirror/copy": {"id": "mirror/copy"}})
    hub.lfs_file("org/original", "model.safetensors", data)
    hub.lfs_file("mirror/copy", "model.safetensors", data)

    outcome = hub.match([_artifact(path)], [path])

    assert outcome.matches == {}
    assert outcome.ambiguous == 1
    assert hub.card_calls == []


def test_cache_and_config_naming_the_same_repo_is_one_candidate(tmp_path):
    data = b"weights"
    path = _cache_file(tmp_path, "org/model", "model.safetensors", data)
    (path.parent / "config.json").write_text(json.dumps({"_name_or_path": "org/model"}))
    hub = FakeHub(cards={"org/model": {"id": "org/model"}})
    hub.lfs_file("org/model", "model.safetensors", data)

    outcome = hub.match([_artifact(path)], [path])

    assert outcome.matches[0].source == hf_match.SOURCE_CACHE
    assert hub.index_calls == [("org/model", REV)]


def test_only_one_verifying_candidate_wins(tmp_path):
    data = b"weights"
    path = _cache_file(tmp_path, "org/model", "model.safetensors", data)
    (path.parent / "config.json").write_text(json.dumps({"_name_or_path": "org/base"}))
    hub = FakeHub(cards={"org/model": {"id": "org/model"}})
    hub.lfs_file("org/model", "model.safetensors", data)
    hub.lfs_file("org/base", "model.safetensors", b"other")
    assert hub.match([_artifact(path)], [path]).matches[0].card == {"id": "org/model"}


def test_no_evidence_makes_no_request_at_all(tmp_path):
    path = _plain_file(tmp_path, "model.safetensors", b"w")
    hub = FakeHub()
    outcome = hub.match([_artifact(path)], [path])
    assert outcome.considered == 0 and outcome.matches == {}
    assert hub.index_calls == [] and hub.card_calls == []


def test_a_rejected_config_value_is_never_requested(tmp_path):
    path = _plain_file(tmp_path / "dl", "model.safetensors", b"w", "/home/me/secret-project")
    hub = FakeHub()
    hub.match([_artifact(path)], [path])
    assert hub.index_calls == []


def test_listing_failure_degrades_to_no_card(tmp_path):
    path = _cache_file(tmp_path, "org/gated", "model.safetensors", b"w")
    hub = FakeHub()  # fetch_index returns None, as the real one does on any failure
    outcome = hub.match([_artifact(path)], [path])
    assert outcome.matches == {} and outcome.considered == 1


def test_card_failure_after_a_verified_match_degrades_to_no_card(tmp_path):
    data = b"w"
    path = _cache_file(tmp_path, "org/model", "model.safetensors", data)
    hub = FakeHub()  # no card
    hub.lfs_file("org/model", "model.safetensors", data)
    assert hub.match([_artifact(path)], [path]).matches == {}


def test_a_malformed_listing_is_not_a_match(tmp_path):
    path = _cache_file(tmp_path, "org/model", "model.safetensors", b"w")
    hub = FakeHub(repos={"org/model": [None, "x", {"lfs": "nope"}, {"oid": 5}]},
                  cards={"org/model": {"id": "org/model"}})
    assert hub.match([_artifact(path)], [path]).matches == {}


def test_many_files_from_one_repo_share_one_listing_and_one_card(tmp_path):
    a, b = b"shard-1", b"shard-2"
    pa = _cache_file(tmp_path, "org/model", "model-00001.safetensors", a)
    pb = _cache_file(tmp_path, "org/model", "model-00002.safetensors", b)
    hub = FakeHub(cards={"org/model": {"id": "org/model"}})
    hub.lfs_file("org/model", "model-00001.safetensors", a)
    hub.lfs_file("org/model", "model-00002.safetensors", b)

    outcome = hub.match([_artifact(pa), _artifact(pb)], [pa, pb])

    assert sorted(outcome.matches) == [0, 1]
    assert len(hub.index_calls) == 1 and len(hub.card_calls) == 1


def test_remote_artifacts_without_a_local_path_are_skipped(tmp_path):
    hub = FakeHub()
    outcome = hub.match([{"name": "m.safetensors", "hash": "remote_unhashed"}], [None])
    assert outcome.considered == 0 and hub.index_calls == []


def test_an_unhashed_local_file_can_still_match_by_rehashing(tmp_path):
    data = b"w"
    path = _cache_file(tmp_path, "org/model", "model.safetensors", data)
    hub = FakeHub(cards={"org/model": {"id": "org/model"}})
    hub.lfs_file("org/model", "model.safetensors", data)
    art = _artifact(path) | {"hash": "hash_error"}
    assert hub.match([art], [path]).matched == 1


def test_git_oid_is_the_git_blob_hash():
    # `printf 'hello\n' | git hash-object --stdin`
    assert hf_match.git_blob_oid_of(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


# -- opt-out ------------------------------------------------------------------

def test_env_var_disables_the_lookup():
    assert hf_match.disabled_by_env({"AISBOM_NO_HF_LOOKUP": "1"})
    assert not hf_match.disabled_by_env({})
