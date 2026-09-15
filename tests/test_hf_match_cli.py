"""Local model files matched to their Hugging Face repo, end to end.

The matcher itself is covered in test_hf_match.py. These tests are about the
wiring: a local scan picks the card up, every output that carries card data
agrees, the opt-outs make no request at all, and a scan with nothing to match
is unchanged.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from typer.testing import CliRunner

from aisbom import hf_match, remote
from aisbom.cli import app
from aisbom.cyclonedx_gen import build_cyclonedx_json
from aisbom.scanner import DeepScanner
from aisbom.spdx3_gen import generate_spdx3_sbom

runner = CliRunner()

REPO = "google-bert/bert-base-uncased"
REV = "86b5e0934494bd15c9632b12f734a8a67f723594"
CARD = {
    "id": REPO,
    "pipeline_tag": "fill-mask",
    "library_name": "transformers",
    "sha": REV,
    "cardData": {"license": "apache-2.0", "datasets": ["bookcorpus", "wikipedia"]},
    "config": {"model_type": "bert", "architectures": ["BertForMaskedLM"]},
}


def _safetensors(payload: str = "") -> bytes:
    header = json.dumps({"__metadata__": {"note": payload}}).encode()
    return struct.pack("<Q", len(header)) + header


def _cached_model(root: Path, data: bytes, repo: str = REPO, rev: str = REV) -> Path:
    snapshot = root / "hub" / f"models--{repo.replace('/', '--')}" / "snapshots" / rev
    snapshot.mkdir(parents=True)
    path = snapshot / "model.safetensors"
    path.write_bytes(data)
    return path


class Hub:
    """Replaces the two HF calls hf_match makes; records each request."""

    def __init__(self, monkeypatch, files=None, card=CARD):
        self.files = files or {}
        self.card = card
        self.calls = []
        monkeypatch.setattr(remote, "fetch_huggingface_file_index", self.index)
        monkeypatch.setattr(remote, "fetch_huggingface_model_card", self.fetch_card)

    def index(self, repo_id, revision=None):
        self.calls.append(("index", repo_id, revision))
        data = self.files.get(repo_id)
        if data is None:
            return None
        return [{"type": "file", "path": "model.safetensors", "oid": "0" * 40,
                 "lfs": {"oid": hashlib.sha256(data).hexdigest()}}]

    def fetch_card(self, repo_id, revision=None):
        self.calls.append(("card", repo_id, revision))
        return self.card


def _scan(tmp_path, *extra):
    out = tmp_path / "sbom.json"
    result = runner.invoke(app, ["scan", str(tmp_path / "hub"), "--output", str(out), *extra])
    return result, out


def _model_components(path: Path):
    return [c for c in json.loads(path.read_text())["components"]
            if c["type"] == "machine-learning-model"]


# -- scanner ------------------------------------------------------------------

def test_scanner_records_where_each_local_artifact_was_read(tmp_path):
    path = _cached_model(tmp_path, _safetensors())
    results = DeepScanner(str(tmp_path)).scan()
    assert results["artifact_paths"] == [path]


def test_scanner_records_no_paths_for_remote_artifacts(monkeypatch):
    monkeypatch.setattr("aisbom.scanner.fetch_huggingface_model_card", lambda t: None)
    monkeypatch.setattr(
        "aisbom.scanner.DeepScanner._resolve_remote_targets", lambda self, t: []
    )
    assert DeepScanner("hf://org/model").scan()["artifact_paths"] == []


def test_local_paths_never_reach_the_sbom(tmp_path, monkeypatch):
    data = _safetensors()
    _cached_model(tmp_path, data)
    Hub(monkeypatch, files={REPO: data})
    result, out = _scan(tmp_path)
    assert result.exit_code == 0, result.output
    assert str(tmp_path) not in out.read_text()


# -- scan ---------------------------------------------------------------------

def test_local_cached_model_gets_the_card_an_hf_scan_would(tmp_path, monkeypatch):
    data = _safetensors()
    _cached_model(tmp_path, data)
    hub = Hub(monkeypatch, files={REPO: data})

    result, out = _scan(tmp_path)

    assert result.exit_code == 0, result.output
    (component,) = _model_components(out)
    card = component["modelCard"]
    assert card["modelParameters"] == {
        "task": "fill-mask",
        "architectureFamily": "bert",
        "modelArchitecture": "BertForMaskedLM",
        "datasets": [{"type": "dataset", "name": "bookcorpus"},
                     {"type": "dataset", "name": "wikipedia"}],
    }
    props = {p["name"]: p["value"] for p in card["properties"]}
    assert props["aisbom:hf:repo_id"] == REPO
    assert props["aisbom:hf:revision"] == REV
    assert props[hf_match.MATCH_PROPERTY] == hf_match.SOURCE_CACHE
    assert hub.calls == [("index", REPO, REV), ("card", REPO, REV)]
    assert "Hugging Face: matched 1 of 1" in result.output
    assert JsonStrictValidator(SchemaVersion.V1_7).validate_str(out.read_text()) is None


def test_bytes_that_differ_from_the_repo_get_no_card(tmp_path, monkeypatch):
    _cached_model(tmp_path, _safetensors("locally modified"))
    hub = Hub(monkeypatch, files={REPO: _safetensors()})

    result, out = _scan(tmp_path)

    assert result.exit_code == 0, result.output
    (component,) = _model_components(out)
    assert "modelCard" not in component
    assert ("card", REPO, REV) not in hub.calls
    assert "Hugging Face: matched 0 of 1" in result.output


def test_a_tree_with_no_hf_evidence_makes_no_request_and_prints_nothing(tmp_path, monkeypatch):
    (tmp_path / "hub").mkdir()
    (tmp_path / "hub" / "model.safetensors").write_bytes(_safetensors())
    hub = Hub(monkeypatch)

    result, out = _scan(tmp_path)

    assert result.exit_code == 0, result.output
    assert hub.calls == []
    assert "Hugging Face:" not in result.output


@pytest.mark.parametrize("args,env", [
    (["--no-hf-lookup"], {}),
    ([], {"AISBOM_NO_HF_LOOKUP": "1"}),
    (["--offline"], {}),
    ([], {"AISBOM_OFFLINE": "1"}),
])
def test_opt_outs_make_no_request(tmp_path, monkeypatch, args, env):
    data = _safetensors()
    _cached_model(tmp_path, data)
    hub = Hub(monkeypatch, files={REPO: data})
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result, out = _scan(tmp_path, *args)

    assert result.exit_code == 0, result.output
    assert hub.calls == []
    assert "modelCard" not in _model_components(out)[0]


def test_lookup_failure_keeps_the_scan_and_its_exit_code(tmp_path, monkeypatch):
    _cached_model(tmp_path, _safetensors())
    Hub(monkeypatch)  # listing returns None, as on any failure

    result, out = _scan(tmp_path)

    assert result.exit_code == 0, result.output
    assert "modelCard" not in _model_components(out)[0]


@pytest.mark.parametrize("args", [
    ["--format", "markdown"],
    ["--schema-version", "1.6"],
    ["--format", "spdx", "--spdx-version", "2.3"],
])
def test_outputs_that_carry_no_card_skip_the_lookup(tmp_path, monkeypatch, args):
    data = _safetensors()
    _cached_model(tmp_path, data)
    hub = Hub(monkeypatch, files={REPO: data})
    result, _ = _scan(tmp_path, *args)
    assert result.exit_code == 0, result.output
    assert hub.calls == []


def test_spdx3_output_names_the_matched_training_datasets(tmp_path, monkeypatch):
    data = _safetensors()
    _cached_model(tmp_path, data)
    hub = Hub(monkeypatch, files={REPO: data})

    result, out = _scan(tmp_path, "--format", "spdx", "--spdx-version", "3.0")

    assert result.exit_code == 0, result.output
    assert hub.calls
    doc = json.loads(out.read_text())
    datasets = sorted(e["name"] for e in doc["@graph"] if e.get("type") == "dataset_DatasetPackage")
    assert datasets == ["bookcorpus", "wikipedia"]


def test_hf_scans_do_not_run_the_local_matcher(tmp_path, monkeypatch):
    hub = Hub(monkeypatch)
    monkeypatch.setattr("aisbom.scanner.fetch_huggingface_model_card", lambda t: None)
    monkeypatch.setattr("aisbom.scanner.DeepScanner._resolve_remote_targets", lambda self, t: [])
    runner.invoke(app, ["scan", "hf://org/model", "--output", str(tmp_path / "s.json")])
    assert hub.calls == []


# -- generators ---------------------------------------------------------------

def _results_with_two_repos():
    other = {"id": "org/other", "pipeline_tag": "text-generation",
             "cardData": {"datasets": ["the-pile"]}}
    artifacts = [
        {"name": n, "type": "machine-learning-model", "framework": "SafeTensors",
         "risk_level": "LOW", "legal_status": "UNKNOWN", "license": "Unknown",
         "hash": h * 64, "details": {}}
        for n, h in (("a.safetensors", "a"), ("b.safetensors", "b"), ("c.safetensors", "c"))
    ]
    return {
        "artifacts": artifacts, "dependencies": [], "errors": [], "hf_model_card": None,
        "hf_local_matches": {
            0: hf_match.Match(CARD, hf_match.SOURCE_CACHE),
            2: hf_match.Match(other, hf_match.SOURCE_CONFIG),
        },
    }


def test_cyclonedx_generator_attaches_each_files_own_card():
    doc = json.loads(build_cyclonedx_json(_results_with_two_repos()))
    cards = {c["name"]: c.get("modelCard") for c in doc["components"]}
    assert cards["a.safetensors"]["modelParameters"]["task"] == "fill-mask"
    assert cards["b.safetensors"] is None
    assert cards["c.safetensors"]["modelParameters"]["task"] == "text-generation"


def test_spdx3_trains_each_package_on_its_own_datasets_only():
    doc = json.loads(generate_spdx3_sbom(_results_with_two_repos()))
    graph = doc["@graph"]
    by_id = {e.get("spdxId"): e for e in graph}
    trained = {
        by_id[r["from"]]["name"]: sorted(by_id[t]["name"] for t in r["to"])
        for r in graph if r.get("relationshipType") == "trainedOn"
    }
    assert trained == {
        "a.safetensors": ["bookcorpus", "wikipedia"],
        "c.safetensors": ["the-pile"],
    }
    pkgs = {e["name"]: e for e in graph if e.get("type") == "ai_AIPackage"}
    assert "ai_informationAboutTraining" not in pkgs["b.safetensors"]


# -- score --------------------------------------------------------------------

def test_score_of_a_matched_local_tree_regains_model_card_and_dataset_points(tmp_path, monkeypatch):
    data = _safetensors()
    _cached_model(tmp_path, data)

    Hub(monkeypatch, files={REPO: data})
    matched = runner.invoke(app, ["score", str(tmp_path / "hub"), "--json"])
    unmatched = runner.invoke(app, ["score", str(tmp_path / "hub"), "--json", "--no-hf-lookup"])

    assert matched.exit_code == 0, matched.output
    assert unmatched.exit_code == 0, unmatched.output

    def dims(result):
        payload = json.loads(result.stdout)
        return {d["key"]: d["score"] for d in payload["dimensions"]}

    got, before = dims(matched), dims(unmatched)
    assert got["modelcard"] == 100 and before["modelcard"] == 0
    assert got["datasets"] == 100 and before["datasets"] == 0
