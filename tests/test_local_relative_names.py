"""Local components are named by their path relative to the scan target.

Two files with the same basename in different folders (`a/model.pt` and
`b/model.pt`) used to produce two components both named `model.pt`.
`aisbom diff` keys components by name, so one of them silently dropped out of
every comparison. Files at the top of the scan target keep their bare
filename, so baselines made before this change still match them.

Renaming a nested component would make an old baseline look like the file
was removed and a new one added. `aisbom diff` therefore pairs a removed and
an added component that carry the same SHA-256 (unique on both sides) and
reports them as one renamed component.
"""

import json
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest
from typer.testing import CliRunner

from aisbom.cli import app
from aisbom.diff import SBOMDiff
from aisbom.mock_generator import create_mock_restricted_file
from aisbom.scanner import DeepScanner, local_artifact_name
from tests.test_scanner_cli import _write_malicious_pt

runner = CliRunner()


def _names(results):
    return sorted(a["name"] for a in results["artifacts"])


# --- scanner naming ---------------------------------------------------------


def test_nested_files_are_named_by_relative_path(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    _write_malicious_pt(tmp_path / "a" / "model.pt")
    _write_malicious_pt(tmp_path / "b" / "model.pt")
    create_mock_restricted_file(tmp_path)

    results = DeepScanner(str(tmp_path)).scan()

    assert _names(results) == ["a/model.pt", "b/model.pt", "mock_restricted.safetensors"]


def test_deeply_nested_file_keeps_every_folder(tmp_path):
    deep = tmp_path / "x" / "y" / "z"
    deep.mkdir(parents=True)
    _write_malicious_pt(deep / "model.pt")

    assert _names(DeepScanner(str(tmp_path)).scan()) == ["x/y/z/model.pt"]


def test_relative_scan_target_gives_no_dot_prefix(tmp_path, monkeypatch):
    (tmp_path / "a").mkdir()
    _write_malicious_pt(tmp_path / "a" / "model.pt")
    monkeypatch.chdir(tmp_path)

    assert _names(DeepScanner(".").scan()) == ["a/model.pt"]


def test_name_never_includes_folders_above_the_scan_target(tmp_path):
    target = tmp_path / "private-project" / "models"
    (target / "a").mkdir(parents=True)
    _write_malicious_pt(target / "a" / "model.pt")

    names = _names(DeepScanner(str(target)).scan())

    assert names == ["a/model.pt"]
    assert "private-project" not in names[0]


def test_single_file_target_keeps_its_bare_name(tmp_path):
    (tmp_path / "a").mkdir()
    _write_malicious_pt(tmp_path / "a" / "model.pt")

    assert _names(DeepScanner(str(tmp_path / "a" / "model.pt")).scan()) == ["model.pt"]


@pytest.mark.parametrize(
    "root, path, expected",
    [
        (PurePosixPath("/scan"), PurePosixPath("/scan/model.pt"), "model.pt"),
        (PurePosixPath("/scan"), PurePosixPath("/scan/a/b/model.pt"), "a/b/model.pt"),
        (PureWindowsPath("C:/scan"), PureWindowsPath("C:/scan/a/b/model.pt"), "a/b/model.pt"),
    ],
)
def test_names_use_forward_slashes_on_every_os(root, path, expected):
    assert local_artifact_name(root, path) == expected


def test_cli_sbom_carries_relative_names(tmp_path):
    tree = tmp_path / "tree"
    (tree / "a").mkdir(parents=True)
    _write_malicious_pt(tree / "a" / "model.pt")
    out = tmp_path / "sbom.json"

    result = runner.invoke(
        app, ["scan", str(tree), "--output", str(out), "--offline", "--no-fail-on-risk"]
    )

    assert result.exit_code == 0, result.output
    names = [c["name"] for c in json.loads(out.read_text())["components"]]
    assert "a/model.pt" in names


# --- aisbom diff ------------------------------------------------------------

H1 = "a" * 64
H2 = "b" * 64


def _comp(name, sha=None, risk="LOW"):
    c = {"name": name, "version": "unknown", "description": f"Risk: {risk} | Framework: PyTorch"}
    if sha:
        c["hashes"] = [{"alg": "SHA-256", "content": sha}]
    return c


def _diff(tmp_path, old, new):
    f_old, f_new = tmp_path / "old.json", tmp_path / "new.json"
    f_old.write_text(json.dumps({"components": old}))
    f_new.write_text(json.dumps({"components": new}))
    return SBOMDiff(f_old, f_new).compare()


def test_diff_tells_same_named_files_in_different_folders_apart(tmp_path):
    res = _diff(
        tmp_path,
        [_comp("a/model.onnx", H1), _comp("b/model.onnx", H2)],
        [_comp("a/model.onnx", H1)],
    )
    assert [c["name"] for c in res.removed] == ["b/model.onnx"]
    assert res.added == [] and res.changed == []


def test_same_hash_rename_is_reported_as_renamed(tmp_path):
    res = _diff(
        tmp_path,
        [_comp("model.pt", H1, "CRITICAL")],
        [_comp("a/model.pt", H1, "CRITICAL")],
    )
    assert res.added == [] and res.removed == []
    assert len(res.changed) == 1
    assert res.changed[0].name == "a/model.pt"
    assert res.changed[0].renamed_from == "model.pt"
    assert res.risk_increased is False
    assert res.hash_drifted is False


def test_rename_that_escalates_still_raises_risk(tmp_path):
    res = _diff(
        tmp_path,
        [_comp("model.pt", H1, "MEDIUM")],
        [_comp("a/model.pt", H1, "CRITICAL")],
    )
    assert res.changed[0].renamed_from == "model.pt"
    assert res.changed[0].risk_diff == ("MEDIUM", "CRITICAL")
    assert res.risk_increased is True


def test_one_file_split_into_two_paths_raises_no_risk(tmp_path):
    res = _diff(
        tmp_path,
        [_comp("model.pt", H1, "CRITICAL")],
        [_comp("a/model.pt", H1, "CRITICAL"), _comp("b/model.pt", H1, "CRITICAL")],
    )
    assert sorted(c["name"] for c in res.added) == ["a/model.pt", "b/model.pt"]
    assert [c["name"] for c in res.removed] == ["model.pt"]
    assert res.risk_increased is False


def test_added_critical_with_a_new_hash_still_raises_risk(tmp_path):
    res = _diff(tmp_path, [_comp("model.pt", H1, "LOW")], [_comp("a/model.pt", H2, "CRITICAL")])
    assert res.risk_increased is True
    assert len(res.added) == 1 and len(res.removed) == 1


@pytest.mark.parametrize("sha", [None, "remote_unhashed", "aaaa"])
def test_missing_or_placeholder_hash_never_pairs(tmp_path, sha):
    res = _diff(tmp_path, [_comp("model.pt", sha, "CRITICAL")], [_comp("a/model.pt", sha, "CRITICAL")])
    assert len(res.added) == 1 and len(res.removed) == 1
    assert res.risk_increased is True


def test_hash_shared_by_two_removed_components_does_not_pair(tmp_path):
    res = _diff(tmp_path, [_comp("x.pt", H1), _comp("y.pt", H1)], [_comp("a/x.pt", H1)])
    assert len(res.added) == 1 and len(res.removed) == 2


def test_cli_diff_shows_a_rename_and_exits_zero(tmp_path):
    f_old, f_new = tmp_path / "old.json", tmp_path / "new.json"
    f_old.write_text(json.dumps({"components": [_comp("model.pt", H1, "CRITICAL")]}))
    f_new.write_text(json.dumps({"components": [_comp("a/model.pt", H1, "CRITICAL")]}))

    result = runner.invoke(app, ["diff", str(f_old), str(f_new)])

    assert result.exit_code == 0, result.output
    flat = "".join(result.output.split())
    assert "Renamed" in flat
    assert "from:model.pt" in flat
