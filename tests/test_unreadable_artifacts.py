"""Unparseable model files are errors, not clean LOW-risk artifacts (#131).

`LOW` is an assertion: AIsbom opened the artifact and found nothing dangerous.
For a file no parser ever read, the honest output is "could not read this", and
collapsing the two is the #125 failure in a different place — something never
examined passing a CI gate.

Before this change, six distinct corruption shapes all graded clean and exited
0, because the inspectors' own failure signal was never consulted: five of them
write `meta["error"]` and nothing in the codebase read it. Two of the shapes
never raise at all (a text `.pt`, a two-byte pickle), and the git-LFS pointer
set `meta["error"]` to the *empty string* — so a truthiness check on that key
would still have missed it. Each inspector therefore has to report whether its
parse actually succeeded, which is what these tests pin.

The bytes here are real corruption (a truncated zip, a two-byte pickle, random
bytes, an LFS stub, plain text) rather than curated fixtures, per the
`probe-real-trees-for-false-positives` lesson: the false-positive risk lives in
ordinary files, so the guard has to be proven against ordinary files.
"""

import json
import struct

import pytest
from typer.testing import CliRunner

from aisbom.cli import app
from aisbom.properties import build_component_properties
from aisbom.scanner import UNREADABLE_TYPES, DeepScanner

runner = CliRunner()


# --- the six reproduced shapes -------------------------------------------

LFS_POINTER = (
    b"version https://git-lfs.github.com/spec/v1\n"
    b"oid sha256:4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e\n"
    b"size 440449768\n"
)

# Every corruption shape the issue reproduced, plus the two it missed: a zero
# byte file and an LFS pointer stub (the common real-world unparseable
# `.safetensors`, left by a clone without `git lfs pull`).
SHAPES = [
    ("lfs_pointer.safetensors", LFS_POINTER, "LfsPointer"),
    ("empty.gguf", b"", "EmptyFile"),
    ("truncated_pickle.pkl", b"\x80\x05", "TruncatedStream"),
    ("random.safetensors", b"\x91\x3f" * 100, "TruncatedStream"),
    ("garbage.pt", b"totally not a model at all", "UnrecognizedFormat"),
    ("truncated_zip.pt", b"PK\x03\x04corrupt-not-a-real-zip", "UnrecognizedFormat"),
]


def _scan(tmp_path, name: str, payload: bytes):
    (tmp_path / name).write_bytes(payload)
    return DeepScanner(tmp_path).scan()


def _errors_for(results, name: str):
    return [e for e in results["errors"] if e["file"].endswith(name)]


def _artifact(results, name: str):
    for art in results["artifacts"]:
        if art["name"] == name:
            return art
    return None


@pytest.mark.parametrize("name,payload,expected_type", SHAPES)
def test_unreadable_file_is_recorded_as_an_error(tmp_path, name, payload, expected_type):
    """Each corruption shape lands in results["errors"] with its subtype."""
    results = _scan(tmp_path, name, payload)

    errors = _errors_for(results, name)
    assert errors, f"{name} produced no error entry"
    assert errors[0]["unreadable"] is True
    assert errors[0]["unreadable_type"] == expected_type
    assert expected_type in UNREADABLE_TYPES


@pytest.mark.parametrize("name,payload,_expected", SHAPES)
def test_unreadable_file_is_never_low_risk(tmp_path, name, payload, _expected):
    """The whole point: an unexamined file must not read as a clean verdict."""
    art = _artifact(_scan(tmp_path, name, payload), name)

    assert art is not None, "the file should still appear in the SBOM"
    assert art["risk_level"].startswith("UNKNOWN ("), art["risk_level"]
    assert "LOW" not in art["risk_level"]
    assert art["unreadable"] is True


def test_random_bytes_are_not_described_as_safetensors(tmp_path):
    """A format label is an assertion that that format's parser succeeded."""
    results = _scan(tmp_path, "random.safetensors", b"\x91\x3f" * 100)
    art = _artifact(results, "random.safetensors")

    assert not art.get("framework"), art.get("framework")
    names = {n for n, _ in build_component_properties(art)}
    assert "aisbom:format" not in names


def test_unreadable_artifact_carries_marker_properties(tmp_path):
    """The SBOM records that the file was seen and not examined."""
    results = _scan(tmp_path, "lfs_pointer.safetensors", LFS_POINTER)
    props = dict(build_component_properties(_artifact(results, "lfs_pointer.safetensors")))

    assert props["aisbom:unreadable"] == "true"
    assert props["aisbom:unreadable_type"] == "LfsPointer"


def test_lfs_pointer_error_names_the_remedy(tmp_path):
    """A pointer stub is a config problem; "could not parse" would misdirect."""
    results = _scan(tmp_path, "model.safetensors", LFS_POINTER)

    assert "git lfs pull" in _errors_for(results, "model.safetensors")[0]["error"]


# --- the .pth collision ---------------------------------------------------
#
# `.pth` is the one model extension that is *also* a real text format: Python's
# `site` module reads every `.pth` in site-packages, appending each line to
# sys.path or executing it when it starts with `import`. Those files exist in
# every virtualenv and must keep scanning clean, so the text branch narrows to
# `.pth` alone and validates against that spec instead of accepting any text.

@pytest.mark.parametrize(
    "content",
    [
        "/usr/local/lib/python3.11/site-packages",
        "import _virtualenv",
        "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var)",
        "# a comment\n/opt/some/path\n",
        "/first/path\n/second/path\n",
    ],
)
def test_real_pth_path_config_still_scans_clean(tmp_path, content):
    """Genuine path-config files are not corruption and must not be flagged.

    An *empty* `.pth` is deliberately absent from these cases: zero of the 141
    real `.pth` files across this machine's virtualenvs are empty, so an empty
    model-extension file is treated as a failed download uniformly rather than
    exempting one extension on a case that does not occur in practice.
    """
    (tmp_path / "site-packages.pth").write_text(content)
    results = DeepScanner(tmp_path).scan()

    assert results["errors"] == []
    art = _artifact(results, "site-packages.pth")
    assert art["risk_level"] == "LOW"
    assert art["framework"] == "Python Path Config"


@pytest.mark.parametrize(
    "content",
    [
        "totally not a model at all",
        "<!DOCTYPE html><html><body>404 Not Found</body></html>",
        "version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 1\n",
    ],
)
def test_text_that_is_not_a_path_config_is_unreadable(tmp_path, content):
    """Text alone was never evidence of a path config — an HTML error page
    saved over a checkpoint used to score LOW."""
    (tmp_path / "model.pth").write_text(content)
    results = DeepScanner(tmp_path).scan()

    assert results["errors"], "non-path-config text should not pass as clean"
    assert _artifact(results, "model.pth")["risk_level"].startswith("UNKNOWN (")


@pytest.mark.parametrize("ext", [".pt", ".bin"])
def test_path_config_classification_is_pth_only(tmp_path, ext):
    """Nothing produces a text `.pt`/`.bin` path config; such a file is a
    corrupt download or a saved error page, not a configuration."""
    (tmp_path / f"model{ext}").write_text("/usr/local/lib/python3.11/site-packages")
    results = DeepScanner(tmp_path).scan()

    assert results["errors"]
    assert _artifact(results, f"model{ext}")["framework"] != "Python Path Config"


# --- regression from the real-tree probe ----------------------------------

def test_pickle_with_trailing_raw_bytes_is_not_unreadable(tmp_path):
    """A real pickle need not be the whole file.

    Promoted from the real-tree probe, which is the only reason this is here:
    an earlier draft required the opcode walk to reach STOP, and that called
    **75** valid files unreadable — every `.pkl` in joblib's own test corpus,
    across every virtualenv on the machine. joblib writes its arrays as raw
    bytes straight after the pickle's STOP, so the walk dies on that trailing
    data after 54 perfectly good content opcodes.

    The bytes below are that layout: a complete protocol-3 pickle carrying a
    `NumpyArrayWrapper` global, followed by raw array data.
    """
    body = (
        b"\x80\x03]q\x00(cjoblib.numpy_pickle\nNumpyArrayWrapper\nq\x01)"
        b"\x81q\x02}q\x03X\x05\x00\x00\x00shapeq\x04K\x05\x85q\x05sbe."
    )
    trailing = bytes(range(256)) * 4          # raw array payload, not opcodes
    results = _scan(tmp_path, "model.pkl", body + trailing)

    assert not _errors_for(results, "model.pkl"), results["errors"]
    assert _artifact(results, "model.pkl")["risk_level"] != "UNKNOWN (Truncated)"


# --- the pre-existing honest labels get their consequence ----------------
#
# Three inspectors already told the truth about files they could not read —
# `UNKNOWN (Invalid Header)` (GGUF), `UNKNOWN (Unrecognized Container)`
# (Keras), `UNKNOWN (Unparsable ONNX)` — but the verdict had no consequence:
# `_risk_score` maps an `UNKNOWN` label to 0, *below* LOW, so such a file
# exited 0 and rated safer than a clean model. Same class of problem as the
# rest of the slice, so it is fixed on the same terms rather than left as a
# knowingly inconsistent corner.

@pytest.mark.parametrize(
    "name,payload",
    [
        ("bad.gguf", b"NOPE" + b"\x00" * 32),
        ("junk.keras", b"not a container at all" * 10),
        ("junk.onnx", b"\xff\xff\xff\xff" * 40),
    ],
)
def test_unparsable_known_format_is_an_error(tmp_path, name, payload):
    results = _scan(tmp_path, name, payload)

    assert _errors_for(results, name), f"{name} produced no error entry"
    assert _artifact(results, name)["unreadable"] is True


def test_unparsable_gguf_exits_1_rather_than_0(tmp_path):
    """An UNKNOWN label scores 0 in `_risk_score`, so this used to exit 0."""
    (tmp_path / "bad.gguf").write_bytes(b"NOPE" + b"\x00" * 32)
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(tmp_path / "s.json")])

    assert result.exit_code == 1, result.output


# --- clean models stay clean ---------------------------------------------

def test_valid_safetensors_still_scores_low(tmp_path):
    """No false "unreadable" for a real artifact (the regression that matters)."""
    header = json.dumps({"__metadata__": {"license": "apache-2.0"}}).encode()
    payload = struct.pack("<Q", len(header)) + header
    results = _scan(tmp_path, "good.safetensors", payload)

    assert results["errors"] == []
    art = _artifact(results, "good.safetensors")
    assert art["risk_level"] == "LOW"
    assert art["framework"] == "SafeTensors"


# --- exit codes and score ------------------------------------------------

def test_scan_exits_1_on_an_unreadable_file(tmp_path):
    """AC#4, and what README.md already documents exit 1 to mean."""
    (tmp_path / "random.safetensors").write_bytes(b"\x91\x3f" * 100)
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(tmp_path / "s.json")])

    assert result.exit_code == 1, result.output


def test_scan_reports_unreadable_files_distinctly(tmp_path):
    """AC#3 — surfaced as its own section, not folded into "Could not parse"."""
    (tmp_path / "model.safetensors").write_bytes(LFS_POINTER)
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(tmp_path / "s.json")])

    assert "Could not read" in result.output
    assert "git lfs pull" in result.output


def test_clean_tree_still_exits_0(tmp_path):
    """The other half of AC#6: no new failure for a scan with nothing wrong."""
    header = json.dumps({}).encode()
    (tmp_path / "good.safetensors").write_bytes(struct.pack("<Q", len(header)) + header)
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(tmp_path / "s.json")])

    assert result.exit_code == 0, result.output


def test_score_refuses_to_grade_an_unreadable_scan(tmp_path):
    """AC#5 — the #114 partial-scan gate keys off results["errors"], so it
    starts firing for local corruption and not only remote fetch failures."""
    (tmp_path / "random.safetensors").write_bytes(b"\x91\x3f" * 100)
    result = runner.invoke(app, ["score", str(tmp_path)])

    assert result.exit_code == 1, result.output
    assert "Refusing to score a partial scan" in result.output
