"""Local scan-target shapes: a single file, a directory, and unusable paths.

`Path.rglob` only ever yields the *contents* of a directory. The local branch
of `DeepScanner.scan()` used it as its only discovery mechanism, so a target
that was a regular file — or a path that did not exist at all — walked nothing,
recorded no error, and produced a clean `exit 0`. A malicious `.pt` named
directly on the command line reported "No AI models found" while the identical
file scanned via its parent directory was correctly CRITICAL (#125).

That is the worst possible failure mode for a CI gate: the tool reports success
and emits a well-formed SBOM asserting zero components. These tests pin the
distinction the fix rests on — *nothing to report* (an empty directory, exit 0)
versus *nothing was examined* (an unusable target, exit 1) — since both used to
look identical from the outside.

The README documents the single-file form for both flagship security features
(`aisbom scan model.pkl --strict`, `aisbom scan model.pt --lint`), so those
invocations are covered explicitly rather than only via a directory.
"""

import pytest
from typer.testing import CliRunner

from aisbom.cli import app
from aisbom.mock_generator import create_mock_gguf, create_mock_restricted_file
from aisbom.scanner import DeepScanner
from tests.test_scanner_cli import _write_malicious_pt

runner = CliRunner()


def _unwrapped(text: str) -> str:
    """Strip all whitespace so assertions survive rich's line wrapping.

    Absolute temp paths are longer than the 80-column test terminal, and rich
    breaks them mid-token, so a plain `path in output` check fails for a
    message that rendered correctly.
    """
    return "".join(text.split())


# --- a single file is a first-class target -------------------------------


@pytest.mark.parametrize("flags", [[], ["--strict"], ["--lint"]])
def test_single_malicious_file_target_is_critical(tmp_path, flags):
    """The regression itself: a malicious file named directly must exit 2.

    Parametrized over the two modes the README documents with a file target,
    because the bug was in target discovery and so was mode-independent.
    """
    model = tmp_path / "mock_malware.pt"
    _write_malicious_pt(model)

    result = runner.invoke(app, ["scan", str(model), *flags])

    assert result.exit_code == 2
    assert "No AI models found" not in result.output


def test_single_file_and_parent_directory_agree(tmp_path):
    """A file must get the same verdict whichever way it is reached.

    This is the invariant the bug broke, and the cheapest guard against the
    file path and the directory walk drifting apart again.
    """
    _write_malicious_pt(tmp_path / "mock_malware.pt")

    via_file = DeepScanner(str(tmp_path / "mock_malware.pt")).scan()
    via_dir = DeepScanner(str(tmp_path)).scan()

    assert len(via_file["artifacts"]) == len(via_dir["artifacts"]) == 1
    assert via_file["artifacts"][0]["risk_level"] == via_dir["artifacts"][0]["risk_level"]
    assert "CRITICAL" in via_file["artifacts"][0]["risk_level"]
    assert via_file["errors"] == []


@pytest.mark.parametrize(
    "make_file, expected_name",
    [
        (create_mock_restricted_file, "mock_restricted.safetensors"),
        (create_mock_gguf, "mock_restricted.gguf"),
    ],
)
def test_single_file_target_works_for_every_format(tmp_path, make_file, expected_name):
    """Single-file targets are not a PyTorch-only affordance."""
    make_file(tmp_path)

    results = DeepScanner(str(tmp_path / expected_name)).scan()

    assert [a["name"] for a in results["artifacts"]] == [expected_name]
    assert results["errors"] == []


def test_single_requirements_file_target_parses_dependencies(tmp_path):
    """`requirements.txt` is matched by name, so it works as a target too."""
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("torch==2.1.0\nrequests>=2.0\n")

    results = DeepScanner(str(reqs)).scan()

    assert len(results["dependencies"]) == 2
    assert results["errors"] == []


# --- unusable targets are errors, not empty results ----------------------


def test_nonexistent_target_is_an_error(tmp_path):
    """Exit 1, and the message must name the path that could not be scanned."""
    missing = tmp_path / "does-not-exist.pt"

    result = runner.invoke(app, ["scan", str(missing)])

    output = _unwrapped(result.output)
    assert result.exit_code == 1
    assert _unwrapped(str(missing)) in output
    assert _unwrapped("Cannot scan") in output
    assert _unwrapped("No such file or directory") in output
    # The old behavior. It is a claim about the target's contents and must not
    # appear when the target was never opened.
    assert "No AI models found" not in result.output


def test_nonexistent_target_records_a_structured_error(tmp_path):
    results = DeepScanner(str(tmp_path / "nope")).scan()

    assert len(results["errors"]) == 1
    error = results["errors"][0]
    assert error["target_error"] is True
    assert "No such file or directory" in error["error"]
    # Fetch-failure rendering expects a live exception; target errors must not
    # be mistaken for one.
    assert not error.get("fetch_failure")


def test_unsupported_single_file_target_is_an_error(tmp_path):
    """Naming a file no scanner claims is a failed instruction, not a result.

    Distinct from the directory walk, where skipping a non-model file is
    correct — see the sibling test below.
    """
    notes = tmp_path / "notes.txt"
    notes.write_text("not a model\n")

    result = runner.invoke(app, ["scan", str(notes)])

    assert result.exit_code == 1
    assert _unwrapped(str(notes)) in _unwrapped(result.output)
    assert _unwrapped("Unsupported file type") in _unwrapped(result.output)


def test_broken_symlink_target_is_an_error(tmp_path):
    """`is_dir()`/`is_file()` follow symlinks, so a dangling link reads missing."""
    link = tmp_path / "dangling"
    link.symlink_to(tmp_path / "nowhere")

    results = DeepScanner(str(link)).scan()

    assert len(results["errors"]) == 1
    assert results["errors"][0]["target_error"] is True


# --- the other side of the line: genuinely clean scans stay exit 0 -------


def test_empty_directory_is_still_a_clean_scan(tmp_path):
    """Guard against over-correcting: nothing to report is not an error."""
    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0
    assert "No AI models found" in result.output


def test_directory_walk_still_ignores_unsupported_files(tmp_path):
    """A tree legitimately contains non-model files; that is not an error."""
    (tmp_path / "README.md").write_text("# notes\n")
    (tmp_path / "notes.txt").write_text("not a model\n")

    results = DeepScanner(str(tmp_path)).scan()

    assert results["artifacts"] == []
    assert results["errors"] == []


# --- interaction with the risk gate --------------------------------------


def test_no_fail_on_risk_does_not_suppress_a_target_error(tmp_path):
    """`--fail-on-risk` governs risk findings only, never a broken target.

    A pipeline that opts out of risk-gating still needs to hear that its path
    was wrong, otherwise the flag silently restores the original bug.
    """
    result = runner.invoke(app, ["scan", str(tmp_path / "gone"), "--no-fail-on-risk"])

    assert result.exit_code == 1


def test_no_fail_on_risk_still_clears_a_real_critical(tmp_path):
    """The complement, so the test above cannot pass for the wrong reason."""
    _write_malicious_pt(tmp_path / "mock_malware.pt")

    result = runner.invoke(app, ["scan", str(tmp_path), "--no-fail-on-risk"])

    assert result.exit_code == 0
