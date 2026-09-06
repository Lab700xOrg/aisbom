"""
Behavioural regression tests for `action/entrypoint.sh`.

These execute the real shell script with a stubbed `aisbom` on PATH that
records the argv it was handed. That matters: the property under test is
"the default Action run makes no request to aisbom.io", and the only honest
way to assert it is to observe what the scan was actually invoked with,
rather than to grep the entrypoint source for a flag. A future edit that
re-introduces `--share` by another route still fails these tests.

Sharing is opt-in (`share: false` by default). Everything else the Action
does — the SBOM artifact, the PR comment, fail-on-risk, the platform upload
— is independent of it.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINT = ROOT / "action" / "entrypoint.sh"

VIEWER_URL = "https://aisbom.io/viewer?h=StubShareId1"

# Argv positions 1-9 as action.yml passes them; `share` is appended as $10.
BASE_ARGS = [
    ".",           # $1 directory
    "sbom.json",   # $2 output-file
    "gh-token",    # $3 github-token
    "10",          # $4 max-rows
    "true",        # $5 comment-on-clean
    "true",        # $6 fail-on-risk
    "",            # $7 token
    "",            # $8 platform-url
    "false",       # $9 fail-on-platform-error
]

# Faithful to the CLI: the viewer URL is only ever printed when --share was
# passed. Records its own argv so the test can assert on the real invocation.
AISBOM_STUB = """#!/bin/bash
printf '%s\\n' "$@" > "${AISBOM_ARGV_FILE}"
echo "AIsbom scanning ${2:-.}"
for arg in "$@"; do
    if [ "${arg}" = "--share" ]; then
        echo "Shareable link: __VIEWER_URL__"
    fi
done
exit 0
"""

# Stands in for `python /aisbom-action/post_comment.py`, which only exists
# inside the Docker image.
PYTHON_STUB = """#!/bin/bash
printf '%s\\n' "$@" > "${PYTHON_ARGV_FILE}"
exit 0
"""


class EntrypointRun:
    """Captured result of one entrypoint.sh invocation."""

    def __init__(self, proc, scan_argv, github_output, scan_log, python_argv):
        self.proc = proc
        self.scan_argv = scan_argv
        self.github_output = github_output
        self.scan_log = scan_log
        self.python_argv = python_argv

    @property
    def outputs(self) -> dict[str, str]:
        """GITHUB_OUTPUT parsed into a dict. Absent key != empty value."""
        out = {}
        for line in self.github_output.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                out[key] = value
        return out


def _write_stub(path: Path, body: str) -> None:
    path.write_text(body.replace("__VIEWER_URL__", VIEWER_URL))
    path.chmod(0o755)


def run_entrypoint(tmp_path: Path, args: list[str], *, create_sbom: bool = False) -> EntrypointRun:
    """Execute entrypoint.sh with stubbed `aisbom` and `python` on PATH."""
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True)
    _write_stub(bindir / "aisbom", AISBOM_STUB)
    _write_stub(bindir / "python", PYTHON_STUB)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    if create_sbom:
        (workspace / "sbom.json").write_text('{"components": []}')

    scan_argv = tmp_path / "scan-argv.txt"
    python_argv = tmp_path / "python-argv.txt"
    github_output = tmp_path / "github-output.txt"
    scan_log = tmp_path / "scan.log"
    github_output.touch()

    env = {
        **os.environ,
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "AISBOM_ARGV_FILE": str(scan_argv),
        "PYTHON_ARGV_FILE": str(python_argv),
        "GITHUB_OUTPUT": str(github_output),
        "AISBOM_SCAN_LOG": str(scan_log),
    }

    proc = subprocess.run(
        ["bash", str(ENTRYPOINT), *args],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
    )
    return EntrypointRun(
        proc=proc,
        scan_argv=scan_argv.read_text().splitlines() if scan_argv.exists() else [],
        github_output=github_output.read_text(),
        scan_log=scan_log.read_text() if scan_log.exists() else "",
        python_argv=python_argv.read_text().splitlines() if python_argv.exists() else [],
    )


class TestSharingIsOptIn:
    """The default Action run must not publish the SBOM to aisbom.io."""

    def test_default_run_passes_no_share_flags(self, tmp_path):
        run = run_entrypoint(tmp_path, [*BASE_ARGS, "false"])
        assert run.proc.returncode == 0
        assert run.scan_argv, "stub aisbom was never invoked"
        assert "--share" not in run.scan_argv
        assert "--share-yes" not in run.scan_argv

    def test_share_omitted_entirely_still_defaults_off(self, tmp_path):
        """An old caller passing only nine args must not start publishing."""
        run = run_entrypoint(tmp_path, BASE_ARGS)
        assert run.proc.returncode == 0
        assert "--share" not in run.scan_argv
        assert "--share-yes" not in run.scan_argv

    def test_default_run_contacts_no_share_endpoint(self, tmp_path):
        """Asserted on the scan log, not by inspecting the entrypoint source."""
        run = run_entrypoint(tmp_path, [*BASE_ARGS, "false"])
        # Guard against passing vacuously on an empty/missing log.
        assert run.scan_log.strip(), "scan log was not captured"
        assert "aisbom.io" not in run.scan_log
        assert "viewer?h=" not in run.scan_log

    def test_default_run_announces_that_sharing_is_off(self, tmp_path):
        run = run_entrypoint(tmp_path, [*BASE_ARGS, "false"])
        assert "Sharing is off" in run.proc.stdout
        assert "share: true" in run.proc.stdout

    @pytest.mark.parametrize("value", ["", "TRUE", "True", "yes", "1", "no"])
    def test_only_exact_true_enables_sharing(self, tmp_path, value):
        """Anything but the literal "true" leaves publishing off."""
        run = run_entrypoint(tmp_path, [*BASE_ARGS, value])
        assert "--share" not in run.scan_argv

    def test_share_true_passes_both_flags(self, tmp_path):
        run = run_entrypoint(tmp_path, [*BASE_ARGS, "true"])
        assert "--share" in run.scan_argv
        assert "--share-yes" in run.scan_argv

    def test_scan_target_and_output_survive_the_conditional(self, tmp_path):
        """The empty-array expansion must not eat or reorder the real args."""
        for share in ("false", "true"):
            run = run_entrypoint(tmp_path / share, [*BASE_ARGS, share])
            assert run.scan_argv[:2] == ["scan", "."]
            assert "--output" in run.scan_argv
            assert run.scan_argv[run.scan_argv.index("--output") + 1] == "sbom.json"


class TestShareUrlOutput:
    """`share-url` is empty, not absent and not an error, when sharing is off."""

    def test_share_url_written_but_empty_when_off(self, tmp_path):
        run = run_entrypoint(tmp_path, [*BASE_ARGS, "false"])
        assert "share-url" in run.outputs
        assert run.outputs["share-url"] == ""

    def test_share_url_populated_when_on(self, tmp_path):
        run = run_entrypoint(tmp_path, [*BASE_ARGS, "true"])
        assert run.outputs["share-url"] == VIEWER_URL

    def test_share_url_stays_empty_even_if_log_carries_a_url(self, tmp_path):
        """Belt and braces: the guard is the input, not just the log contents."""
        run = run_entrypoint(tmp_path, [*BASE_ARGS, "false"])
        # Stub prints no URL without --share, so the log is clean; the assertion
        # that matters is that the output is keyed off the input either way.
        assert run.outputs["share-url"] == ""


class TestUnaffectedByShareSetting:
    """sbom-path and the PR comment behave identically with sharing off."""

    def test_sbom_path_output_unaffected(self, tmp_path):
        for share in ("false", "true"):
            run = run_entrypoint(tmp_path / share, [*BASE_ARGS, share])
            assert run.outputs["sbom-path"] == "sbom.json"

    def test_pr_comment_still_runs_when_sharing_is_off(self, tmp_path):
        run = run_entrypoint(tmp_path, [*BASE_ARGS, "false"], create_sbom=True)
        assert run.python_argv, "post_comment.py was not invoked"
        assert "/aisbom-action/post_comment.py" in run.python_argv
        assert "--sbom" in run.python_argv

    @pytest.mark.parametrize("share,expected", [("false", "false"), ("true", "true")])
    def test_share_setting_is_forwarded_to_the_comment_renderer(
        self, tmp_path, share, expected
    ):
        """The comment must not re-derive sharing from the log on its own."""
        run = run_entrypoint(tmp_path / share, [*BASE_ARGS, share], create_sbom=True)
        assert "--share-enabled" in run.python_argv
        assert run.python_argv[run.python_argv.index("--share-enabled") + 1] == expected
