import json
import os
import subprocess
import sys
from pathlib import Path

from aisbom.generator import create_mock_restricted_file, create_mock_gguf
from tests.test_scanner_cli import _write_malicious_pt


def _aisbom_executable() -> str:
    """Return the aisbom console script next to the current Python executable."""
    exe_path = Path(sys.executable).with_name("aisbom")
    return str(exe_path)


def _run_cli(args, cwd: Path, env=None):
    env_vars = os.environ.copy()
    if env:
        env_vars.update(env)
    result = subprocess.run(
        [_aisbom_executable(), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=env_vars,
    )
    return result


def test_cli_scan_subprocess_creates_sbom(tmp_path):
    _write_malicious_pt(tmp_path / "mock_malware.pt")
    create_mock_restricted_file(tmp_path)
    create_mock_gguf(tmp_path)
    (tmp_path / "requirements.txt").write_text("torch==2.1.0\nrequests>=2.0\n")

    output_path = tmp_path / "sbom.json"
    result = _run_cli(["scan", str(tmp_path), "--output", str(output_path)], cwd=tmp_path)

    assert result.returncode != 0, "Critical risk should trigger non-zero exit"
    assert output_path.is_file()

    sbom = json.loads(output_path.read_text())
    names = {c["name"] for c in sbom["components"]}
    assert {"mock_malware.pt", "mock_restricted.safetensors", "mock_restricted.gguf", "torch", "requests"} <= names


def test_cli_info_shows_version(tmp_path):
    result = _run_cli(["info"], cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Version:" in result.stdout


def test_generate_test_artifacts_creates_all_mocks(tmp_path):
    # Run the generator via CLI to ensure all mock files are produced
    result = _run_cli(["generate-test-artifacts", str(tmp_path)], cwd=tmp_path)
    assert result.returncode == 0, result.stderr

    expected = {"mock_malware.pt", "mock_restricted.safetensors", "mock_restricted.gguf"}
    produced = {p.name for p in tmp_path.iterdir() if p.is_file()}
    assert expected <= produced
