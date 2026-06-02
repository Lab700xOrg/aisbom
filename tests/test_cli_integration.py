import json
import os
import subprocess
import sys
import importlib
from aisbom.cli import app
from typer.testing import CliRunner
from pathlib import Path

from aisbom.mock_generator import create_mock_malware_file, create_mock_restricted_file, create_mock_gguf
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


runner = CliRunner()


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


def test_cli_scan_emits_namespaced_properties_per_format(tmp_path):
    _write_malicious_pt(tmp_path / "mock_malware.pt")
    create_mock_restricted_file(tmp_path)
    create_mock_gguf(tmp_path)

    output_path = tmp_path / "sbom.json"
    _run_cli(["scan", str(tmp_path), "--output", str(output_path)], cwd=tmp_path)

    sbom = json.loads(output_path.read_text())
    by_name = {c["name"]: c for c in sbom["components"]}

    def props(comp):
        out = {}
        for p in comp.get("properties", []):
            out.setdefault(p["name"], []).append(p["value"])
        return out

    # Pickle: format + at least one opcode + a count, all aisbom:* namespaced.
    pkl = props(by_name["mock_malware.pt"])
    assert pkl["aisbom:format"] == ["pickle"]
    assert len(pkl["aisbom:pickle:opcode"]) >= 1
    assert pkl["aisbom:pickle:opcode_count"][0] == str(len(pkl["aisbom:pickle:opcode"]))

    # SafeTensors: format + tensor count.
    st = props(by_name["mock_restricted.safetensors"])
    assert st["aisbom:format"] == ["safetensors"]
    assert "aisbom:safetensors:tensor_count" in st

    # GGUF: format + metadata keys.
    gg = props(by_name["mock_restricted.gguf"])
    assert gg["aisbom:format"] == ["gguf"]
    assert "aisbom:gguf:metadata_keys" in gg

    # Backwards compatibility: the human description string is unchanged.
    assert by_name["mock_malware.pt"]["description"].startswith("Risk:")
    for comp in (by_name["mock_malware.pt"], by_name["mock_restricted.safetensors"]):
        for name in props(comp):
            assert name.startswith("aisbom:")


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


def test_cli_scan_no_artifacts_is_success(tmp_path):
    output_path = tmp_path / "sbom.json"
    result = _run_cli(["scan", str(tmp_path), "--output", str(output_path)], cwd=tmp_path)
    assert result.returncode == 0
    assert output_path.is_file()


def test_cli_scan_defaults_to_sbom_json_when_output_missing(tmp_path, monkeypatch):
    _write_malicious_pt(tmp_path / "mock_malware.pt")
    create_mock_restricted_file(tmp_path)
    create_mock_gguf(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    sbom_path = tmp_path / "sbom.json"
    assert sbom_path.exists()


def test_cli_scan_schema_v15_branch(tmp_path):
    _write_malicious_pt(tmp_path / "mock_malware.pt")
    create_mock_restricted_file(tmp_path)
    create_mock_gguf(tmp_path)
    output_path = tmp_path / "sbom15.json"
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--schema-version", "1.5", "--output", str(output_path)],
    )
    assert result.exit_code == 2
    assert output_path.exists()


def test_cli_scan_markdown_default_output(tmp_path, monkeypatch):
    _write_malicious_pt(tmp_path / "mock_malware.pt")
    create_mock_restricted_file(tmp_path)
    create_mock_gguf(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "markdown"])
    assert result.exit_code == 2
    md_path = tmp_path / "aisbom-report.md"
    assert md_path.exists()
    content = md_path.read_text()
    assert "AIsbom Report" in content
    assert "mock_malware.pt" in content
    assert "mock_malware.pt" in content

def test_cli_diff_command(tmp_path):
    # Use generator to make real files
    create_mock_malware_file(tmp_path)
    (tmp_path / "sbom1.json").write_text(json.dumps({"components": []}))
    (tmp_path / "sbom2.json").write_text(json.dumps({
        "components": [{
            "name": "mock_malware.pt", 
            "version": "1.0", 
            "description": "Risk: CRITICAL"
        }]
    }))
    
    result = runner.invoke(app, ["diff", str(tmp_path/"sbom1.json"), str(tmp_path/"sbom2.json")])
    assert result.exit_code == 1
    assert "FAILURE" in result.stdout
    assert "mock_malware.pt" in result.stdout
