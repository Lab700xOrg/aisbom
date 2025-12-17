import json
import zipfile
from pathlib import Path
from typer.testing import CliRunner

from aisbom.cli import app
from aisbom.generator import create_mock_restricted_file
from aisbom.safety import scan_pickle_stream
from aisbom.scanner import DeepScanner


runner = CliRunner()

# Minimal pickle bytecode that uses STACK_GLOBAL to call os.system
STACK_GLOBAL_SYSTEM = b"\x80\x04\x8c\x02os\x8c\x06system\x93."


def _write_malicious_pt(path: Path):
    """Create a PyTorch-style archive with a known dangerous pickle payload."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("archive/data.pkl", STACK_GLOBAL_SYSTEM)
        zf.writestr("archive/version", "3")


def test_scan_pickle_stream_detects_dangerous_opcode():
    threats = scan_pickle_stream(STACK_GLOBAL_SYSTEM)

    assert threats, "Expected at least one dangerous opcode to be detected"
    assert "os.system" in threats


def test_deep_scanner_detects_artifacts_and_dependencies(tmp_path):
    _write_malicious_pt(tmp_path / "mock_malware.pt")
    create_mock_restricted_file(tmp_path)
    (tmp_path / "requirements.txt").write_text("torch==2.1.0\nrequests>=2.0\n")

    scanner = DeepScanner(tmp_path)
    results = scanner.scan()

    artifacts = {a["name"]: a for a in results["artifacts"]}
    assert "mock_malware.pt" in artifacts
    assert artifacts["mock_malware.pt"]["risk_level"].startswith("CRITICAL")
    assert artifacts["mock_malware.pt"]["hash"] != "hash_error"

    assert "mock_restricted.safetensors" in artifacts
    assert artifacts["mock_restricted.safetensors"]["legal_status"].startswith("LEGAL RISK")
    assert artifacts["mock_restricted.safetensors"]["license"] != "Unknown"

    deps = {d["name"]: d["version"] for d in results["dependencies"]}
    assert deps["torch"] == "2.1.0"
    assert deps["requests"] == "2.0"


def test_cli_scan_outputs_sbom_with_components(tmp_path):
    _write_malicious_pt(tmp_path / "mock_malware.pt")
    create_mock_restricted_file(tmp_path)
    (tmp_path / "requirements.txt").write_text("torch==2.1.0\nrequests>=2.0\n")

    output_path = tmp_path / "sbom.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(output_path)])

    assert result.exit_code == 0
    assert output_path.is_file()

    data = json.loads(output_path.read_text())
    component_names = {c["name"] for c in data["components"]}

    assert "mock_malware.pt" in component_names
    assert "mock_restricted.safetensors" in component_names
    assert "torch" in component_names
    assert "requests" in component_names
