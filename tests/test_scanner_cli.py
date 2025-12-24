import json
import zipfile
import struct
import importlib
from pathlib import Path
from typer.testing import CliRunner

from aisbom.cli import app
from aisbom.generator import (
    MockExploitPayload,
    create_mock_malware_file,
    create_mock_restricted_file,
    create_mock_gguf,
)
from aisbom.safety import scan_pickle_stream
from aisbom.scanner import DeepScanner
from aisbom import cli as cli_module


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


def test_scan_pickle_stream_detects_global_with_space_separator():
    import pickle

    payload = pickle.dumps(MockExploitPayload(), protocol=2)
    threats = scan_pickle_stream(payload)
    assert threats and any("posix.system" in t for t in threats)


def test_scan_pickle_stream_strict_mode_blocks_unknown_imports():
    threats = scan_pickle_stream(STACK_GLOBAL_SYSTEM, strict_mode=True)
    assert threats == ["UNSAFE_IMPORT: os.system"]


def test_scan_pickle_stream_strict_mode_allows_safe_builtin():
    # STACK_GLOBAL for builtins.getattr
    safe_builtin = b"\x80\x04\x8c\x08builtins\x8c\x07getattr\x93."
    threats = scan_pickle_stream(safe_builtin, strict_mode=True)
    assert threats == []


def test_mock_exploit_payload_reduce_has_os_system():
    func, args = MockExploitPayload().__reduce__()
    assert func.__name__ == "system"
    assert "AIsbom RCE simulation" in args[0]


def test_create_mock_malware_file_writes_zip(tmp_path):
    pt_path = create_mock_malware_file(tmp_path)
    assert pt_path.exists()
    with zipfile.ZipFile(pt_path, "r") as zf:
        assert "archive/data.pkl" in zf.namelist()


def test_generate_markdown_renders_table():
    results = {
        "artifacts": [
            {
                "name": "model.pt",
                "framework": "PyTorch",
                "risk_level": "CRITICAL (RCE Detected)",
                "legal_status": "LEGAL RISK (cc)",
                "hash": "deadbeefcafebabe",
            }
        ],
        "dependencies": [{"name": "torch"}],
    }
    md = cli_module._generate_markdown(results)
    assert "AIsbom Report" in md
    assert "Dependencies found: **1**" in md
    assert "| model.pt | PyTorch | 🔴" in md
    assert "deadbeef" in md


def test_info_command_falls_back_when_package_missing(monkeypatch):
    import aisbom.cli as cli

    def _raise_package_not_found(name):
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(cli.importlib.metadata, "version", _raise_package_not_found)
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "unknown (dev build)" in result.stdout


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


def test_deep_scanner_strict_mode_marks_unknown_imports(tmp_path):
    _write_malicious_pt(tmp_path / "strict_malware.pt")  # stack global os.system
    scanner = DeepScanner(tmp_path, strict_mode=True)
    results = scanner.scan()
    threats = results["artifacts"][0]["details"]["threats"]
    assert any("UNSAFE_IMPORT" in t for t in threats)


def test_deep_scanner_handles_generated_mock_malware(tmp_path):
    create_mock_malware_file(tmp_path)
    scanner = DeepScanner(tmp_path)
    results = scanner.scan()
    threats = results["artifacts"][0]["details"]["threats"]
    assert any("posix.system" in t or "os.system" in t for t in threats)


def test_deep_scanner_flags_legacy_pt_when_not_zip(tmp_path):
    legacy = tmp_path / "legacy_model.pt"
    legacy.write_bytes(b"not a zip file")

    scanner = DeepScanner(tmp_path)
    results = scanner.scan()
    art = {a["name"]: a for a in results["artifacts"]}[legacy.name]
    assert art["risk_level"] == "LOW"
    assert art["framework"] == "Python Path Config"


def test_cli_scan_outputs_sbom_with_components(tmp_path):
    _write_malicious_pt(tmp_path / "mock_malware.pt")
    create_mock_restricted_file(tmp_path)
    create_mock_gguf(tmp_path)
    (tmp_path / "requirements.txt").write_text("torch==2.1.0\nrequests>=2.0\n")

    output_path = tmp_path / "sbom.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(output_path)])

    assert result.exit_code == 2  # Critical risk -> non-zero exit
    assert output_path.is_file()

    data = json.loads(output_path.read_text())
    component_names = {c["name"] for c in data["components"]}

    assert "mock_malware.pt" in component_names
    assert "mock_restricted.safetensors" in component_names
    assert "mock_restricted.gguf" in component_names
    assert "torch" in component_names
    assert "requests" in component_names


def test_gguf_scanning_sets_license_and_legal_status(tmp_path):
    gguf_path = create_mock_gguf(tmp_path)

    scanner = DeepScanner(tmp_path)
    results = scanner.scan()

    artifacts = {a["name"]: a for a in results["artifacts"]}
    assert gguf_path.name in artifacts
    gguf = artifacts[gguf_path.name]
    assert gguf["framework"] == "GGUF"
    assert gguf["risk_level"] == "LOW"
    assert gguf["license"] == "cc-by-nc-sa-4.0"
    assert gguf["legal_status"].startswith("LEGAL RISK")
    assert gguf["hash"] != "hash_error"


def test_gguf_scalar_kv_parsing_skips_numeric_entries(tmp_path):
    # Craft GGUF with a numeric KV (val_type=0) to exercise skip logic
    path = tmp_path / "numeric.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version
        f.write(struct.pack("<Q", 0))  # tensor count
        f.write(struct.pack("<Q", 1))  # kv count
        key = "general.weight_count"
        f.write(struct.pack("<Q", len(key)))
        f.write(key.encode())
        f.write(struct.pack("<I", 0))  # val_type uint8
        f.write(struct.pack("<Q", 1))  # value bytes (uint8)
        f.write(b"\x01")

    scanner = DeepScanner(tmp_path)
    results = scanner.scan()
    gguf = {a["name"]: a for a in results["artifacts"]}[path.name]
    assert gguf["risk_level"] == "LOW"


def test_gguf_array_entry_causes_parse_break(tmp_path):
    path = tmp_path / "array.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 0))  # tensor count
        f.write(struct.pack("<Q", 1))  # kv count
        key = "general.arch"
        f.write(struct.pack("<Q", len(key)))
        f.write(key.encode())
        f.write(struct.pack("<I", 9))  # val_type array -> triggers break
        f.write(struct.pack("<Q", 0))

    scanner = DeepScanner(tmp_path)
    results = scanner.scan()
    gguf = {a["name"]: a for a in results["artifacts"]}[path.name]
    assert gguf["risk_level"] == "LOW"


def test_cli_scan_allows_success_when_fail_on_risk_disabled(tmp_path):
    _write_malicious_pt(tmp_path / "mock_malware.pt")
    create_mock_restricted_file(tmp_path)
    create_mock_gguf(tmp_path)
    (tmp_path / "requirements.txt").write_text("torch==2.1.0\nrequests>=2.0\n")

    output_path = tmp_path / "sbom.json"
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--output", str(output_path), "--no-fail-on-risk"],
    )

    assert result.exit_code == 0
    assert output_path.is_file()
