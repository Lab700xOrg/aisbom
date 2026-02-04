import pytest
from typer.testing import CliRunner
from aisbom.cli import app
from aisbom.scanner import DeepScanner
from unittest.mock import patch, MagicMock
from pathlib import Path

runner = CliRunner()

@pytest.fixture(autouse=True)
def mock_version_check():
    """Disable network calls in CLI tests."""
    with patch("aisbom.cli.check_latest_version", return_value="0.0.0"):
        yield

def test_cli_diff_command(tmp_path):
    """Test the 'aisbom diff' command via CLI to cover cli.py lines."""
    old_sbom = tmp_path / "old.json"
    new_sbom = tmp_path / "new.json"
    
    old_sbom.write_text('{}')
    new_sbom.write_text('{}')
    
    with patch("aisbom.cli.SBOMDiff") as MockDiff:
        instance = MockDiff.return_value
        mock_result = MagicMock()
        mock_result.added = []
        mock_result.removed = []
        # Ensure we have at least one change to trigger the loop
        change_mock = MagicMock()
        change_mock.name = "model-a" # Set attribute explicitly for Rich table
        change_mock.risk_diff = ("LOW", "MEDIUM")
        change_mock.legal_status_diff = None
        change_mock.license_diff = None
        change_mock.version_diff = ("1.0", "1.1")
        change_mock.hash_diff = None
        
        mock_result.changed = [change_mock]
        mock_result.risk_increased = False
        mock_result.hash_drifted = False
        instance.compare.return_value = mock_result
        
        result = runner.invoke(app, ["diff", str(old_sbom), str(new_sbom)])
        if result.exit_code != 0:
            with open("test_debug.log", "a") as log:
                log.write(f"\n--- Diff Test Failure ---\nOutput: {result.stdout}\nException: {result.exception}\n")
                if result.exc_info:
                    import traceback
                    traceback.print_exception(*result.exc_info, file=log)
        assert result.exit_code == 0
        assert "Comparing" in result.stdout
        assert "DRIFT" in result.stdout
        assert "Ver: 1.0 -> 1.1" in result.stdout

def test_cli_scan_spdx(tmp_path):
    """Test scan with SPDX output format."""
    (tmp_path / "test.pt").touch()
    
    with patch("aisbom.cli.DeepScanner") as MockScanner:
        instance = MockScanner.return_value
        instance.scan.return_value = {
            "artifacts": [{
                "name": "test.pt", 
                "risk_level": "LOW", 
                "framework": "PyTorch", 
                "license": "MIT",
                "legal_status": "UNKNOWN" # Required field
            }],
            "dependencies": [],
            "errors": []
        }
        
        output_file = tmp_path / "out.spdx.json"
        
        # Patching the module where the function is DEFINED, not where it's imported locally
        with patch("aisbom.spdx_gen.generate_spdx_sbom", return_value="SPDX-2.3"):
            result = runner.invoke(app, ["scan", str(tmp_path), "--format", "spdx", "--output", str(output_file)])
            
        if result.exit_code != 0:
            with open("test_debug.log", "a") as log:
                log.write(f"\n--- SPDX Test Failure ---\nOutput: {result.stdout}\nException: {result.exception}\n")
        
        assert result.exit_code == 0
        assert output_file.exists()
        assert "SPDX-2.3" in output_file.read_text()

def test_cli_scan_lint(tmp_path):
    """Test scan with --lint flag enabled."""
    (tmp_path / "test.pkl").touch()
    
    with patch("aisbom.cli.DeepScanner") as MockScanner:
        instance = MockScanner.return_value
        instance.scan.return_value = {
            "artifacts": [{
                "name": "test.pkl", 
                "risk_level": "CRITICAL",
                "framework": "PyTorch", 
                "details": {
                    "lint_report": [{"msg": "Unsafe global", "hint": "Fix it", "severity": "ERROR"}]
                },
                "legal_status": "UNKNOWN" # Added missing key to prevent potential key errors in render
            }],
            "dependencies": [],
            "errors": []
        }
        
        result = runner.invoke(app, ["scan", str(tmp_path), "--lint", "--no-fail-on-risk"])
        print(result.stdout)
        assert result.exit_code == 0
        assert "Migration Readiness" in result.stdout


def test_scanner_hash_error(tmp_path):
    """Test handling of hash calculation errors (PermissionError)."""
    f = tmp_path / "locked.file"
    f.touch()
    f.chmod(0o000) # Remove read permissions
    
    scanner = DeepScanner(str(tmp_path))
    try:
        # Depending on OS/User execution, this might still be readable by root, 
        # so we force the exception via mock if needed, but let's try real first.
        # If real fails to trigger, we mock.
        if f.stat().st_mode & 0o400: # If still readable (unlikely on nix unless root)
             with patch("builtins.open", side_effect=PermissionError("Mock")):
                 h = scanner._calculate_hash(f)
        else:
             h = scanner._calculate_hash(f)
    except:
        # Fallback to mock if chmod didn't work as expected
        with patch("builtins.open", side_effect=PermissionError("Mock")):
             h = scanner._calculate_hash(f)
    
    # Restore permissions to clean up
    f.chmod(0o666)
    
    assert h == "hash_error"

def test_scanner_invalid_gguf(tmp_path):
    """Test GGUF parser handles invalid magic header."""
    f = tmp_path / "bad.gguf"
    f.write_bytes(b"BAD_MAGIC_HEADER")
    
    scanner = DeepScanner(str(tmp_path))
    meta = scanner._inspect_gguf(f)
    assert "Invalid Header" in meta["risk_level"]

def test_scanner_malformed_requirements(tmp_path):
    """Test handling of malformed requirements.txt."""
    req = tmp_path / "requirements.txt"
    req.write_text("This is not a valid requirement file")
    
    scanner = DeepScanner(str(tmp_path))
    scanner._parse_requirements(req)
    # pip-requirements-parser might handle some junk, but let's ensure it doesn't crash
    # and if it errors, it goes to errors list.
    assert len(scanner.errors) == 0 # It might just parse 0 deps, which is fine.
    
    # Force an exception to test the try/except block
    with patch("pip_requirements_parser.RequirementsFile.from_file", side_effect=Exception("Boom")):
        scanner._parse_requirements(req)
        assert len(scanner.errors) == 1
        assert "Boom" in scanner.errors[0]["error"]

def test_scanner_remote_variants():
    """Test remote resolution for specific types (Mocked)."""
    scanner = DeepScanner("hf://test/repo")
    
    # Mock remote stream context
    with patch("aisbom.scanner.RemoteStream") as MockStream:
         MockStream.return_value.__enter__.return_value = MagicMock()
         
         # 1. Safetensors
         with patch("aisbom.scanner.resolve_huggingface_repo", return_value=["https://huggingface.co/test/model.safetensors"]):
             with patch.object(scanner, "_inspect_safetensors") as mock_insp:
                 scanner.scan()
                 mock_insp.assert_called_once()
                 
         # 2. GGUF
         with patch("aisbom.scanner.resolve_huggingface_repo", return_value=["https://huggingface.co/test/model.gguf"]):
             with patch.object(scanner, "_inspect_gguf") as mock_insp:
                 scanner.scan()
                 mock_insp.assert_called_once()
