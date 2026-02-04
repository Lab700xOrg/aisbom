import pickle
import pytest
import struct
from aisbom.scanner import DeepScanner

class Unsafe:
    pass

def test_scanner_legacy_binary_lint(tmp_path):
    # Create a dummy .pt file that is NOT a zip (legacy binary)
    # And contains an unsafe import to trigger linter
    f = tmp_path / "legacy.pt"
    # Protocol 0 usually ensures it's not detected as zip/text
    # We use Unsafe class to verify linter actually ran in that block
    f.write_bytes(pickle.dumps(Unsafe(), protocol=0))
    
    scanner = DeepScanner(str(tmp_path), lint=True)
    results = scanner.scan()
    
    artifact = results['artifacts'][0]
    assert artifact['risk_level'] == "CRITICAL (Legacy Binary)"
    assert "lint_report" in artifact['details']
    assert any("Unsafe" in e['msg'] for e in artifact['details']['lint_report'])

def test_scanner_safetensors_coverage(tmp_path):
    # Minimal safetensors header to hit _inspect_safetensors lines
    f = tmp_path / "model.safetensors"
    header_json = b'{"__metadata__": {"license": "mit"}, "tensor": {"dtype":"F16", "shape":[1]}}'
    f.write_bytes(struct.pack('<Q', len(header_json)) + header_json)
    
    scanner = DeepScanner(str(tmp_path))
    results = scanner.scan()
    
    artifact = results['artifacts'][0]
    assert artifact['framework'] == "SafeTensors"
    assert artifact['license'] == "mit"
