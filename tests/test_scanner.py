import pickle
import pytest
import struct
from aisbom.scanner import DeepScanner

class Unsafe:
    pass

def test_scanner_legacy_binary_lint(tmp_path):
    # A bare (non-ZIP) .pt holding a benign protocol-0 pickle. `Unsafe` is an
    # empty class — the name is historical; nothing here is dangerous.
    f = tmp_path / "legacy.pt"
    f.write_bytes(pickle.dumps(Unsafe(), protocol=0))

    scanner = DeepScanner(str(tmp_path), lint=True)
    results = scanner.scan()

    artifact = results['artifacts'][0]
    # This used to report CRITICAL (Legacy Binary), which was a false positive:
    # the verdict came from the bytes not looking like text, not from anything
    # found in them. The stream is now disassembled first, so a well-formed
    # pickle with no dangerous global gets the same verdict the ZIP path gives
    # the same content. `--strict` still escalates an unrecognized import here.
    assert artifact['risk_level'] == "MEDIUM (Pickle Present)"
    assert "lint_report" in artifact['details']
    assert any("Unsafe" in e['msg'] for e in artifact['details']['lint_report'])


def test_bare_legacy_pickle_with_unknown_global_is_critical_in_strict_mode(tmp_path):
    """The strict-mode safety net over the MEDIUM verdict above."""
    f = tmp_path / "legacy.pt"
    f.write_bytes(pickle.dumps(Unsafe(), protocol=0))

    artifact = DeepScanner(str(tmp_path), strict_mode=True).scan()['artifacts'][0]
    assert "CRITICAL" in artifact['risk_level']
    assert "UNSAFE_IMPORT" in artifact['risk_level']

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
