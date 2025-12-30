import pytest
from pathlib import Path
from aisbom.mock_generator import (
    create_mock_malware_file,
    create_mock_restricted_file,
    create_mock_gguf,
    create_demo_diff_sboms
)

def test_create_mock_malware_file(tmp_path):
    f = create_mock_malware_file(tmp_path)
    assert f.exists()
    assert f.name == "mock_malware.pt"
    assert f.stat().st_size > 0

def test_create_mock_restricted_file(tmp_path):
    f = create_mock_restricted_file(tmp_path)
    assert f.exists()
    assert f.name == "mock_restricted.safetensors"
    # Basic check of content is hard without parsing, but size > 0
    assert f.stat().st_size > 0

def test_create_mock_gguf(tmp_path):
    f = create_mock_gguf(tmp_path)
    assert f.exists()
    assert f.name == "mock_restricted.gguf"
    assert f.read_bytes().startswith(b"GGUF")

def test_create_demo_diff_sboms(tmp_path):
    old, new = create_demo_diff_sboms(tmp_path)
    assert old.exists()
    assert new.exists()
    assert old.name == "sbom_baseline.json"
    assert new.name == "sbom_drifted.json"
    
    import json
    data = json.loads(new.read_text())
    assert "components" in data
    # Check that our specific drifted components exist
    names = [c["name"] for c in data["components"]]
    assert "drift-hash.pt" in names
    assert "drift-license.pt" in names
