import pytest
import json
from aisbom.spdx_gen import generate_spdx_sbom

def test_spdx_generation():
    # Mock Results
    results = {
        "artifacts": [
            {
                "name": "model.pkl",
                "filename": "model.pkl",
                "risk_level": "LOW",
                "legal_status": "PASS",
                "framework": "PyTorch",
                "format": "pickle",
                "hash": "abcdef123456"
            }
        ],
        "dependencies": [
            {
                "name": "requests",
                "version": "2.28.1"
            }
        ],
        "errors": []
    }
    
    # Generate SPDX
    spdx_json_str = generate_spdx_sbom(results)
    
    # Verify it is valid JSON
    data = json.loads(spdx_json_str)
    
    # Verify Structure
    assert "SPDXID" in data
    assert data["name"] == "AIsbom-Scan"
    assert len(data.get("packages", [])) == 2
    
    # Check Artifact Mapping
    pkgs = data["packages"]
    model_pkg = next(p for p in pkgs if "model" in p["name"])
    assert model_pkg["name"] == "model.pkl"
    assert "SPDXRef-Artifact-" in model_pkg["SPDXID"]
    assert "PyTorch" in model_pkg.get("comment", "")
    
    # Check Dependency Mapping
    lib_pkg = next(p for p in pkgs if p["name"] == "requests")
    assert lib_pkg["versionInfo"] == "2.28.1"
    assert "SPDXRef-Lib-" in lib_pkg["SPDXID"]
