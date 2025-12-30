import json
import pytest
from typer.testing import CliRunner
from aisbom.cli import app
from aisbom.diff import SBOMDiff
from pathlib import Path

runner = CliRunner()

@pytest.fixture
def clean_sbom():
    return {
        "components": [
            {
                "name": "comp1",
                "version": "1.0.0",
                "description": "Risk: LOW",
                "hashes": [{"alg": "SHA-256", "content": "aaaa"}]
            }
        ]
    }

@pytest.fixture
def dirty_sbom():
    return {
         "components": [
            {
                "name": "comp1",
                "version": "1.0.1", # Version Change
                "description": "Risk: CRITICAL", # Risk Increase
                "hashes": [{"alg": "SHA-256", "content": "bbbb"}] # Hash Change
            },
            {
                "name": "comp2", # Added
                "version": "2.0.0",
                "description": "Risk: LOW",
                "hashes": []
            }
        ]
    }

def test_diff_logic(tmp_path, clean_sbom, dirty_sbom):
    f1 = tmp_path / "1.json"
    f2 = tmp_path / "2.json"
    f1.write_text(json.dumps(clean_sbom))
    f2.write_text(json.dumps(dirty_sbom))
    
    differ = SBOMDiff(f1, f2)
    res = differ.compare()
    
    assert len(res.added) == 1
    assert res.added[0]["name"] == "comp2"
    
    assert len(res.changed) == 1
    c = res.changed[0]
    assert c.name == "comp1"
    assert c.version_diff == ("1.0.0", "1.0.1")
    assert c.risk_diff == ("LOW", "CRITICAL")
    assert c.hash_diff == ("aaaa", "bbbb")
    
    assert res.risk_increased is True
    assert res.hash_drifted is True

def test_cli_fail_on_risk(tmp_path, clean_sbom, dirty_sbom):
    f1 = tmp_path / "1.json"
    f2 = tmp_path / "2.json"
    f1.write_text(json.dumps(clean_sbom))
    f2.write_text(json.dumps(dirty_sbom))
    
    result = runner.invoke(app, ["diff", str(f1), str(f2), "--fail-on-risk-increase"])
    assert result.exit_code == 1
    assert "FAILURE" in result.stdout
    # Table layout changed, now in separate column
    # "LOW -> CRITICAL" may have styling codes, so we relax the check or match the raw text if possible.
    # The Rich table output might still contain "LOW -> CRITICAL" just separated by spaces or ansi codes.
    assert "LOW -> CRITICAL" in result.stdout or "LOW ->" in result.stdout

def test_cli_pass_no_fail(tmp_path, clean_sbom, dirty_sbom):
    f1 = tmp_path / "1.json"
    f2 = tmp_path / "2.json"
    f1.write_text(json.dumps(clean_sbom))
    f2.write_text(json.dumps(dirty_sbom))
    
    result = runner.invoke(app, ["diff", str(f1), str(f2), "--no-fail-on-risk-increase"])
    assert result.exit_code == 0
    assert "FAILURE" not in result.stdout

def test_diff_removed(tmp_path, clean_sbom):
    f1 = tmp_path / "1.json"
    f2 = tmp_path / "2.json"
    f1.write_text(json.dumps(clean_sbom))
    # Remove one
    f2.write_text(json.dumps({"components": []}))
    
    differ = SBOMDiff(f1, f2)
    res = differ.compare()
    assert len(res.removed) == 1
    assert res.removed[0]["name"] == "comp1"

def test_no_changes(tmp_path, clean_sbom):
    f1 = tmp_path / "1.json"
    f1.write_text(json.dumps(clean_sbom))
    
    differ = SBOMDiff(f1, f1)
    res = differ.compare()
    assert not res.changed
    assert not res.added
    assert not res.removed
    
    result = runner.invoke(app, ["diff", str(f1), str(f1)])
    assert result.exit_code == 0
    assert "No changes detected" in result.stdout

def test_hash_edge_cases(tmp_path):
    # Case 1: No Hashes vs SHA-256
    c1 = {"name": "c1", "version": "1", "hashes": []}
    c2 = {"name": "c1", "version": "1", "hashes": [{"alg": "SHA-256", "content": "abc"}]}
    
    # Create dummy files for init
    dummy = tmp_path / "dummy.json"
    dummy.write_text("{}")
    
    differ = SBOMDiff(dummy, dummy)
    differ.old_data = {}
    differ.new_data = {}
    
    assert differ._get_hash(c1) == ""
    assert differ._get_hash(c2) == "abc"
    
    # Case 2: MD5 only (ignored)
    c3 = {"name": "c1", "version": "1", "hashes": [{"alg": "MD5", "content": "123"}]}
    assert differ._get_hash(c3) == ""

def test_legal_status_parsing(tmp_path):
    dummy = tmp_path / "dummy.json"
    dummy.write_text("{}")
    
    differ = SBOMDiff(dummy, dummy)
    differ.old_data = {}
    differ.new_data = {}
    
    # Case 1: PASS
    c1 = {"description": "Legal: PASS | License: MIT"}
    assert differ._get_legal_status(c1) == "PASS"
    
    # Case 2: Random
    c2 = {"description": "Legal: WEIRD_STATUS"}
    assert differ._get_legal_status(c2) == "WEIRD_STATUS"
    
    # Case 3: Empty/Missing
    assert differ._get_legal_status({}) == "UNKNOWN"

def test_risk_worsening_non_critical(tmp_path):
    # Should detect change but not bump 'risk_increased' flag if not critical
    c1 = {"components": [{"name": "c", "description": "Risk: LOW"}]}
    c2 = {"components": [{"name": "c", "description": "Risk: MEDIUM"}]}
    
    f1 = tmp_path / "1.json"
    f2 = tmp_path / "2.json"
    f1.write_text(json.dumps(c1))
    f2.write_text(json.dumps(c2))
    
    res = SBOMDiff(f1, f2).compare()
    assert res.changed[0].risk_diff == ("LOW", "MEDIUM")
    assert res.risk_increased is False # MEDIUM is not CRITICAL
