from pathlib import Path
from aisbom.scanner import DeepScanner


def test_python_pth_config_is_safe(tmp_path):
    pth_file = tmp_path / "site-packages.pth"
    pth_file.write_text("/usr/local/lib/python3.11/site-packages")

    scanner = DeepScanner(tmp_path)
    results = scanner.scan()

    artifacts = {a["name"]: a for a in results["artifacts"]}
    assert "site-packages.pth" in artifacts
    meta = artifacts["site-packages.pth"]
    assert meta["risk_level"] == "LOW"
    assert meta["framework"] == "Python Path Config"
