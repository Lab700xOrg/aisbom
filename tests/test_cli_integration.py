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


# ---------------------------------------------------------------------------
# #111 — CycloneDX 1.7 is the default output.
# ---------------------------------------------------------------------------


def _scan_to_sbom(tmp_path, name, *extra_args):
    _write_malicious_pt(tmp_path / "mock_malware.pt")
    create_mock_restricted_file(tmp_path)
    create_mock_gguf(tmp_path)
    output_path = tmp_path / name
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--output", str(output_path), *extra_args]
    )
    assert result.exit_code == 2
    return json.loads(output_path.read_text())


def test_cli_scan_defaults_to_cyclonedx_1_7(tmp_path):
    sbom = _scan_to_sbom(tmp_path, "default.json")
    assert sbom["specVersion"] == "1.7"
    assert sbom["bomFormat"] == "CycloneDX"


def test_cli_scan_explicit_1_6_still_emits_1_6_without_model_cards(tmp_path):
    """Pinning the old version keeps the exact pre-#111 document shape."""
    sbom = _scan_to_sbom(tmp_path, "pinned.json", "--schema-version", "1.6")
    assert sbom["specVersion"] == "1.6"
    assert all("modelCard" not in c for c in sbom["components"])


def test_local_gguf_scan_carries_a_model_card_with_no_network(tmp_path):
    """AC: local scans benefit too — the family comes from the GGUF header.

    Uses a GGUF that actually declares `general.architecture`; the shared mock
    fixture only carries a license key, so it legitimately yields no card.
    """
    from tests.test_gguf_template import _gguf_with_templates

    _gguf_with_templates(tmp_path / "llama-model.gguf", {})
    output_path = tmp_path / "gguf.json"
    runner.invoke(app, ["scan", str(tmp_path), "--output", str(output_path)])

    sbom = json.loads(output_path.read_text())
    (gguf,) = [c for c in sbom["components"] if c["name"] == "llama-model.gguf"]
    assert gguf["modelCard"]["modelParameters"] == {"architectureFamily": "llama"}


def test_gguf_without_an_architecture_gets_no_model_card(tmp_path):
    """Nothing known → no empty `modelCard: {}` noise in the artifact."""
    sbom = _scan_to_sbom(tmp_path, "sparse.json")
    gguf = [c for c in sbom["components"] if c["name"].endswith(".gguf")]
    assert gguf and "modelCard" not in gguf[0]


def test_default_scan_preserves_every_1_6_component_field(tmp_path):
    """The additive guarantee, asserted through the real CLI rather than a
    hand-built BOM: descriptions, hashes, licenses and aisbom:* properties all
    survive the default flip untouched."""
    old = _scan_to_sbom(tmp_path, "old.json", "--schema-version", "1.6")
    new = _scan_to_sbom(tmp_path, "new.json")

    old_by_name = {c["name"]: c for c in old["components"]}
    new_by_name = {c["name"]: c for c in new["components"]}
    assert set(old_by_name) == set(new_by_name)

    for name, old_component in old_by_name.items():
        for key, value in old_component.items():
            if key == "bom-ref":
                continue  # random UUID per run
            assert new_by_name[name][key] == value, f"{name}.{key} regressed"
        added = set(new_by_name[name]) - set(old_component)
        assert added <= {"modelCard"}, f"{name} grew unexpected keys: {added}"


def test_remote_sentinel_hashes_are_never_emitted_as_digests(tmp_path, monkeypatch):
    """Regression: `remote_unhashed` was written into a SHA-256 hash field.

    Range-request scans never read the whole file, so the scanner stores a
    sentinel where a digest would go. The old guard only filtered
    `hash_error`, so every hf:// SBOM carried `"content": "remote_unhashed"`
    and failed CycloneDX validation — at 1.6 as well as 1.7. Caught by
    validating a real `hf://` scan rather than a fixture.
    """
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    import aisbom.scanner as scanner_module

    def fake_scan(self):
        return {
            "artifacts": [
                {
                    "name": "remote.safetensors",
                    "framework": "SafeTensors",
                    "risk_level": "LOW",
                    "legal_status": "OK",
                    "hash": "remote_unhashed",
                    "details": {},
                },
                {
                    "name": "unreadable.pt",
                    "framework": "PyTorch",
                    "risk_level": "LOW",
                    "legal_status": "OK",
                    "hash": "hash_error",
                    "details": {},
                },
                {
                    "name": "local.gguf",
                    "framework": "GGUF",
                    "risk_level": "LOW",
                    "legal_status": "OK",
                    "hash": "a" * 64,
                    "details": {},
                },
            ],
            "dependencies": [],
            "errors": [],
            "hf_model_card": None,
        }

    monkeypatch.setattr(scanner_module.DeepScanner, "scan", fake_scan)
    output_path = tmp_path / "sentinels.json"
    runner.invoke(app, ["scan", str(tmp_path), "--output", str(output_path)])

    raw = output_path.read_text()
    assert "remote_unhashed" not in raw
    assert "hash_error" not in raw

    by_name = {c["name"]: c for c in json.loads(raw)["components"]}
    assert "hashes" not in by_name["remote.safetensors"], "sentinel must omit the field"
    assert "hashes" not in by_name["unreadable.pt"]
    assert by_name["local.gguf"]["hashes"] == [{"alg": "SHA-256", "content": "a" * 64}]

    errors = JsonStrictValidator(SchemaVersion.V1_7).validate_str(raw)
    assert errors is None, f"sentinel hashes broke 1.7 validation: {errors}"


def test_default_scan_output_validates_against_the_1_7_schema(tmp_path):
    """AC #1, end to end: what the CLI actually writes to disk is valid 1.7."""
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    output_path = tmp_path / "validated.json"
    _write_malicious_pt(tmp_path / "mock_malware.pt")
    create_mock_restricted_file(tmp_path)
    create_mock_gguf(tmp_path)
    runner.invoke(app, ["scan", str(tmp_path), "--output", str(output_path)])

    errors = JsonStrictValidator(SchemaVersion.V1_7).validate_str(output_path.read_text())
    assert errors is None, f"CLI output failed 1.7 validation: {errors}"


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
