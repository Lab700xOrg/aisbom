import json
import zipfile
import struct
import importlib
from pathlib import Path
from typer.testing import CliRunner

from aisbom.cli import app
from aisbom.mock_generator import (
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


# ---------------------------------------------------------------------------
# Phase 4.1 — Default-command onboarding panel
# ---------------------------------------------------------------------------

def test_no_args_shows_onboarding_panel():
    """`aisbom` with no subcommand must show the quickstart panel, not Typer's help dump."""
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "Try it now" in result.stdout
    # The exact example command — keep in sync with PHASE_4_1_DESIGN.md.
    assert "aisbom scan hf://google-bert/bert-base-uncased" in result.stdout
    # Pointer to the full reference must be present so power users aren't lost.
    assert "aisbom --help" in result.stdout


def test_help_flag_still_shows_typer_help():
    """`aisbom --help` must continue to show Typer's full command reference."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.stdout
    # Subcommand list survives — confirms we haven't shadowed Typer's help.
    assert "Commands" in result.stdout


def test_subcommand_invocation_unaffected_by_callback():
    """A subcommand call must skip the panel and run the subcommand normally."""
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    # The onboarding-panel marker must NOT appear; `info` has its own panel.
    assert "Try it now" not in result.stdout


# ---------------------------------------------------------------------------
# Phase 4 help-pass (queued for 0.10.0): --version, env-var doc, info telemetry
# ---------------------------------------------------------------------------

def test_version_flag_prints_version_and_exits():
    """`aisbom --version` (and `-V`) must print the version and exit 0."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "aisbom" in result.stdout
    # Onboarding panel must NOT show — --version wins over the no-args path.
    assert "Try it now" not in result.stdout

    short_result = runner.invoke(app, ["-V"])
    assert short_result.exit_code == 0
    assert "aisbom" in short_result.stdout


def test_help_mentions_telemetry_env_var():
    """`aisbom --help` must document the AISBOM_NO_TELEMETRY opt-out lever."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "AISBOM_NO_TELEMETRY" in result.stdout


def test_scan_help_mentions_share_visibility_and_expiry():
    """`aisbom scan --help` must surface the two key facts about --share:
    public visibility + 30-day expiry. CI users adding --share --share-yes
    to a pipeline never see the interactive prompt, so help is their only
    chance to learn these properties."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    # --share help text must call out public + expiry
    assert "public" in result.stdout.lower() or "publicly" in result.stdout.lower()
    assert "30 days" in result.stdout or "30-day" in result.stdout
    # --share-yes help must call out CI/CD intent
    assert "CI/CD" in result.stdout or "CI / CD" in result.stdout


def test_info_shows_telemetry_state(monkeypatch):
    """`aisbom info` must surface telemetry state so users have one canonical
    place to confirm whether events are firing on their machine."""
    # Default state — telemetry enabled.
    monkeypatch.delenv("AISBOM_NO_TELEMETRY", raising=False)
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "Telemetry:" in result.stdout
    assert "enabled" in result.stdout.lower() or "AISBOM_NO_TELEMETRY" in result.stdout

    # Opted-out state.
    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "opted out" in result.stdout.lower()


# ---------------------------------------------------------------------------
# Phase 4.3 — Trackable footer on every successful scan
# ---------------------------------------------------------------------------

def test_attribution_ref_appends_question_mark_for_clean_url(monkeypatch):
    """A URL with no existing query string should get `?ref=cli` appended."""
    monkeypatch.delenv("AISBOM_NO_TELEMETRY", raising=False)
    from aisbom.cli import _attribution_ref
    assert _attribution_ref("https://aisbom.io/advisories") == "https://aisbom.io/advisories?ref=cli"


def test_attribution_ref_appends_ampersand_for_query_url(monkeypatch):
    """A URL with an existing query string should get `&ref=cli` appended."""
    monkeypatch.delenv("AISBOM_NO_TELEMETRY", raising=False)
    from aisbom.cli import _attribution_ref
    assert _attribution_ref("https://aisbom.io/viewer?h=abc") == "https://aisbom.io/viewer?h=abc&ref=cli"


def test_attribution_ref_strips_when_telemetry_opted_out(monkeypatch):
    """Opt-out users get the URL with NO attribution tag — still useful, untracked."""
    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    from aisbom.cli import _attribution_ref
    assert _attribution_ref("https://aisbom.io/viewer?h=abc") == "https://aisbom.io/viewer?h=abc"
    assert _attribution_ref("https://aisbom.io/advisories") == "https://aisbom.io/advisories"


def test_scan_footer_shows_advisories_link_with_ref(tmp_path, monkeypatch):
    """Every successful scan ends with the Next steps panel pointing at advisories."""
    monkeypatch.delenv("AISBOM_NO_TELEMETRY", raising=False)
    out = tmp_path / "sbom.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(out)])
    assert result.exit_code == 0, result.stdout
    assert "Next steps" in result.stdout
    assert "aisbom.io/advisories" in result.stdout
    # Attribution tag must be present in the default (telemetry-on) state.
    assert "ref=cli" in result.stdout


def test_scan_footer_strips_ref_when_telemetry_opted_out(tmp_path, monkeypatch):
    """Opted-out users still see the panel, but URLs lose the `ref=cli` tag."""
    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    out = tmp_path / "sbom.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(out)])
    assert result.exit_code == 0, result.stdout
    assert "aisbom.io/advisories" in result.stdout
    # Critical: no attribution tag for opt-out users.
    assert "ref=cli" not in result.stdout


def test_scan_footer_nudges_share_when_flag_not_used(tmp_path, monkeypatch):
    """Without --share, the footer should hint that --share unlocks a hosted link."""
    monkeypatch.delenv("AISBOM_NO_TELEMETRY", raising=False)
    out = tmp_path / "sbom.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(out)])
    assert result.exit_code == 0, result.stdout
    # The hint specifically mentions the --share flag.
    assert "--share" in result.stdout


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

def test_cli_scan_share_prompts_and_aborts_if_no(tmp_path, monkeypatch):
    from unittest.mock import MagicMock
    import requests
    
    _write_malicious_pt(tmp_path / "mock_malware.pt")
    output_path = tmp_path / "sbom.json"
    
    mock_post = MagicMock()
    monkeypatch.setattr(requests, "post", mock_post)
    
    # We pass 'N' to the prompt
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(output_path), "--share", "--no-fail-on-risk"], input="N\n")
    
    assert "Upload this SBOM to aisbom.io" in result.stdout
    assert "Share cancelled" in result.stdout
    mock_post.assert_not_called()

def test_cli_scan_share_yes_uploads_and_prints_url(tmp_path, monkeypatch):
    from unittest.mock import MagicMock
    import requests
    
    _write_malicious_pt(tmp_path / "mock_malware.pt")
    output_path = tmp_path / "sbom.json"
    
    class MockResponse:
        def raise_for_status(self): pass
        def json(self): return {"url": "https://aisbom.io/viewer?h=test_hash123"}
        
    mock_post = MagicMock(return_value=MockResponse())
    monkeypatch.setattr(requests, "post", mock_post)
    
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(output_path), "--share", "--share-yes", "--no-fail-on-risk"])
    
    # Should skip prompt
    assert "Upload this SBOM to aisbom.io" not in result.stdout
    assert "https://aisbom.io/viewer?h=test_hash123" in result.stdout
    
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == "https://aisbom.io/api/sbom-share"
    assert "application/json" in kwargs["headers"]["Content-Type"]
    assert "data" in kwargs


# ---------------------------------------------------------------------------
# Slice #56 — cli_error telemetry enrichment (http_status / token_present /
# target_type). The diagnostic must make auth vs firewall vs typo
# distinguishable in GA4 without ever leaking a URL, repo id, token, or body.
# ---------------------------------------------------------------------------

import pytest
import requests
from aisbom.cli import _classify_http_status, _token_present


def _http_error(status: int) -> requests.exceptions.HTTPError:
    resp = requests.Response()
    resp.status_code = status
    return requests.exceptions.HTTPError(response=resp)


class _RaisingScanner:
    """Stub DeepScanner whose scan() raises a preset exception."""

    _exc: BaseException

    def __init__(self, *args, **kwargs):
        pass

    def scan(self):
        raise type(self)._exc


def _scanner_raising(exc: BaseException):
    return type("_RS", (_RaisingScanner,), {"_exc": exc})


def _capture_cli_error(monkeypatch):
    """Patch telemetry.post_event to record cli_error payloads; return the list."""
    captured: list[dict] = []

    def _record(event, params=None, scan_id=None):
        if event == "cli_error":
            captured.append(dict(params or {}))
        return None

    monkeypatch.setattr("aisbom.telemetry.post_event", _record)
    return captured


def test_classify_http_status_buckets_http_error_by_status():
    assert _classify_http_status(_http_error(401)) == "401"
    assert _classify_http_status(_http_error(403)) == "403"
    assert _classify_http_status(_http_error(404)) == "404"


def test_classify_http_status_buckets_timeout_and_connection_error():
    assert _classify_http_status(requests.exceptions.Timeout()) == "timeout"
    assert _classify_http_status(requests.exceptions.ConnectionError()) == "connection_error"
    # ConnectTimeout is a subclass of both — must bucket as timeout, not connection_error.
    assert _classify_http_status(requests.exceptions.ConnectTimeout()) == "timeout"


def test_classify_http_status_falls_back_to_other():
    assert _classify_http_status(ValueError("boom")) == "other"
    # HTTPError with no usable response also degrades to the generic bucket.
    assert _classify_http_status(requests.exceptions.HTTPError()) == "other"


def test_token_present_reflects_env(monkeypatch):
    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.delenv("HUGGING_FACE_HUB_TOKEN", raising=False)
    assert _token_present() == "false"
    monkeypatch.setenv("HF_TOKEN", "x")
    assert _token_present() == "true"
    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.setenv("HUGGING_FACE_HUB_TOKEN", "y")
    assert _token_present() == "true"


def test_scan_fetch_failure_emits_enriched_cli_error(tmp_path, monkeypatch):
    captured = _capture_cli_error(monkeypatch)
    monkeypatch.setattr(cli_module, "DeepScanner", _scanner_raising(_http_error(401)))
    monkeypatch.setenv("HF_TOKEN", "secret-token-value")

    result = runner.invoke(app, ["scan", "hf://acme/private-model"])

    assert result.exit_code != 0
    assert len(captured) == 1
    payload = captured[0]
    assert payload["command"] == "scan"
    assert payload["error_type"] == "HTTPError"
    assert payload["http_status"] == "401"
    assert payload["token_present"] == "true"
    assert payload["target_type"] == "huggingface"


def test_scan_fetch_failure_buckets_timeout(monkeypatch):
    captured = _capture_cli_error(monkeypatch)
    monkeypatch.setattr(cli_module, "DeepScanner", _scanner_raising(requests.exceptions.Timeout()))

    runner.invoke(app, ["scan", "https://example.com/model.safetensors"])

    assert captured and captured[0]["http_status"] == "timeout"
    assert captured[0]["target_type"] == "https"


def test_scan_fetch_failure_buckets_connection_error(monkeypatch):
    captured = _capture_cli_error(monkeypatch)
    monkeypatch.setattr(
        cli_module, "DeepScanner", _scanner_raising(requests.exceptions.ConnectionError())
    )

    runner.invoke(app, ["scan", "hf://acme/model"])

    assert captured and captured[0]["http_status"] == "connection_error"


def test_cli_error_payload_leaks_no_token_url_or_body(monkeypatch):
    captured = _capture_cli_error(monkeypatch)
    secret_token = "hf_supersecrettokenvalue"
    monkeypatch.setenv("HF_TOKEN", secret_token)
    body = "<html>internal error trace at 10.0.0.1</html>"
    err = _http_error(403)
    err.response._content = body.encode()  # attach a body the bucket must ignore
    monkeypatch.setattr(cli_module, "DeepScanner", _scanner_raising(err))

    runner.invoke(app, ["scan", "hf://secret-org/secret-repo"])

    assert captured
    joined = " ".join(str(v) for v in captured[0].values())
    # No token value, repo id, URL, hostname, or response body may appear.
    for leak in (secret_token, "secret-org", "secret-repo", "hf://", body, "10.0.0.1"):
        assert leak not in joined
    # Only the agreed-upon keys are present.
    assert set(captured[0]) == {
        "command",
        "error_type",
        "http_status",
        "token_present",
        "target_type",
        "consecutive_failures",
    }
    # The loop-detector dimension (#99) is a bucketed count, never raw data.
    assert captured[0]["consecutive_failures"] in (
        [str(n) for n in range(1, 10)] + ["10+"]
    )


# ---------------------------------------------------------------------------
# #58 — Reactive status-aware fetch-failure messages (no traceback)
# ---------------------------------------------------------------------------

from aisbom.cli import _format_fetch_error

_HF_FILE_URL = "https://huggingface.co/acme/private-model/resolve/main/model.safetensors"


def test_format_fetch_error_401_without_token(monkeypatch):
    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.delenv("HUGGING_FACE_HUB_TOKEN", raising=False)
    msg = _format_fetch_error(_http_error(401), _HF_FILE_URL)
    assert "private" in msg or "gated" in msg
    assert "HF_TOKEN" in msg
    assert "despite" not in msg  # not the token-present branch
    assert "model.safetensors" in msg


def test_format_fetch_error_403_with_token(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "x")
    msg = _format_fetch_error(_http_error(403), _HF_FILE_URL)
    assert "despite a token" in msg
    assert "read access" in msg
    assert "license on huggingface.co" in msg


def test_format_fetch_error_timeout_names_host():
    msg = _format_fetch_error(requests.exceptions.Timeout(), _HF_FILE_URL)
    assert "huggingface.co" in msg
    assert "egress" in msg or "firewall" in msg


def test_format_fetch_error_connection_error_names_host():
    msg = _format_fetch_error(requests.exceptions.ConnectionError(), _HF_FILE_URL)
    assert "Network error reaching huggingface.co" in msg


def test_format_fetch_error_404():
    msg = _format_fetch_error(_http_error(404), _HF_FILE_URL)
    assert "not found" in msg
    assert "repo id" in msg or "URL" in msg


def test_format_fetch_error_other_status_includes_code():
    msg = _format_fetch_error(_http_error(500), _HF_FILE_URL)
    assert "Failed to fetch" in msg
    assert "HTTP 500" in msg


def test_format_fetch_error_non_http_has_no_code():
    msg = _format_fetch_error(ValueError("boom"), _HF_FILE_URL)
    assert msg == "Failed to fetch model.safetensors."


def test_format_fetch_error_hf_resolve_target_uses_repo_id_and_host():
    # A resolve-time failure passes the raw hf:// target, not a byte URL.
    msg = _format_fetch_error(_http_error(404), "hf://acme/private-model")
    assert "acme/private-model not found" in msg
    timeout_msg = _format_fetch_error(requests.exceptions.Timeout(), "hf://acme/private-model")
    assert "reaching huggingface.co" in timeout_msg


class _FetchFailingScanner:
    """Real-shaped DeepScanner stub: scan() returns a structured fetch error
    (mirroring what the patched scanner now does) instead of raising."""

    _exc: BaseException
    _target: str

    def __init__(self, target, *args, **kwargs):
        self._target_value = target

    def scan(self):
        return {
            "artifacts": [],
            "dependencies": [],
            "errors": [
                {
                    "file": self._target_value,
                    "error": str(type(self)._exc),
                    "fetch_failure": True,
                    "exception": type(self)._exc,
                }
            ],
        }


def _scanner_fetch_failing(exc: BaseException):
    return type("_FFS", (_FetchFailingScanner,), {"_exc": exc})


def test_scan_gated_without_token_prints_clean_message_and_exits_1(monkeypatch):
    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.delenv("HUGGING_FACE_HUB_TOKEN", raising=False)
    captured = _capture_cli_error(monkeypatch)
    monkeypatch.setattr(
        cli_module, "DeepScanner", _scanner_fetch_failing(_http_error(401))
    )

    result = runner.invoke(app, ["scan", "hf://acme/private-model"])

    # Exit 1 via the errors path; the only exception is the controlled Exit.
    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.output
    # Status-aware hint (printed via the stderr console; merged into output here).
    assert "private" in result.output or "gated" in result.output
    assert "HF_TOKEN" in result.output


class _MultiFetchFailingScanner:
    """DeepScanner stub returning several structured fetch failures at once
    (the sharded-model case: model-0000N-of-00012.safetensors × N)."""

    _errors: list[dict]

    def __init__(self, *args, **kwargs):
        pass

    def scan(self):
        return {"artifacts": [], "dependencies": [], "errors": list(type(self)._errors)}


def _scanner_multi_failing(errors: list[dict]):
    return type("_MFS", (_MultiFetchFailingScanner,), {"_errors": errors})


def _shard_error(i: int, exc: BaseException) -> dict:
    url = (
        "https://huggingface.co/acme/model/resolve/main/"
        f"model-{i:05d}-of-00012.safetensors"
    )
    return {"file": url, "error": str(exc), "fetch_failure": True, "exception": exc}


def test_sharded_identical_fetch_failures_print_one_deduped_line(monkeypatch):
    # 12 shards, all 401: one ✖ line naming the first shard + a count,
    # not 12 near-identical lines (verification feedback on #99).
    errors = [_shard_error(i, _http_error(401)) for i in range(1, 13)]
    monkeypatch.setattr(cli_module, "DeepScanner", _scanner_multi_failing(errors))

    result = runner.invoke(app, ["scan", "hf://acme/model"])

    # Rich wraps at the test terminal width; normalize before matching.
    flat = " ".join(result.output.split())
    assert flat.count("Authentication failed") == 1
    assert "model-00001-of-00012.safetensors" in flat
    assert "11 more files with the same error" in flat


def test_mixed_failure_modes_print_one_line_each(monkeypatch):
    # Distinct failure modes must NOT collapse together.
    errors = [
        _shard_error(1, _http_error(401)),
        _shard_error(2, _http_error(401)),
        _shard_error(3, requests.exceptions.Timeout()),
    ]
    monkeypatch.setattr(cli_module, "DeepScanner", _scanner_multi_failing(errors))

    result = runner.invoke(app, ["scan", "hf://acme/model"])

    flat = " ".join(result.output.split())
    assert flat.count("Authentication failed") == 1
    assert "1 more file with the same error" in flat
    assert flat.count("Network error") == 1


def test_sharded_failures_still_emit_one_cli_error_per_file(monkeypatch):
    # Display is deduped; telemetry emission stays per-file (#58 semantics).
    captured = _capture_cli_error(monkeypatch)
    errors = [_shard_error(i, _http_error(401)) for i in range(1, 13)]
    monkeypatch.setattr(cli_module, "DeepScanner", _scanner_multi_failing(errors))

    runner.invoke(app, ["scan", "hf://acme/model"])

    assert len(captured) == 12


def test_scan_fetch_failure_emits_both_cli_error_and_cli_scan(monkeypatch):
    captured_events: list[str] = []

    def _record(event, params=None, scan_id=None):
        captured_events.append(event)
        return None

    monkeypatch.setattr("aisbom.telemetry.post_event", _record)
    monkeypatch.setattr(
        cli_module, "DeepScanner", _scanner_fetch_failing(_http_error(403))
    )

    runner.invoke(app, ["scan", "hf://acme/model"])

    # The slice notes: one failed scan emits both a cli_error and a cli_scan.
    assert "cli_error" in captured_events
    assert "cli_scan" in captured_events

