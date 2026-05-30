"""Tests for action/platform_upload.py.

The helper lives outside the `aisbom` package (it ships only inside the Action
Docker image), so we import it via the file path rather than as a package.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

# Load the sidecar module by path; the `action/` directory is not on sys.path
# in normal CLI usage and isn't part of the `aisbom` package.
_MODULE_PATH = Path(__file__).resolve().parent.parent / "action" / "platform_upload.py"
_SPEC = importlib.util.spec_from_file_location("platform_upload", _MODULE_PATH)
platform_upload = importlib.util.module_from_spec(_SPEC)
sys.modules["platform_upload"] = platform_upload
assert _SPEC.loader is not None
_SPEC.loader.exec_module(platform_upload)


# ---------------------------------------------------------------------------
# normalize_platform_url
# ---------------------------------------------------------------------------

def test_normalize_platform_url_blank_uses_default():
    assert platform_upload.normalize_platform_url("") == "https://app.aisbom.io"


def test_normalize_platform_url_none_uses_default():
    assert platform_upload.normalize_platform_url(None) == "https://app.aisbom.io"


def test_normalize_platform_url_strips_trailing_slash():
    assert platform_upload.normalize_platform_url("https://app.aisbom.io/") == "https://app.aisbom.io"


def test_normalize_platform_url_leaves_localhost_unchanged():
    assert platform_upload.normalize_platform_url("http://localhost:8787") == "http://localhost:8787"


def test_normalize_platform_url_strips_whitespace():
    assert platform_upload.normalize_platform_url("  https://app.aisbom.io  ") == "https://app.aisbom.io"


# ---------------------------------------------------------------------------
# compute_run_id
# ---------------------------------------------------------------------------

def test_compute_run_id_combines_run_and_attempt():
    env = {"GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "2"}
    assert platform_upload.compute_run_id(env) == "42-2"


def test_compute_run_id_missing_attempt_defaults_to_1():
    env = {"GITHUB_RUN_ID": "42"}
    assert platform_upload.compute_run_id(env) == "42-1"


def test_compute_run_id_missing_run_id_returns_unknown():
    env = {}
    assert platform_upload.compute_run_id(env) == "unknown-1"


# ---------------------------------------------------------------------------
# summarize_response
# ---------------------------------------------------------------------------

def test_summarize_response_truncates_long_body():
    body = "x" * 1000
    summary = platform_upload.summarize_response(200, body)
    assert "200" in summary
    assert len(summary) < 600


def test_summarize_response_includes_status_and_body():
    summary = platform_upload.summarize_response(401, "unauthorized")
    assert "401" in summary
    assert "unauthorized" in summary


# ---------------------------------------------------------------------------
# upload — happy and sad paths
# ---------------------------------------------------------------------------

@pytest.fixture
def sbom_file(tmp_path: Path) -> Path:
    p = tmp_path / "sbom.json"
    p.write_text(json.dumps({"components": []}))
    return p


def _mock_response(status: int, body: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    return resp


def test_upload_empty_token_skips_post(sbom_file: Path):
    with patch("requests.post") as mock_post:
        rc = platform_upload.upload(
            sbom_path=str(sbom_file),
            token="",
            platform_url="",
            trigger="push",
            fail_on_error=False,
            env={},
        )
    assert rc == 0
    mock_post.assert_not_called()


def test_upload_success_returns_zero(sbom_file: Path):
    with patch("requests.post", return_value=_mock_response(200, "ok")) as mock_post:
        rc = platform_upload.upload(
            sbom_path=str(sbom_file),
            token="tok",
            platform_url="https://app.aisbom.io",
            trigger="push",
            fail_on_error=False,
            env={"GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"},
        )
    assert rc == 0
    mock_post.assert_called_once()


def test_upload_401_best_effort_returns_zero(sbom_file: Path):
    with patch("requests.post", return_value=_mock_response(401, "nope")):
        rc = platform_upload.upload(
            sbom_path=str(sbom_file),
            token="tok",
            platform_url="https://app.aisbom.io",
            trigger="push",
            fail_on_error=False,
            env={},
        )
    assert rc == 0


def test_upload_401_with_fail_on_error_returns_three(sbom_file: Path):
    with patch("requests.post", return_value=_mock_response(401, "nope")):
        rc = platform_upload.upload(
            sbom_path=str(sbom_file),
            token="tok",
            platform_url="https://app.aisbom.io",
            trigger="push",
            fail_on_error=True,
            env={},
        )
    assert rc == 3


def test_upload_network_exception_best_effort_returns_zero(sbom_file: Path):
    with patch("requests.post", side_effect=requests.ConnectionError("boom")):
        rc = platform_upload.upload(
            sbom_path=str(sbom_file),
            token="tok",
            platform_url="https://app.aisbom.io",
            trigger="push",
            fail_on_error=False,
            env={},
        )
    assert rc == 0


def test_upload_network_exception_with_fail_on_error_returns_three(sbom_file: Path):
    with patch("requests.post", side_effect=requests.ConnectionError("boom")):
        rc = platform_upload.upload(
            sbom_path=str(sbom_file),
            token="tok",
            platform_url="https://app.aisbom.io",
            trigger="push",
            fail_on_error=True,
            env={},
        )
    assert rc == 3


def test_upload_sets_required_headers(sbom_file: Path):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["headers"] = kwargs["headers"]
        captured["data"] = kwargs.get("data")
        return _mock_response(200, "ok")

    with patch("requests.post", side_effect=fake_post):
        platform_upload.upload(
            sbom_path=str(sbom_file),
            token="secret-token",
            platform_url="https://app.aisbom.io",
            trigger="pull_request",
            fail_on_error=False,
            env={"GITHUB_RUN_ID": "999", "GITHUB_RUN_ATTEMPT": "3"},
        )

    headers = captured["headers"]
    assert headers["Authorization"] == "Bearer secret-token"
    assert headers["Content-Type"] == "application/json"
    assert headers["X-Aisbom-Trigger"] == "pull_request"
    assert headers["X-Aisbom-Run-Id"] == "999-3"
    assert captured["url"].endswith("/v1/scan-result")


def test_upload_emits_log_group_with_disable_hint(sbom_file: Path, capsys):
    with patch("requests.post", return_value=_mock_response(200, "ok")):
        platform_upload.upload(
            sbom_path=str(sbom_file),
            token="tok",
            platform_url="https://app.aisbom.io",
            trigger="push",
            fail_on_error=False,
            env={},
        )
    out = capsys.readouterr().out
    assert "::group::" in out
    assert "::endgroup::" in out
    assert "https://app.aisbom.io" in out
    assert "AISBOM_TOKEN" in out  # the "to disable" hint


def test_upload_blank_platform_url_resolves_to_default(sbom_file: Path):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        return _mock_response(200, "ok")

    with patch("requests.post", side_effect=fake_post):
        platform_upload.upload(
            sbom_path=str(sbom_file),
            token="tok",
            platform_url="",
            trigger="push",
            fail_on_error=False,
            env={},
        )
    assert captured["url"] == "https://app.aisbom.io/v1/scan-result"


# ---------------------------------------------------------------------------
# main() — argparse wiring
# ---------------------------------------------------------------------------

def test_main_invokes_upload_with_parsed_args(sbom_file: Path):
    with patch.object(platform_upload, "upload", return_value=0) as mock_upload:
        rc = platform_upload.main([
            "--sbom", str(sbom_file),
            "--token", "tok",
            "--platform-url", "https://app.aisbom.io",
            "--trigger", "pull_request",
        ])
    assert rc == 0
    mock_upload.assert_called_once()
    kwargs = mock_upload.call_args.kwargs
    assert kwargs["token"] == "tok"
    assert kwargs["platform_url"] == "https://app.aisbom.io"
    assert kwargs["trigger"] == "pull_request"
    assert kwargs["fail_on_error"] is False


def test_main_passes_fail_on_error_flag(sbom_file: Path):
    with patch.object(platform_upload, "upload", return_value=3) as mock_upload:
        rc = platform_upload.main([
            "--sbom", str(sbom_file),
            "--token", "tok",
            "--platform-url", "",
            "--trigger", "push",
            "--fail-on-error",
        ])
    assert rc == 3
    assert mock_upload.call_args.kwargs["fail_on_error"] is True


# ---------------------------------------------------------------------------
# parse_args — argparse strictness around dash-leading values
#
# Regression for 2026-05-30: roughly 1.5% of platform-issued base64url tokens
# begin with `-`. The entrypoint must use `--key=value` form so argparse
# doesn't misread the token as another option. These tests lock the
# contract from BOTH directions: `=` form must accept dash-leading values,
# space form must STILL fail for them (so a future regression in the
# entrypoint surfaces immediately rather than going silent).
# ---------------------------------------------------------------------------

def test_parse_args_accepts_dash_leading_token_with_equals_form():
    ns = platform_upload.parse_args([
        "--sbom=any.json",
        "--token=-DashLeading_xyz",
        "--platform-url=",
        "--trigger=push",
    ])
    assert ns.token == "-DashLeading_xyz"
    assert ns.sbom == "any.json"


def test_parse_args_accepts_double_dash_token_with_equals_form():
    ns = platform_upload.parse_args(["--sbom=x", "--token=--weird"])
    assert ns.token == "--weird"


def test_parse_args_rejects_dash_leading_token_with_space_form():
    # This is the actual production bug. We assert the failure mode so that
    # if the entrypoint ever drifts back to space-separated args, this test
    # fails loudly at PR time instead of silently in customer CI.
    with pytest.raises(SystemExit):
        platform_upload.parse_args(["--sbom", "x", "--token", "-x"])


def test_parse_args_empty_token_with_equals_form_is_allowed():
    ns = platform_upload.parse_args(["--sbom=x", "--token="])
    assert ns.token == ""
