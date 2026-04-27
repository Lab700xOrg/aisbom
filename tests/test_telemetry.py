"""Unit tests for aisbom.telemetry — the CLI side of Phase 1.2 telemetry."""

from __future__ import annotations

import json
import threading
from unittest.mock import MagicMock, patch

import pytest
import requests as _requests

from aisbom import telemetry


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(autouse=True)
def isolate_env(monkeypatch):
    """
    Ensure each test starts with a clean telemetry env. Tests that need
    specific env vars set will do so via monkeypatch.setenv inside the test.
    """
    for var in ("AISBOM_NO_TELEMETRY", "AISBOM_TELEMETRY_V2", "GITHUB_ACTIONS", "CI"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """Point Path.home() at a tmp dir for tests that need a writable home."""
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def telemetry_enabled(monkeypatch, fake_home):
    """Convenience: opt-in to v2 with a writable home."""
    monkeypatch.setenv("AISBOM_TELEMETRY_V2", "1")
    return fake_home


# ============================================================================
# is_ci()
# ============================================================================

class TestIsCI:
    def test_returns_true_when_github_actions_set(self, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        assert telemetry.is_ci() is True

    def test_returns_true_when_ci_set(self, monkeypatch):
        monkeypatch.setenv("CI", "true")
        assert telemetry.is_ci() is True

    def test_returns_true_when_both_set(self, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("CI", "true")
        assert telemetry.is_ci() is True

    def test_returns_false_when_neither_set(self):
        assert telemetry.is_ci() is False

    def test_returns_true_for_any_truthy_value(self, monkeypatch):
        # GitHub Actions sets these to "true" but other CIs may use "1" etc.
        monkeypatch.setenv("CI", "1")
        assert telemetry.is_ci() is True


# ============================================================================
# get_config_dir()
# ============================================================================

class TestGetConfigDir:
    def test_creates_aisbom_directory(self, fake_home):
        result = telemetry.get_config_dir()
        assert result == fake_home / ".aisbom"
        assert (fake_home / ".aisbom").is_dir()

    def test_returns_path_when_already_exists(self, fake_home):
        (fake_home / ".aisbom").mkdir()
        result = telemetry.get_config_dir()
        assert result == fake_home / ".aisbom"

    def test_cleans_up_probe_file(self, fake_home):
        telemetry.get_config_dir()
        assert not (fake_home / ".aisbom" / ".write_probe").exists()

    def test_idempotent(self, fake_home):
        a = telemetry.get_config_dir()
        b = telemetry.get_config_dir()
        assert a == b

    def test_returns_none_when_mkdir_fails(self, fake_home):
        with patch("pathlib.Path.mkdir", side_effect=OSError("readonly fs")):
            assert telemetry.get_config_dir() is None

    def test_returns_none_when_mkdir_permission_denied(self, fake_home):
        with patch("pathlib.Path.mkdir", side_effect=PermissionError("no perms")):
            assert telemetry.get_config_dir() is None

    def test_returns_none_when_probe_write_fails(self, fake_home):
        with patch("pathlib.Path.write_text", side_effect=PermissionError("ro")):
            assert telemetry.get_config_dir() is None


# ============================================================================
# save_config()
# ============================================================================

class TestSaveConfig:
    def test_writes_json(self, fake_home):
        telemetry.save_config({"k": "v"})
        config_path = fake_home / ".aisbom" / "config.json"
        assert config_path.exists()
        assert json.loads(config_path.read_text()) == {"k": "v"}

    def test_no_orphaned_tmp_file_on_success(self, fake_home):
        telemetry.save_config({"k": "v"})
        assert not (fake_home / ".aisbom" / "config.json.tmp").exists()

    def test_silent_when_config_dir_unavailable(self):
        with patch.object(telemetry, "get_config_dir", return_value=None):
            telemetry.save_config({"k": "v"})  # should not raise

    def test_round_trip(self, fake_home):
        original = {
            "user_id": "abc123",
            "installed_at": "2026-04-25T18:00:00Z",
            "schema_version": 1,
        }
        telemetry.save_config(original)
        loaded = json.loads((fake_home / ".aisbom" / "config.json").read_text())
        assert loaded == original

    def test_overwrites_existing(self, fake_home):
        telemetry.save_config({"v": 1})
        telemetry.save_config({"v": 2})
        loaded = json.loads((fake_home / ".aisbom" / "config.json").read_text())
        assert loaded == {"v": 2}

    def test_silent_on_write_error(self, fake_home):
        with patch("pathlib.Path.write_text", side_effect=OSError("disk full")):
            telemetry.save_config({"k": "v"})  # must not raise


# ============================================================================
# get_or_init_config()
# ============================================================================

class TestGetOrInitConfig:
    def test_first_call_creates_config(self, telemetry_enabled):
        cfg = telemetry.get_or_init_config()
        assert cfg["schema_version"] == telemetry.CONFIG_SCHEMA_VERSION
        assert "user_id" in cfg
        assert "installed_at" in cfg

    def test_user_id_is_16_hex_chars(self, telemetry_enabled):
        cfg = telemetry.get_or_init_config()
        assert len(cfg["user_id"]) == 16
        int(cfg["user_id"], 16)  # must parse as hex

    def test_installed_at_is_iso8601_z(self, telemetry_enabled):
        cfg = telemetry.get_or_init_config()
        # YYYY-MM-DDTHH:MM:SSZ — exactly 20 chars
        assert cfg["installed_at"].endswith("Z")
        assert len(cfg["installed_at"]) == 20

    def test_subsequent_calls_return_same_user_id(self, telemetry_enabled):
        first = telemetry.get_or_init_config()
        second = telemetry.get_or_init_config()
        assert first["user_id"] == second["user_id"]
        assert first["installed_at"] == second["installed_at"]

    def test_config_persisted_to_disk(self, telemetry_enabled):
        telemetry.get_or_init_config()
        config_file = telemetry_enabled / ".aisbom" / "config.json"
        assert config_file.exists()
        on_disk = json.loads(config_file.read_text())
        assert "user_id" in on_disk

    def test_returns_empty_dict_when_config_dir_none(self, monkeypatch):
        monkeypatch.setenv("AISBOM_TELEMETRY_V2", "1")
        with patch.object(telemetry, "get_config_dir", return_value=None):
            assert telemetry.get_or_init_config() == {}

    def test_recovers_from_corrupt_config(self, telemetry_enabled):
        (telemetry_enabled / ".aisbom").mkdir()
        (telemetry_enabled / ".aisbom" / "config.json").write_text("{not valid json")
        cfg = telemetry.get_or_init_config()
        assert "user_id" in cfg

    def test_no_op_when_no_telemetry_set(self, fake_home, monkeypatch):
        monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
        monkeypatch.setenv("AISBOM_TELEMETRY_V2", "1")
        cfg = telemetry.get_or_init_config()
        assert cfg == {}
        # Critically, no file written when user has opted out
        assert not (fake_home / ".aisbom" / "config.json").exists()

    def test_no_op_when_v2_not_enabled(self, fake_home):
        # No env vars set: telemetry_enabled fixture not used here
        cfg = telemetry.get_or_init_config()
        assert cfg == {}
        assert not (fake_home / ".aisbom" / "config.json").exists()


# ============================================================================
# _build_user_agent()
# ============================================================================

class TestBuildUserAgent:
    def test_format(self):
        ua = telemetry._build_user_agent()
        assert ua.startswith("aisbom-cli/")
        assert "python " in ua
        assert "ci=" in ua
        # surrounding parens for the system block
        assert "(" in ua and ")" in ua

    def test_version_unknown_when_package_missing(self):
        with patch(
            "importlib.metadata.version",
            side_effect=__import__("importlib.metadata").metadata.PackageNotFoundError("aisbom-cli"),
        ):
            ua = telemetry._build_user_agent()
            assert "aisbom-cli/unknown" in ua

    def test_includes_ci_true_when_ci_set(self, monkeypatch):
        monkeypatch.setenv("CI", "true")
        ua = telemetry._build_user_agent()
        assert "ci=true" in ua

    def test_includes_ci_false_when_unset(self):
        ua = telemetry._build_user_agent()
        assert "ci=false" in ua


# ============================================================================
# post_event()
# ============================================================================

class TestPostEventGates:
    def test_no_op_when_no_telemetry_set(self, monkeypatch):
        monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
        monkeypatch.setenv("AISBOM_TELEMETRY_V2", "1")
        with patch("aisbom.telemetry.requests.post") as mock_post:
            result = telemetry.post_event("cli_scan", {})
        assert result is None
        mock_post.assert_not_called()

    def test_no_op_when_v2_not_enabled(self):
        with patch("aisbom.telemetry.requests.post") as mock_post:
            result = telemetry.post_event("cli_scan", {})
        assert result is None
        mock_post.assert_not_called()

    def test_no_op_when_v2_set_to_other_value(self, monkeypatch):
        monkeypatch.setenv("AISBOM_TELEMETRY_V2", "true")  # not "1" exactly
        with patch("aisbom.telemetry.requests.post") as mock_post:
            result = telemetry.post_event("cli_scan", {})
        assert result is None
        mock_post.assert_not_called()

    def test_no_telemetry_wins_over_v2(self, monkeypatch):
        # Both set: NO_TELEMETRY should still win
        monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
        monkeypatch.setenv("AISBOM_TELEMETRY_V2", "1")
        with patch("aisbom.telemetry.requests.post") as mock_post:
            result = telemetry.post_event("cli_scan", {})
        assert result is None
        mock_post.assert_not_called()


class TestPostEventThreading:
    def test_returns_thread_when_enabled(self, telemetry_enabled):
        with patch("aisbom.telemetry.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=204)
            t = telemetry.post_event(
                "cli_scan", {"target_type": "hf"}, scan_id="abc-123"
            )
        assert isinstance(t, threading.Thread)
        t.join(timeout=2.0)
        assert mock_post.called

    def test_thread_is_non_daemon(self, telemetry_enabled):
        with patch("aisbom.telemetry.requests.post"):
            t = telemetry.post_event("cli_scan", {})
        assert t.daemon is False
        t.join(timeout=2.0)


class TestPostEventPayload:
    def test_calls_correct_endpoint(self, telemetry_enabled):
        with patch("aisbom.telemetry.requests.post") as mock_post:
            t = telemetry.post_event("cli_scan", {"k": "v"}, scan_id="sid")
            t.join(timeout=2.0)
        assert mock_post.call_args.args[0] == telemetry.TELEMETRY_ENDPOINT

    def test_sends_event_and_params_in_body(self, telemetry_enabled):
        with patch("aisbom.telemetry.requests.post") as mock_post:
            t = telemetry.post_event(
                "cli_diff", {"has_drift": "true"}, scan_id="xyz"
            )
            t.join(timeout=2.0)
        body = mock_post.call_args.kwargs["json"]
        assert body["event"] == "cli_diff"
        assert body["params"]["has_drift"] == "true"
        assert body["scan_id"] == "xyz"

    def test_includes_user_id_in_params(self, telemetry_enabled):
        with patch("aisbom.telemetry.requests.post") as mock_post:
            t = telemetry.post_event("cli_scan", {"target_type": "hf"})
            t.join(timeout=2.0)
        body = mock_post.call_args.kwargs["json"]
        assert "user_id" in body["params"]
        assert len(body["params"]["user_id"]) == 16

    def test_user_id_stable_across_calls(self, telemetry_enabled):
        with patch("aisbom.telemetry.requests.post") as mock_post:
            t1 = telemetry.post_event("cli_scan", {})
            t1.join(timeout=2.0)
            t2 = telemetry.post_event("cli_scan", {})
            t2.join(timeout=2.0)
        body1 = mock_post.call_args_list[0].kwargs["json"]
        body2 = mock_post.call_args_list[1].kwargs["json"]
        assert body1["params"]["user_id"] == body2["params"]["user_id"]

    def test_omits_scan_id_when_none(self, telemetry_enabled):
        with patch("aisbom.telemetry.requests.post") as mock_post:
            t = telemetry.post_event("cli_install_first_seen", {})
            t.join(timeout=2.0)
        body = mock_post.call_args.kwargs["json"]
        assert "scan_id" not in body

    def test_user_agent_format_matches_version_check(self, telemetry_enabled):
        with patch("aisbom.telemetry.requests.post") as mock_post:
            t = telemetry.post_event("cli_scan", {})
            t.join(timeout=2.0)
        ua = mock_post.call_args.kwargs["headers"]["User-Agent"]
        # exact contract with the Worker UA parser at index.js:60
        assert ua.startswith("aisbom-cli/")
        assert "python " in ua
        assert "ci=" in ua

    def test_timeout_set(self, telemetry_enabled):
        with patch("aisbom.telemetry.requests.post") as mock_post:
            t = telemetry.post_event("cli_scan", {})
            t.join(timeout=2.0)
        assert mock_post.call_args.kwargs["timeout"] == telemetry.POST_TIMEOUT_SEC

    def test_handles_none_params(self, telemetry_enabled):
        # post_event must accept params=None without crashing
        with patch("aisbom.telemetry.requests.post") as mock_post:
            t = telemetry.post_event("cli_scan", None)
            t.join(timeout=2.0)
        body = mock_post.call_args.kwargs["json"]
        assert body["event"] == "cli_scan"
        assert isinstance(body["params"], dict)


class TestPostEventResilience:
    def test_silent_on_network_error(self, telemetry_enabled):
        with patch(
            "aisbom.telemetry.requests.post",
            side_effect=Exception("network down"),
        ):
            t = telemetry.post_event("cli_scan", {})
            t.join(timeout=2.0)
            # If _do_post let the exception escape the thread, it would have
            # been raised during join() — pytest would fail. Reaching this
            # line means resilience contract is honored.

    def test_silent_on_timeout(self, telemetry_enabled):
        with patch(
            "aisbom.telemetry.requests.post",
            side_effect=_requests.Timeout("timed out"),
        ):
            t = telemetry.post_event("cli_scan", {})
            t.join(timeout=2.0)

    def test_silent_on_connection_error(self, telemetry_enabled):
        with patch(
            "aisbom.telemetry.requests.post",
            side_effect=_requests.ConnectionError("refused"),
        ):
            t = telemetry.post_event("cli_scan", {})
            t.join(timeout=2.0)
