"""Unit tests for aisbom.loop_state — the consecutive-failure loop detector.

Parent: aisbom-ops #99 (CLI stale-loop nudge). The module persists a local,
privacy-neutral consecutive-failure counter in ~/.aisbom/loop_state.json so
`aisbom scan` can warn an operator whose automated scans fail identically
run after run. State is local-only UX state (no network), so it is written
even when AISBOM_NO_TELEMETRY is set.
"""

from __future__ import annotations

import json

import pytest

from aisbom import loop_state


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    """Writable config dir for loop state, overriding the conftest stub."""
    monkeypatch.setattr("aisbom.telemetry.get_config_dir", lambda: tmp_path)
    return tmp_path


# ============================================================================
# record_failure()
# ============================================================================

class TestRecordFailure:
    def test_first_failure_returns_one_and_persists(self, state_dir):
        count = loop_state.record_failure("HTTPError", "401", "huggingface")
        assert count == 1
        state = json.loads((state_dir / "loop_state.json").read_text())
        assert state["error_type"] == "HTTPError"
        assert state["http_status"] == "401"
        assert state["target_type"] == "huggingface"
        assert state["count"] == 1
        assert "last_seen" in state

    def test_identical_failure_increments(self, state_dir):
        for expected in (1, 2, 3):
            count = loop_state.record_failure("HTTPError", "401", "huggingface")
            assert count == expected

    def test_different_fingerprint_resets_to_one(self, state_dir):
        loop_state.record_failure("HTTPError", "401", "huggingface")
        loop_state.record_failure("HTTPError", "401", "huggingface")
        # status changed 401 -> timeout: not the same loop
        count = loop_state.record_failure("ConnectTimeout", "timeout", "huggingface")
        assert count == 1
        state = json.loads((state_dir / "loop_state.json").read_text())
        assert state["http_status"] == "timeout"
        assert state["count"] == 1

    def test_corrupt_state_file_treated_as_fresh(self, state_dir):
        (state_dir / "loop_state.json").write_text("{not json")
        count = loop_state.record_failure("HTTPError", "401", "huggingface")
        assert count == 1

    def test_unwritable_dir_is_silent_noop(self, monkeypatch):
        monkeypatch.setattr("aisbom.telemetry.get_config_dir", lambda: None)
        # No dir: nothing persisted, but the call still reports this failure.
        assert loop_state.record_failure("HTTPError", "401", "huggingface") == 1
        assert loop_state.record_failure("HTTPError", "401", "huggingface") == 1

    def test_works_with_telemetry_opted_out(self, state_dir, monkeypatch):
        # Loop state is local-only UX state: AISBOM_NO_TELEMETRY must NOT
        # disable it (documented in README Telemetry & Privacy).
        monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
        assert loop_state.record_failure("HTTPError", "401", "huggingface") == 1
        assert loop_state.record_failure("HTTPError", "401", "huggingface") == 2
        assert (state_dir / "loop_state.json").exists()

    def test_state_survives_across_invocations(self, state_dir):
        # Simulates two separate CLI processes sharing the state file.
        loop_state.record_failure("HTTPError", "401", "huggingface")
        loop_state.record_failure("HTTPError", "401", "huggingface")
        # A "new process" reads the same file fresh from disk.
        assert loop_state.record_failure("HTTPError", "401", "huggingface") == 3


# ============================================================================
# record_success()
# ============================================================================

class TestRecordSuccess:
    def test_success_on_same_target_type_clears_state(self, state_dir):
        loop_state.record_failure("HTTPError", "401", "huggingface")
        loop_state.record_failure("HTTPError", "401", "huggingface")
        loop_state.record_success("huggingface")
        assert not (state_dir / "loop_state.json").exists()
        assert loop_state.record_failure("HTTPError", "401", "huggingface") == 1

    def test_success_on_other_target_type_keeps_state(self, state_dir):
        # A passing *local* scan says nothing about the failing HF loop.
        loop_state.record_failure("HTTPError", "401", "huggingface")
        loop_state.record_success("local")
        assert loop_state.record_failure("HTTPError", "401", "huggingface") == 2

    def test_success_with_no_state_is_noop(self, state_dir):
        loop_state.record_success("huggingface")  # must not raise

    def test_unwritable_dir_is_silent_noop(self, monkeypatch):
        monkeypatch.setattr("aisbom.telemetry.get_config_dir", lambda: None)
        loop_state.record_success("huggingface")  # must not raise


# ============================================================================
# bucket_count()
# ============================================================================

class TestBucketCount:
    @pytest.mark.parametrize("count,expected", [
        (1, "1"), (2, "2"), (9, "9"), (10, "10+"), (133, "10+"),
    ])
    def test_low_cardinality_buckets(self, count, expected):
        assert loop_state.bucket_count(count) == expected


# ============================================================================
# CLI wiring — the stderr nudge and the telemetry dimension
# ============================================================================

import requests
from typer.testing import CliRunner

import aisbom.cli as cli_module
from aisbom.cli import app

runner = CliRunner()


def _http_error(status: int) -> requests.exceptions.HTTPError:
    resp = requests.Response()
    resp.status_code = status
    return requests.exceptions.HTTPError(response=resp)


class _FetchFailingScanner:
    """DeepScanner stub returning a structured fetch failure (the #58 shape)."""

    _exc: BaseException

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


class _CleanScanner:
    """DeepScanner stub that succeeds with nothing found."""

    def __init__(self, *args, **kwargs):
        pass

    def scan(self):
        return {"artifacts": [], "dependencies": [], "errors": []}


def _scanner_fetch_failing(exc: BaseException):
    return type("_FFS", (_FetchFailingScanner,), {"_exc": exc})


@pytest.fixture
def cli_env(state_dir, tmp_path, monkeypatch):
    """Loop-state-enabled CLI environment: writable state dir, no version
    check network call, cwd pinned to tmp so sbom.json lands there."""
    monkeypatch.setattr(cli_module, "run_version_check_wrapper", lambda: None)
    monkeypatch.setattr(cli_module, "update_result", {"version": None})
    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.delenv("HUGGING_FACE_HUB_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)
    return state_dir


class TestLoopWarningCli:
    def test_no_warning_before_third_failure(self, cli_env, monkeypatch):
        monkeypatch.setattr(
            cli_module, "DeepScanner", _scanner_fetch_failing(_http_error(401))
        )
        for _ in range(2):
            result = runner.invoke(app, ["scan", "hf://acme/private-model"])
            assert "times in a row" not in result.output

    def test_third_identical_failure_prints_nudge_with_token_hint(
        self, cli_env, monkeypatch
    ):
        monkeypatch.setattr(
            cli_module, "DeepScanner", _scanner_fetch_failing(_http_error(401))
        )
        for _ in range(2):
            runner.invoke(app, ["scan", "hf://acme/private-model"])
        result = runner.invoke(app, ["scan", "hf://acme/private-model"])
        assert "3 times in a row" in result.output
        assert "HF_TOKEN" in result.output

    def test_upgrade_hint_only_when_newer_version_known(self, cli_env, monkeypatch):
        monkeypatch.setattr(
            cli_module, "DeepScanner", _scanner_fetch_failing(_http_error(401))
        )
        for _ in range(2):
            runner.invoke(app, ["scan", "hf://acme/private-model"])
        # Version check already knows a newer version (no extra network call).
        monkeypatch.setattr(cli_module, "update_result", {"version": "99.0.0"})
        result = runner.invoke(app, ["scan", "hf://acme/private-model"])
        assert "99.0.0" in result.output
        assert "pip install --upgrade aisbom-cli" in result.output

    def test_success_resets_counter(self, cli_env, monkeypatch):
        monkeypatch.setattr(
            cli_module, "DeepScanner", _scanner_fetch_failing(_http_error(401))
        )
        for _ in range(2):
            runner.invoke(app, ["scan", "hf://acme/private-model"])
        # A successful scan of the same target class breaks the loop...
        monkeypatch.setattr(cli_module, "DeepScanner", _CleanScanner)
        runner.invoke(app, ["scan", "hf://acme/private-model"])
        # ...so the next failure is #1 again, not #3: no warning.
        monkeypatch.setattr(
            cli_module, "DeepScanner", _scanner_fetch_failing(_http_error(401))
        )
        result = runner.invoke(app, ["scan", "hf://acme/private-model"])
        assert "times in a row" not in result.output

    def test_non_auth_failure_omits_token_hint(self, cli_env, monkeypatch):
        monkeypatch.setattr(
            cli_module,
            "DeepScanner",
            _scanner_fetch_failing(requests.exceptions.Timeout()),
        )
        for _ in range(2):
            runner.invoke(app, ["scan", "hf://acme/model"])
        result = runner.invoke(app, ["scan", "hf://acme/model"])
        assert "3 times in a row" in result.output
        assert "HF_TOKEN" not in result.output


class TestConsecutiveFailuresTelemetry:
    def _capture_cli_error(self, monkeypatch):
        captured: list[dict] = []

        def _record(event, params=None, scan_id=None):
            if event == "cli_error":
                captured.append(dict(params or {}))
            return None

        monkeypatch.setattr("aisbom.telemetry.post_event", _record)
        return captured

    def test_fetch_failure_payload_carries_bucketed_count(self, cli_env, monkeypatch):
        captured = self._capture_cli_error(monkeypatch)
        monkeypatch.setattr(
            cli_module, "DeepScanner", _scanner_fetch_failing(_http_error(401))
        )
        for _ in range(3):
            runner.invoke(app, ["scan", "hf://acme/private-model"])
        assert [p["consecutive_failures"] for p in captured] == ["1", "2", "3"]

    def test_crash_path_payload_carries_count(self, cli_env, monkeypatch):
        captured = self._capture_cli_error(monkeypatch)

        class _Raising:
            def __init__(self, *a, **kw):
                pass

            def scan(self):
                raise _http_error(500)

        monkeypatch.setattr(cli_module, "DeepScanner", _Raising)
        runner.invoke(app, ["scan", "hf://acme/model"])
        assert captured and captured[0]["consecutive_failures"] == "1"
