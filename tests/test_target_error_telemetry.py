"""Observability for unusable scan targets (aisbom-ops #126).

#125 made a missing path, a broken symlink, or a named file no scanner claims
fail the scan (exit 1) instead of passing clean. It did not make that failure
*visible*: a target error reached no `cli_error` emit site, was counted in the
misleadingly-named `parse_error_count`, and — worst — called
`loop_state.record_success`, so a cron job pointed at a typo'd path reset the
stale-loop counter (#99) on every single run.

These tests pin the three fixes and the privacy position that constrains them:
the event carries a closed-set synthetic `error_type`, never the path, the
extension, or the user-facing message.
"""

import json
import os

import pytest
from typer.testing import CliRunner

from aisbom import cli as cli_module
from aisbom.cli import app
from aisbom.scanner import TARGET_ERROR_TYPES, DeepScanner

runner = CliRunner()

# A deliberately distinctive path fragment and extension so a leak into the
# payload is detectable by substring, not just by key name.
_SECRET_DIR = "acme-internal-secret-project"
_ODD_EXT = ".zzqx"


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    """Writable loop-state dir, no version-check network call, captured events."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    monkeypatch.setattr("aisbom.telemetry.get_config_dir", lambda: state_dir)
    monkeypatch.setattr(cli_module, "run_version_check_wrapper", lambda: None)
    monkeypatch.setattr(cli_module, "update_result", {"version": None})
    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.delenv("HUGGING_FACE_HUB_TOKEN", raising=False)
    monkeypatch.delenv("AISBOM_NO_TELEMETRY", raising=False)
    monkeypatch.chdir(tmp_path)

    events: list[tuple[str, dict]] = []

    def _record(event, params=None, scan_id=None):
        events.append((event, dict(params or {})))
        return None

    monkeypatch.setattr("aisbom.telemetry.post_event", _record)
    return {"tmp": tmp_path, "state": state_dir, "events": events}


def _errors(events):
    return [p for e, p in events if e == "cli_error"]


def _scans(events):
    return [p for e, p in events if e == "cli_scan"]


def _missing_target(tmp_path):
    return str(tmp_path / _SECRET_DIR / "does-not-exist.pt")


def _unsupported_target(tmp_path):
    d = tmp_path / _SECRET_DIR
    d.mkdir(exist_ok=True)
    f = d / f"notes{_ODD_EXT}"
    f.write_text("not a model")
    return str(f)


# --- scanner: closed-set reason codes ------------------------------------


def test_target_error_types_are_a_closed_set():
    assert TARGET_ERROR_TYPES == frozenset(
        {"MissingTarget", "UnsupportedFileType", "NotAFileOrDirectory"}
    )


def test_missing_target_records_missing_target_type(tmp_path):
    errors = DeepScanner(_missing_target(tmp_path)).scan()["errors"]
    assert [e["target_error_type"] for e in errors] == ["MissingTarget"]


def test_broken_symlink_records_missing_target_type(tmp_path):
    link = tmp_path / "dangling.pt"
    link.symlink_to(tmp_path / "gone.pt")
    errors = DeepScanner(str(link)).scan()["errors"]
    assert [e["target_error_type"] for e in errors] == ["MissingTarget"]


def test_unsupported_file_records_unsupported_file_type(tmp_path):
    errors = DeepScanner(_unsupported_target(tmp_path)).scan()["errors"]
    assert [e["target_error_type"] for e in errors] == ["UnsupportedFileType"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a FIFO")
def test_fifo_records_not_a_file_or_directory_type(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    errors = DeepScanner(str(fifo)).scan()["errors"]
    assert [e["target_error_type"] for e in errors] == ["NotAFileOrDirectory"]


@pytest.mark.parametrize("ext", [".zzqx", ".docx", "", ".PT_backup", ".🙂"])
def test_unusual_extensions_never_mint_a_new_type(tmp_path, ext):
    f = tmp_path / f"file{ext}"
    f.write_text("plain text, not a pickle")
    errors = DeepScanner(str(f)).scan()["errors"]
    assert [e["target_error_type"] for e in errors] == ["UnsupportedFileType"]


def test_recording_an_unknown_type_is_refused(tmp_path):
    with pytest.raises(ValueError):
        DeepScanner(str(tmp_path))._record_target_error("x", "msg", "SomethingNew")


# --- cli_error emission ---------------------------------------------------


def test_target_error_emits_one_cli_error(cli_env):
    result = runner.invoke(app, ["scan", _missing_target(cli_env["tmp"])])
    assert result.exit_code == 1
    errors = _errors(cli_env["events"])
    assert len(errors) == 1
    assert errors[0] == {
        "command": "scan",
        "error_type": "MissingTarget",
        "http_status": "none",
        "token_present": "false",
        "target_type": "local",
        "consecutive_failures": "1",
    }


def test_unsupported_file_emits_unsupported_file_type(cli_env):
    runner.invoke(app, ["scan", _unsupported_target(cli_env["tmp"])])
    assert [p["error_type"] for p in _errors(cli_env["events"])] == [
        "UnsupportedFileType"
    ]


def test_payloads_carry_no_path_extension_or_message(cli_env):
    tmp = cli_env["tmp"]
    runner.invoke(app, ["scan", _missing_target(tmp)])
    runner.invoke(app, ["scan", _unsupported_target(tmp)])
    blob = json.dumps(cli_env["events"])
    for leak in (_SECRET_DIR, _ODD_EXT, "zzqx", str(tmp), "notes",
                 "No such file", "Unsupported file type", "no scanner claimed"):
        assert leak not in blob, f"telemetry leaked {leak!r}"


def test_no_telemetry_suppresses_event_but_keeps_loop_state(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    monkeypatch.setattr("aisbom.telemetry.get_config_dir", lambda: state_dir)
    monkeypatch.setattr(cli_module, "run_version_check_wrapper", lambda: None)
    monkeypatch.setattr(cli_module, "update_result", {"version": None})
    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    monkeypatch.chdir(tmp_path)
    posted: list = []
    monkeypatch.setattr(
        "aisbom.telemetry._do_post", lambda *a, **kw: posted.append(a)
    )

    result = runner.invoke(app, ["scan", _missing_target(tmp_path)])

    assert result.exit_code == 1
    assert posted == []
    state = json.loads((state_dir / "loop_state.json").read_text())
    assert state["error_type"] == "MissingTarget"
    assert state["http_status"] == "none"
    assert state["target_type"] == "local"


# --- stale-loop wiring ----------------------------------------------------


def test_repeated_target_errors_trip_the_nudge(cli_env):
    target = _missing_target(cli_env["tmp"])
    for _ in range(2):
        result = runner.invoke(app, ["scan", target])
        assert "times in a row" not in result.output
    result = runner.invoke(app, ["scan", target])
    assert "3 times in a row" in result.output
    assert "HF_TOKEN" not in result.output
    assert "scan target" in result.output
    # The nudge follows the failure it is about, not the other way round.
    assert result.output.index("Cannot scan") < result.output.index("times in a row")
    assert [p["consecutive_failures"] for p in _errors(cli_env["events"])] == [
        "1", "2", "3",
    ]


def test_clean_local_scan_clears_a_target_error_loop(cli_env):
    tmp = cli_env["tmp"]
    target = _missing_target(tmp)
    for _ in range(2):
        runner.invoke(app, ["scan", target])
    clean = tmp / "empty-dir"
    clean.mkdir()
    assert runner.invoke(app, ["scan", str(clean)]).exit_code == 0
    assert not (cli_env["state"] / "loop_state.json").exists()
    result = runner.invoke(app, ["scan", target])
    assert "times in a row" not in result.output
    assert _errors(cli_env["events"])[-1]["consecutive_failures"] == "1"


def test_different_target_error_causes_do_not_share_a_count(cli_env):
    tmp = cli_env["tmp"]
    runner.invoke(app, ["scan", _missing_target(tmp)])
    runner.invoke(app, ["scan", _missing_target(tmp)])
    runner.invoke(app, ["scan", _unsupported_target(tmp)])
    assert [p["consecutive_failures"] for p in _errors(cli_env["events"])] == [
        "1", "2", "1",
    ]


# --- cli_scan: target errors are distinguishable --------------------------


def test_cli_scan_reports_target_error_count(cli_env):
    runner.invoke(app, ["scan", _missing_target(cli_env["tmp"])])
    (scan,) = _scans(cli_env["events"])
    assert scan["target_error_count"] == "1"
    # Additive: parse_error_count keeps its pre-#126 meaning (all errors).
    assert scan["parse_error_count"] == "1"


def test_parse_error_is_distinguishable_from_target_error(cli_env, monkeypatch):
    class _ParseFailingScanner:
        def __init__(self, *a, **kw):
            pass

        def scan(self):
            return {
                "artifacts": [],
                "dependencies": [],
                "errors": [{"file": "model.pt", "error": "bad zip"}],
            }

    monkeypatch.setattr(cli_module, "DeepScanner", _ParseFailingScanner)
    runner.invoke(app, ["scan", "."])
    (scan,) = _scans(cli_env["events"])
    assert scan["target_error_count"] == "0"
    assert scan["parse_error_count"] == "1"
    assert _errors(cli_env["events"]) == []


def test_clean_scan_reports_zero_target_errors(cli_env):
    clean = cli_env["tmp"] / "empty"
    clean.mkdir()
    runner.invoke(app, ["scan", str(clean)])
    (scan,) = _scans(cli_env["events"])
    assert scan["target_error_count"] == "0"
