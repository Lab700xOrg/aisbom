"""
Local failure-loop detection for `aisbom scan`.

Parent: aisbom-ops #99. The 2026-07-11 cli_error investigation found the
fleet error rate dominated by single machines running automated scans that
fail identically every day (gated HF repo, no token, old CLI). The only
channel to reach such an operator is their own logs — so the CLI keeps a
consecutive-failure counter and prints a loud stderr nudge once the same
failure has happened LOOP_WARN_THRESHOLD times in a row.

The state is a fingerprint of the *shape* of the failure — the same
low-cardinality buckets `cli.py:_scan_error_payload()` computes
(error_type, http_status bucket, target_type). No URLs, repo ids, paths,
or messages are ever stored.

Privacy note: the state file (~/.aisbom/loop_state.json) is local-only UX
state and involves no network, so it is written even when
AISBOM_NO_TELEMETRY is set. Documented in the README's Telemetry & Privacy
section.

PyInstaller constraint: stdlib only (see telemetry.py header).
Contract: never raise, never block the scan flow.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from . import telemetry

STATE_FILENAME = "loop_state.json"

# 3rd consecutive identical failure triggers the stderr nudge.
LOOP_WARN_THRESHOLD = 3


def _state_path():
    home = telemetry.get_config_dir()
    if home is None:
        return None
    return home / STATE_FILENAME


def _load_state() -> dict | None:
    path = _state_path()
    if path is None:
        return None
    try:
        state = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return state if isinstance(state, dict) else None


def _save_state(state: dict) -> None:
    # Atomic write-tmp-then-rename, same idiom as telemetry.save_config, so
    # concurrent CLI invocations cannot corrupt the file.
    path = _state_path()
    if path is None:
        return
    tmp = path.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(state, separators=(",", ":")))
        tmp.replace(path)
    except (OSError, PermissionError):
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def record_failure(error_type: str, http_status: str, target_type: str) -> int:
    """Record one scan-path fetch failure; return the consecutive count.

    Increments when the fingerprint matches the stored one, resets to 1 when
    it changed or no state exists. When the config dir is unwritable the
    count is not persisted and every call reports 1 (the warning simply
    never fires there — acceptable, since that environment also has no
    stable identity to loop on).
    """
    try:
        state = _load_state()
        count = 1
        if (
            state is not None
            and state.get("error_type") == error_type
            and state.get("http_status") == http_status
            and state.get("target_type") == target_type
        ):
            try:
                count = int(state.get("count", 0)) + 1
            except (TypeError, ValueError):
                count = 1
        _save_state({
            "error_type": error_type,
            "http_status": http_status,
            "target_type": target_type,
            "count": count,
            "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
        return count
    except Exception:
        # Never let loop bookkeeping break a scan.
        return 1


def record_success(target_type: str) -> None:
    """Clear the counter when a scan of the same target class succeeds.

    A passing scan of a *different* target class says nothing about the
    failing loop (e.g. a local scan succeeding doesn't mean the gated HF
    repo started working), so the state is kept in that case.
    """
    try:
        state = _load_state()
        if state is None or state.get("target_type") != target_type:
            return
        path = _state_path()
        if path is not None:
            path.unlink(missing_ok=True)
    except Exception:
        pass


def bucket_count(count: int) -> str:
    """Low-cardinality string bucket for the telemetry dimension."""
    return str(count) if count < 10 else "10+"
