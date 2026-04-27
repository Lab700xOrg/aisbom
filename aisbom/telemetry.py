"""
Privacy-respecting CLI telemetry for aisbom-cli.

Events are POSTed to api.aisbom.io/v1/telemetry, which forwards to GA4
Measurement Protocol on the AIsbom CLI stream. See
cloudcowork/PHASE_1_2_DESIGN.md for the full design.

Gates (all must be passed before any network call):
  AISBOM_NO_TELEMETRY  — opt-out, always wins. If set, no events fire and no
                         config files are written.
  AISBOM_TELEMETRY_V2  — opt-in for the v2 rollout. Until set to "1",
                         post_event() is a no-op even with no opt-out.
                         Default-flipped to on in a future release.

PyInstaller constraint: this module imports only stdlib + `requests`. Do not
add new third-party dependencies without updating scripts/build_binaries.sh.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

TELEMETRY_ENDPOINT = "https://api.aisbom.io/v1/telemetry"
POST_TIMEOUT_SEC = 3.0
CONFIG_SCHEMA_VERSION = 1

# Hardcoded app salt. Purpose: make user_id non-reversible to a MAC address
# even if a user_id is ever exposed (e.g., GA4 export). The threat model is
# "outside attacker reverses user_id → MAC", not "attacker compromises this
# source code". Constant value is fine; rotate by bumping the suffix if the
# hash space ever needs to be reset.
_USER_ID_SALT = "aisbom-cli-1.0"


def is_ci() -> bool:
    """True when running inside a CI environment (GITHUB_ACTIONS or CI set)."""
    return bool(os.getenv("GITHUB_ACTIONS") or os.getenv("CI"))


def _telemetry_disabled() -> bool:
    """All-paths short-circuit. Both env vars consulted; opt-out always wins."""
    if os.getenv("AISBOM_NO_TELEMETRY"):
        return True
    if os.getenv("AISBOM_TELEMETRY_V2") != "1":
        return True
    return False


def get_config_dir() -> Path | None:
    """
    Return the writable ~/.aisbom directory, creating it if needed.

    Returns None if the dir cannot be created or written to (sandboxed
    environments, read-only FS, restrictive Docker, etc.). Callers should
    treat None as "skip all stateful telemetry" — never raise from telemetry.
    """
    try:
        home = Path.home() / ".aisbom"
        home.mkdir(exist_ok=True, parents=True)
        probe = home / ".write_probe"
        probe.write_text("")
        probe.unlink()
        return home
    except (OSError, PermissionError):
        return None


def save_config(cfg: dict) -> None:
    """
    Atomically persist config.json to ~/.aisbom/. Silent no-op if the dir is
    unwritable. Uses write-temp-then-rename so concurrent CLI invocations
    cannot corrupt the file.
    """
    home = get_config_dir()
    if home is None:
        return
    tmp = home / "config.json.tmp"
    try:
        tmp.write_text(json.dumps(cfg, separators=(",", ":")))
        tmp.replace(home / "config.json")
    except (OSError, PermissionError):
        # Never raise from telemetry. Best-effort cleanup of orphaned tmp.
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _generate_user_id() -> str:
    """
    Anonymous, stable per-machine user_id. Hash of MAC address + app salt,
    truncated to 16 hex chars. uuid.getnode() returns a random number with
    the multicast bit set if it can't read the MAC, which means a small
    fraction of users (<1%) will get a fresh user_id per process. Documented
    risk; affects returning-user metrics for those users only.
    """
    raw = f"{uuid.getnode()}:{_USER_ID_SALT}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def get_or_init_config() -> dict:
    """
    Load or initialize config.json.

    Returns:
        Config dict with keys schema_version, user_id, installed_at.
        Returns empty dict if telemetry is disabled or config dir unwritable.

    On first call (and when config is missing/corrupt), generates a stable
    anonymous user_id and records install timestamp.
    """
    if _telemetry_disabled():
        return {}
    home = get_config_dir()
    if home is None:
        return {}
    config_path = home / "config.json"
    if config_path.exists():
        try:
            return json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            # corrupt or unreadable — fall through to reinit
            pass
    cfg = {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "user_id": _generate_user_id(),
        "installed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    save_config(cfg)
    return cfg


def _build_user_agent() -> str:
    """
    Match the format from version_check.py:26 verbatim so the Worker's UA
    parser at aisbom-edge/src/index.js works for both endpoints:

        aisbom-cli/{version} ({system}; python {py_ver}; ci={true|false})
    """
    try:
        version = importlib.metadata.version("aisbom-cli")
    except importlib.metadata.PackageNotFoundError:
        version = "unknown"
    system = platform.system()
    py_ver = platform.python_version()
    is_ci_str = "true" if is_ci() else "false"
    return f"aisbom-cli/{version} ({system}; python {py_ver}; ci={is_ci_str})"


def _do_post(event: str, params: dict, scan_id: str | None) -> None:
    """
    Send one event to the Worker. Silent on any failure — the contract is
    that telemetry never raises and never blocks a user-facing flow.
    """
    try:
        body: dict = {"event": event, "params": params}
        if scan_id:
            body["scan_id"] = scan_id
        requests.post(
            TELEMETRY_ENDPOINT,
            json=body,
            headers={"User-Agent": _build_user_agent()},
            timeout=POST_TIMEOUT_SEC,
        )
    except Exception:
        # Catch-all is intentional. Telemetry must not surface errors.
        pass


def post_event(
    event: str,
    params: dict | None = None,
    scan_id: str | None = None,
) -> threading.Thread | None:
    """
    Fire one telemetry event in a non-daemon background thread.

    Args:
        event: The event name (validated against allowlist by the Worker).
        params: Custom event params. user_id is auto-injected from config.
        scan_id: Optional UUID grouping multiple events from one CLI invocation
            into a single GA4 session.

    Returns:
        threading.Thread when the POST has been dispatched; the caller may
        join() with a timeout before exiting to give it a chance to flush.
        None if telemetry is disabled (opt-out or v2 not enabled), in which
        case nothing was queued and nothing will be sent.

    Never raises. Never blocks on the network.
    """
    if _telemetry_disabled():
        return None
    cfg = get_or_init_config()
    full_params = dict(params or {})
    if cfg.get("user_id"):
        full_params["user_id"] = cfg["user_id"]
    thread = threading.Thread(
        target=_do_post,
        args=(event, full_params, scan_id),
        daemon=False,  # non-daemon so process waits for in-flight POSTs at exit
    )
    thread.start()
    return thread
