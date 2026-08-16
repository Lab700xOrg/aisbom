"""
Shared pytest fixtures for the aisbom-cli test suite.

The single fixture defined here, `_stub_telemetry`, autouses to neutralize
all `aisbom.telemetry` network and filesystem side-effects during tests
that exercise the CLI commands. Without it, the eventual `cli.py` wiring
of telemetry would cause every CliRunner-based test to fire real HTTP
POSTs to api.aisbom.io and to write to ~/.aisbom/config.json on the
runner's home directory.

The fixture is exempted for tests in test_telemetry.py, where the real
module behavior is the subject under test.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _stub_telemetry(request, monkeypatch):
    """
    Auto-stub `aisbom.telemetry` for every test except those in
    test_telemetry.py.

    Inert today (cli.py does not yet import aisbom.telemetry, so these
    patches replace symbols that nothing in the code-under-test calls).
    Activates the moment cli.py is wired to call post_event / config
    helpers, at which point this fixture prevents real HTTP and FS I/O
    in the test suite.
    """
    # Tests in test_telemetry.py exercise the real module's behavior
    # and must not be auto-stubbed.
    if request.module.__name__.endswith("test_telemetry"):
        return

    monkeypatch.setattr("aisbom.telemetry.post_event", lambda *a, **kw: None)
    monkeypatch.setattr("aisbom.telemetry.get_or_init_config", lambda: {})
    monkeypatch.setattr("aisbom.telemetry.get_config_dir", lambda: None)
    monkeypatch.setattr("aisbom.telemetry.is_ci", lambda: False)


@pytest.fixture(autouse=True)
def _stub_version_check(monkeypatch):
    """Auto-stub the background update check for every test.

    `scan` and `diff` each start a daemon thread running
    `run_version_check_wrapper`, which calls `check_latest_version` (a real
    request to api.aisbom.io, suppressed only by AISBOM_NO_TELEMETRY) and
    writes the answer into the module-global `update_result`.

    Two problems follow, and this fixture closes both:

    1. **Real network I/O from the test suite.** Nine test modules invoke
       `scan` without stubbing this, so a plain `pytest` run makes live
       outbound requests.
    2. **A cross-test race.** The thread is a daemon and outlives the test
       that spawned it, so it can land in a *later* test and overwrite an
       `update_result` that test deliberately set — observed as an
       intermittent failure in test_loop_state.py's upgrade-hint test, whose
       monkeypatched {"version": "99.0.0"} was reset to None mid-test.

    Both the wrapper and the underlying check are stubbed: stubbing only the
    latter would stop the network but leave the thread still writing to the
    global, so the race would survive.

    Tests that want the update path assert on `update_result` directly (see
    test_version_check.py for the real function, which imports from
    `aisbom.version_check` and is unaffected by these `aisbom.cli` patches).
    """
    monkeypatch.setattr("aisbom.cli.run_version_check_wrapper", lambda: None)
    monkeypatch.setattr("aisbom.cli.check_latest_version", lambda: None)
