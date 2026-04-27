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
