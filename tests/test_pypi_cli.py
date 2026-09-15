"""PyPI license resolution and `--offline`, end to end through the CLI (#129).

The lookup itself is covered in test_pypi.py. These tests pin what a user
sees: licenses in the SBOM a plain `scan` writes, the same document from
`score`, a scan that survives PyPI being down, and an `--offline` run that
makes no network call of any kind — proven with the real HTTP clients and the
socket layer refusing, not with stubs that could hide a call.
"""

import json
import socket

import pytest
import requests as real_requests
from typer.testing import CliRunner

from aisbom import offline, telemetry, version_check
from aisbom.cli import app
from tests.test_cli_integration import _osv_tree
from tests.test_pypi import FakePyPI, _torch_info, _transformers_info

runner = CliRunner()

_REAL_POST_EVENT = telemetry.post_event
_REAL_CHECK_LATEST = version_check.check_latest_version

_REQUIREMENTS = "torch==2.13.0\ntransformers==5.13.1\nnumpy\n"


def _fake_pypi(monkeypatch, **kw):
    fake = FakePyPI([_torch_info(), _transformers_info()], **kw)
    monkeypatch.setattr("aisbom.pypi._default_session", lambda: fake)
    return fake


def _tree(tmp_path, requirements=_REQUIREMENTS):
    (tmp_path / "requirements.txt").write_text(requirements)
    return tmp_path / "sbom.json"


def _components(path):
    return {c["name"]: c for c in json.loads(path.read_text())["components"]}


def _flat(result):
    return " ".join(result.output.split())  # Rich wraps long lines


# --------------------------------------------------------------------------
# Default-on resolution
# --------------------------------------------------------------------------

def test_scan_writes_pypi_licenses_into_the_sbom(tmp_path, monkeypatch):
    out = _tree(tmp_path)
    fake = _fake_pypi(monkeypatch)

    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(out)])
    assert result.exit_code == 0, result.output

    comps = _components(out)
    assert comps["transformers"]["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    assert comps["torch"]["licenses"] == [{"expression": _torch_info()["license_expression"]}]
    assert comps["torch"]["properties"] == [{"name": "aisbom:license:source", "value": "pypi"}]
    # Unpinned: never looked up, never licensed.
    assert "licenses" not in comps["numpy"]
    assert sorted(fake.gets) == [
        "https://pypi.org/pypi/torch/2.13.0/json",
        "https://pypi.org/pypi/transformers/5.13.1/json",
    ]
    flat = _flat(result)
    assert "PyPI: resolved licenses for 2 of 2 pinned dependencies" in flat
    assert "1 unpinned dependency skipped" in flat


def test_a_model_components_legal_status_is_untouched(tmp_path, monkeypatch):
    out = _osv_tree(tmp_path, requirements=_REQUIREMENTS)
    _fake_pypi(monkeypatch)
    runner.invoke(app, ["scan", str(tmp_path), "--output", str(out)])
    for comp in json.loads(out.read_text())["components"]:
        if comp["type"] == "machine-learning-model":
            assert "pypi" not in json.dumps(comp)


def test_pypi_outage_keeps_the_scan_and_its_exit_code(tmp_path, monkeypatch):
    out = _osv_tree(tmp_path, requirements=_REQUIREMENTS)
    _fake_pypi(monkeypatch, fail=real_requests.ConnectionError("down"))

    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(out)])
    assert result.exit_code == 2, result.output  # the malicious pickle still decides
    assert "PyPI license lookup failed for 2 of 2" in _flat(result)
    assert all("licenses" not in c for n, c in _components(out).items()
               if n in ("torch", "transformers"))


def test_spdx_23_output_declares_the_resolved_license(tmp_path, monkeypatch):
    out = tmp_path / "sbom.spdx.json"
    _tree(tmp_path)
    _fake_pypi(monkeypatch)
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--format", "spdx", "--output", str(out)]
    )
    assert result.exit_code == 0, result.output
    pkgs = {p["name"]: p for p in json.loads(out.read_text())["packages"]}
    assert pkgs["transformers"]["licenseDeclared"] == "Apache-2.0"
    assert pkgs["numpy"]["licenseDeclared"] == "NOASSERTION"


@pytest.mark.parametrize("args", [
    ["--format", "markdown"],
    ["--format", "spdx", "--spdx-version", "3.0"],
])
def test_outputs_that_carry_no_dependency_license_skip_the_lookup(tmp_path, monkeypatch, args):
    _tree(tmp_path)
    fake = _fake_pypi(monkeypatch)
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--output", str(tmp_path / "out"), *args]
    )
    assert result.exit_code == 0, result.output
    assert fake.calls == 0


def test_a_scan_with_no_pins_makes_no_request_and_prints_nothing(tmp_path, monkeypatch):
    out = _tree(tmp_path, requirements="numpy\n")
    fake = _fake_pypi(monkeypatch)
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(out)])
    assert fake.calls == 0
    assert "PyPI" not in result.output


def test_score_grades_the_same_licensed_document(tmp_path, monkeypatch):
    _tree(tmp_path, requirements="torch==2.13.0\ntransformers==5.13.1\n")
    _fake_pypi(monkeypatch)
    result = runner.invoke(app, ["score", str(tmp_path), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)  # the PyPI summary stays off stdout
    [lic] = [d for d in payload["dimensions"] if d["key"] == "licenses"]
    assert lic["score"] == 100


def test_score_offline_leaves_dependency_licenses_unresolved(tmp_path, monkeypatch):
    _tree(tmp_path, requirements="torch==2.13.0\n")
    fake = _fake_pypi(monkeypatch)
    result = runner.invoke(app, ["score", str(tmp_path), "--json", "--offline"])
    assert result.exit_code == 0, result.output
    assert fake.calls == 0
    [lic] = [d for d in json.loads(result.stdout)["dimensions"] if d["key"] == "licenses"]
    assert lic["score"] == 0


# --------------------------------------------------------------------------
# --offline / AISBOM_OFFLINE
# --------------------------------------------------------------------------

def _offline_args(tmp_path, out):
    return ["scan", str(tmp_path), "--output", str(out), "--vex"]


def test_offline_flag_skips_pypi_and_osv(tmp_path, monkeypatch):
    from tests.test_cli_integration import _fake_osv

    out = _osv_tree(tmp_path, requirements=_REQUIREMENTS)
    pypi_fake = _fake_pypi(monkeypatch)
    osv_fake = _fake_osv(monkeypatch)

    result = runner.invoke(app, [*_offline_args(tmp_path, out), "--offline"])
    assert result.exit_code == 2, result.output
    assert pypi_fake.calls == 0 and osv_fake.calls == 0
    assert "PyPI" not in result.output and "OSV:" not in result.output


def test_offline_env_var_is_the_same_as_the_flag(tmp_path, monkeypatch):
    out = _tree(tmp_path)
    fake = _fake_pypi(monkeypatch)
    monkeypatch.setenv("AISBOM_OFFLINE", "1")
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert fake.calls == 0


def test_offline_does_not_leak_into_the_next_invocation(tmp_path, monkeypatch):
    out = _tree(tmp_path)
    fake = _fake_pypi(monkeypatch)
    runner.invoke(app, ["scan", str(tmp_path), "--output", str(out), "--offline"])
    runner.invoke(app, ["scan", str(tmp_path), "--output", str(out)])
    assert fake.calls == 2


@pytest.mark.parametrize("command", ["scan", "score"])
@pytest.mark.parametrize("target", [
    "hf://google-bert/bert-base-uncased", "https://example.com/model.pt",
])
def test_offline_refuses_a_remote_target_before_scanning(monkeypatch, command, target):
    def explode(*a, **kw):
        raise AssertionError("the scanner must not run")

    monkeypatch.setattr("aisbom.cli.DeepScanner", explode)
    result = runner.invoke(app, [command, target, "--offline"])
    assert result.exit_code == 1
    assert "--offline" in _flat(result) and "cannot" in _flat(result).lower()


def test_offline_refuses_share(tmp_path):
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--offline", "--share", "--share-yes"]
    )
    assert result.exit_code == 1
    assert "--share" in _flat(result)


def test_offline_disables_telemetry_and_the_version_check(monkeypatch):
    posts, gets = [], []
    monkeypatch.setattr(telemetry.requests, "post", lambda *a, **kw: posts.append(a))
    monkeypatch.setattr(version_check.requests, "get", lambda *a, **kw: gets.append(a))

    offline.enable(True)
    assert _REAL_POST_EVENT("cli_scan", {}) is None
    assert _REAL_CHECK_LATEST() is None
    assert posts == [] and gets == []


def test_offline_env_disables_telemetry_on_every_command(monkeypatch):
    monkeypatch.setenv("AISBOM_OFFLINE", "1")
    assert telemetry._telemetry_disabled()


def test_info_reports_offline_mode(monkeypatch):
    monkeypatch.setenv("AISBOM_OFFLINE", "1")
    result = runner.invoke(app, ["info"])
    assert "AISBOM_OFFLINE" in result.output


# --------------------------------------------------------------------------
# Verified, not assumed: the real clients with the network cut
# --------------------------------------------------------------------------

def _cut_the_network(monkeypatch):
    attempts = []

    def refuse(*args, **kwargs):
        attempts.append(args)
        raise OSError("network is unreachable (air-gapped test)")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    return attempts


def _restore_real_clients(monkeypatch, tmp_path):
    from aisbom import cli, osv, pypi

    monkeypatch.setattr(pypi, "_default_session", lambda: real_requests)
    monkeypatch.setattr(osv, "_default_session", lambda: real_requests)
    monkeypatch.setattr(telemetry, "post_event", _REAL_POST_EVENT)
    monkeypatch.setattr(cli, "check_latest_version", _REAL_CHECK_LATEST)
    monkeypatch.setattr(cli, "run_version_check_wrapper",
                        lambda: cli.update_result.update(version=_REAL_CHECK_LATEST()))
    # Real telemetry would create ~/.aisbom/config.json; keep it in tmp.
    monkeypatch.setattr(telemetry, "get_config_dir", lambda: tmp_path / "cfg")
    monkeypatch.delenv("AISBOM_NO_TELEMETRY", raising=False)


def test_offline_scan_makes_no_network_attempt_at_all(tmp_path, monkeypatch):
    out = _osv_tree(tmp_path, requirements=_REQUIREMENTS)
    _restore_real_clients(monkeypatch, tmp_path)
    attempts = _cut_the_network(monkeypatch)

    result = runner.invoke(app, [*_offline_args(tmp_path, out), "--offline"])
    assert result.exit_code == 2, result.output
    assert attempts == [], f"--offline tried the network: {attempts}"
    assert not (tmp_path / "cfg" / "config.json").exists()


def test_air_gapped_scan_without_offline_matches_an_offline_scan(tmp_path, monkeypatch):
    offline_dir, gapped_dir = tmp_path / "offline", tmp_path / "gapped"
    offline_dir.mkdir()
    gapped_dir.mkdir()
    offline_out = _osv_tree(offline_dir, requirements=_REQUIREMENTS)
    gapped_out = _osv_tree(gapped_dir, requirements=_REQUIREMENTS)

    baseline = runner.invoke(app, ["scan", str(offline_dir), "--output",
                                   str(offline_out), "--offline"])

    monkeypatch.setattr("aisbom.pypi._default_session", lambda: real_requests)
    attempts = _cut_the_network(monkeypatch)
    gapped = runner.invoke(app, ["scan", str(gapped_dir), "--output", str(gapped_out)])

    assert attempts, "the lookup never tried the network, so nothing was proven"
    assert gapped.exit_code == baseline.exit_code == 2, gapped.output

    def shape(path):
        return sorted(
            (c["name"], c["type"], json.dumps(c.get("properties"), sort_keys=True),
             json.dumps(c.get("licenses"), sort_keys=True))
            for c in json.loads(path.read_text())["components"]
        )

    assert shape(gapped_out) == shape(offline_out)
