"""PyPI license resolution for pinned requirements.txt dependencies (#129).

pypi.org is never contacted from this suite. Every test drives a fake session
whose payloads are trimmed copies of real `/pypi/<name>/<version>/json`
responses, so the resolved, unknown, unreachable and cached paths are all
exercised deterministically and offline.
"""

import json
import time

import pytest
import requests

from aisbom import pypi

_REAL_DEFAULT_SESSION = pypi._default_session


@pytest.fixture(autouse=True)
def _no_retry_pause(monkeypatch):
    """Retries are exercised here; their real-time backoff is not."""
    monkeypatch.setattr(pypi, "_BACKOFF_SECONDS", 0)


# --------------------------------------------------------------------------
# Real PyPI `info` shapes (trimmed to the fields AIsbom reads)
# --------------------------------------------------------------------------

def _torch_info():
    """torch 2.13.0: a PEP 639 License-Expression and nothing else."""
    return {
        "name": "torch",
        "version": "2.13.0",
        "license": None,
        "license_expression": (
            "Apache-2.0 AND Apache-2.0 WITH LLVM-exception AND BSD-2-Clause "
            "AND BSD-3-Clause AND BSL-1.0 AND MIT"
        ),
        "classifiers": ["Programming Language :: Python :: 3"],
    }


def _transformers_info():
    """transformers 5.13.1: free text in `license`, no license classifier."""
    return {
        "name": "transformers",
        "version": "5.13.1",
        "license": "Apache 2.0 License",
        "license_expression": None,
        "classifiers": ["Intended Audience :: Developers"],
    }


def _numpy_info():
    """numpy 1.26.4: the whole BSD text in `license`, an ambiguous classifier."""
    return {
        "name": "numpy",
        "version": "1.26.4",
        "license": (
            "Copyright (c) 2005-2023, NumPy Developers.\nAll rights reserved.\n\n"
            "Redistribution and use in source and binary forms, with or without "
            "modification, are permitted provided that ...\n" * 40
        ),
        "license_expression": None,
        "classifiers": ["License :: OSI Approved :: BSD License"],
    }


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}")

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakePyPI:
    """A stand-in for pypi.org that records every URL requested from it."""

    def __init__(self, infos=(), fail=None, payloads=None, statuses=None):
        self.infos = {(i["name"], i["version"]): i for i in infos}
        self.fail = fail
        # {(name, version): raw payload} — for malformed bodies.
        self.payloads = payloads or {}
        # {(name, version): [status, status, ...]} — consumed per request.
        self.statuses = {k: list(v) for k, v in (statuses or {}).items()}
        self.gets = []
        self.headers = []

    def get(self, url, timeout=None, headers=None):
        self.gets.append(url)
        self.headers.append(headers)
        assert timeout is not None and timeout > 0, "every request needs a timeout"
        if self.fail:
            raise self.fail
        # https://pypi.org/pypi/<name>/<version>/json
        name, version = url.rstrip("/").split("/")[-3:-1]
        key = (name, version)
        queued = self.statuses.get(key)
        if queued:
            status = queued.pop(0)
            if status >= 400:
                return FakeResponse({"message": "err"}, status)
        if key in self.payloads:
            return FakeResponse(self.payloads[key])
        if key not in self.infos:
            return FakeResponse({"message": "Not Found"}, 404)
        return FakeResponse({"info": self.infos[key], "urls": []})

    @property
    def calls(self):
        return len(self.gets)


def _dep(name, version, pinned=True):
    return {"name": name, "version": version, "type": "library", "pinned": pinned}


def _resolve(deps, session, cache_dir=None, **kw):
    return pypi.resolve_dependency_licenses(
        deps, session=session, cache_dir=cache_dir, **kw
    )


# --------------------------------------------------------------------------
# Normalisation — what counts as a declared license
# --------------------------------------------------------------------------

def test_pep639_license_expression_is_used_verbatim():
    assert pypi.normalize_license(_torch_info()) == pypi.ResolvedLicense(
        _torch_info()["license_expression"], is_spdx=True
    )


def test_a_spdx_id_in_the_license_field_is_canonicalised():
    info = {"license": "mit", "classifiers": []}
    assert pypi.normalize_license(info) == pypi.ResolvedLicense("MIT", is_spdx=True)


def test_a_spdx_expression_in_the_license_field_is_accepted():
    info = {"license": "Apache-2.0 OR MIT", "classifiers": []}
    assert pypi.normalize_license(info) == pypi.ResolvedLicense(
        "Apache-2.0 OR MIT", is_spdx=True
    )


@pytest.mark.parametrize("text, spdx", [
    ("Apache 2.0 License", "Apache-2.0"),
    ("Apache License 2.0", "Apache-2.0"),
    ("Apache License, Version 2.0", "Apache-2.0"),
    ("MIT License", "MIT"),
    ("BSD 3-Clause License", "BSD-3-Clause"),
])
def test_unambiguous_common_spellings_map_to_spdx(text, spdx):
    info = {"license": text, "classifiers": []}
    assert pypi.normalize_license(info) == pypi.ResolvedLicense(spdx, is_spdx=True)


def test_transformers_free_text_resolves_to_apache():
    assert pypi.normalize_license(_transformers_info()) == pypi.ResolvedLicense(
        "Apache-2.0", is_spdx=True
    )


def test_an_unambiguous_classifier_is_used_when_the_field_is_empty():
    info = {"license": "", "classifiers": ["License :: OSI Approved :: MIT License"]}
    assert pypi.normalize_license(info) == pypi.ResolvedLicense("MIT", is_spdx=True)


@pytest.mark.parametrize("classifier", [
    "License :: OSI Approved :: BSD License",
    "License :: OSI Approved :: Apache Software License",
    "License :: OSI Approved :: GNU General Public License (GPL)",
    "License :: Other/Proprietary License",
])
def test_ambiguous_classifiers_resolve_nothing(classifier):
    info = {"license": None, "classifiers": [classifier]}
    assert pypi.normalize_license(info) is None


@pytest.mark.parametrize("other", [
    "License :: OSI Approved :: BSD License",
    "License :: Other/Proprietary License",
])
def test_a_mapped_classifier_beside_an_unmapped_one_resolves_nothing(other):
    # MIT alongside a generic BSD classifier may mean dual licensing; dropping
    # the one we cannot map and reporting "MIT" would assert a single license.
    info = {"license": None, "classifiers": [
        "License :: OSI Approved :: MIT License", other,
    ]}
    assert pypi.normalize_license(info) is None


def test_the_bare_osi_approved_category_is_not_a_second_license():
    info = {"license": None, "classifiers": [
        "License :: OSI Approved",
        "License :: OSI Approved :: MIT License",
    ]}
    assert pypi.normalize_license(info) == pypi.ResolvedLicense("MIT", is_spdx=True)


def test_two_different_classifiers_are_not_guessed_into_an_expression():
    info = {"license": None, "classifiers": [
        "License :: OSI Approved :: MIT License",
        "License :: OSI Approved :: ISC License (ISCL)",
    ]}
    assert pypi.normalize_license(info) is None


def test_a_license_text_blob_is_never_emitted():
    # numpy: the BSD text itself, plus the classifier that does not say which BSD.
    assert pypi.normalize_license(_numpy_info()) is None


def test_a_short_non_spdx_declaration_is_kept_as_a_name():
    info = {"license": "Proprietary", "classifiers": []}
    assert pypi.normalize_license(info) == pypi.ResolvedLicense(
        "Proprietary", is_spdx=False
    )


def test_a_spdx_classifier_beats_a_free_text_name():
    info = {"license": "Dual licensed",
            "classifiers": ["License :: OSI Approved :: MIT License"]}
    assert pypi.normalize_license(info) == pypi.ResolvedLicense("MIT", is_spdx=True)


@pytest.mark.parametrize("junk", [
    "UNKNOWN", "unknown", "None", "n/a", "", "   ", "LICENSE", "LICENSE.txt",
    "See LICENSE file", "https://example.com/license", "Copyright 2020 Someone",
])
def test_placeholders_and_pointers_resolve_nothing(junk):
    assert pypi.normalize_license({"license": junk, "classifiers": []}) is None


def test_an_invalid_license_expression_falls_through_to_the_other_fields():
    info = {"license_expression": "MIT OR", "license": "Apache-2.0", "classifiers": []}
    assert pypi.normalize_license(info) == pypi.ResolvedLicense(
        "Apache-2.0", is_spdx=True
    )


def test_every_mapping_table_value_is_a_valid_spdx_id():
    # A typo in either table would ship a non-SPDX string flagged is_spdx=True,
    # which SPDX 2.3 output would then reject at write time.
    from cyclonedx import spdx

    for value in {*pypi._SPELLINGS.values(), *pypi._CLASSIFIERS.values()}:
        assert spdx.fixup_id(value) == value, value


@pytest.mark.parametrize("info", [None, [], "MIT", {"license": 42, "classifiers": "x"}])
def test_wrongly_typed_metadata_resolves_nothing(info):
    assert pypi.normalize_license(info) is None


# --------------------------------------------------------------------------
# Lookup — resolved, unknown, unreachable
# --------------------------------------------------------------------------

def test_resolved_license_is_written_onto_the_dependency():
    deps = [_dep("torch", "2.13.0"), _dep("transformers", "5.13.1")]
    result = _resolve(deps, FakePyPI([_torch_info(), _transformers_info()]))

    assert deps[0]["license"] == _torch_info()["license_expression"]
    assert deps[0]["license_is_spdx"] is True
    assert deps[0]["license_source"] == "pypi"
    assert deps[1]["license"] == "Apache-2.0"
    assert (result.queried, result.resolved, result.failed) == (2, 2, 0)
    assert result.error is None


def test_the_request_names_the_exact_pin_and_identifies_the_tool():
    fake = FakePyPI([_torch_info()])
    _resolve([_dep("torch", "2.13.0")], fake)
    assert fake.gets == ["https://pypi.org/pypi/torch/2.13.0/json"]
    assert fake.headers[0]["User-Agent"].startswith("aisbom-cli/")


def test_names_are_canonicalised_before_lookup():
    info = {"name": "ruamel-yaml", "version": "0.18.6", "license": "MIT",
            "classifiers": []}
    fake = FakePyPI([info])
    deps = [_dep("Ruamel.YAML", "0.18.6")]
    _resolve(deps, fake)
    assert fake.gets == ["https://pypi.org/pypi/ruamel-yaml/0.18.6/json"]
    assert deps[0]["license"] == "MIT"


def test_unknown_package_leaves_the_dependency_untouched():
    deps = [_dep("definitely-not-on-pypi", "1.0.0")]
    result = _resolve(deps, FakePyPI())
    assert "license" not in deps[0]
    assert (result.queried, result.resolved, result.failed) == (1, 0, 0)
    assert result.error is None


def test_a_package_declaring_no_usable_license_is_untouched():
    deps = [_dep("numpy", "1.26.4")]
    result = _resolve(deps, FakePyPI([_numpy_info()]))
    assert "license" not in deps[0]
    assert result.resolved == 0 and result.error is None


def test_unpinned_dependencies_are_skipped_and_counted():
    fake = FakePyPI([_torch_info()])
    deps = [_dep("torch", "2.0", pinned=False), _dep("torch", "2.13.0")]
    result = _resolve(deps, fake)
    assert "license" not in deps[0]
    assert deps[1]["license"]
    assert result.skipped_unpinned == 1 and result.queried == 1
    assert fake.calls == 1


def test_no_pinned_dependencies_makes_no_request():
    fake = FakePyPI()
    result = _resolve([_dep("torch", "2.0", pinned=False)], fake)
    assert fake.calls == 0 and result.queried == 0


def test_the_same_pin_listed_twice_is_fetched_once():
    fake = FakePyPI([_torch_info()])
    deps = [_dep("torch", "2.13.0"), _dep("torch", "2.13.0")]
    _resolve(deps, fake)
    assert fake.calls == 1
    assert deps[0]["license"] == deps[1]["license"]


@pytest.mark.parametrize("failure", [
    requests.ConnectionError("no route"),
    requests.Timeout("slow"),
])
def test_unreachable_pypi_degrades_to_no_license(failure):
    deps = [_dep("torch", "2.13.0"), _dep("transformers", "5.13.1")]
    result = _resolve(deps, FakePyPI(fail=failure))
    assert all("license" not in d for d in deps)
    assert result.failed == 2
    assert result.error and "PyPI" in result.error


@pytest.mark.parametrize("payload", [
    ValueError("not json"), [], {"info": "nope"}, {"no_info": {}},
])
def test_a_malformed_body_degrades_that_dependency(payload):
    fake = FakePyPI([_transformers_info()], payloads={("torch", "2.13.0"): payload})
    deps = [_dep("torch", "2.13.0"), _dep("transformers", "5.13.1")]
    result = _resolve(deps, fake)
    assert "license" not in deps[0]
    # One package's failure costs that package, not its neighbours: a license
    # on transformers says nothing about torch, unlike a partial CVE list.
    assert deps[1]["license"] == "Apache-2.0"
    assert result.failed == 1 and result.resolved == 1
    assert result.error


def test_a_transient_503_is_retried_and_resolves():
    fake = FakePyPI([_torch_info()], statuses={("torch", "2.13.0"): [503]})
    deps = [_dep("torch", "2.13.0")]
    result = _resolve(deps, fake)
    assert deps[0]["license"] and fake.calls == 2 and result.failed == 0


@pytest.mark.parametrize("status", [429, 500, 502, 504])
def test_other_transient_statuses_are_retried(status):
    fake = FakePyPI([_torch_info()], statuses={("torch", "2.13.0"): [status]})
    deps = [_dep("torch", "2.13.0")]
    _resolve(deps, fake)
    assert deps[0]["license"]


def test_a_persistent_503_degrades_after_bounded_attempts():
    fake = FakePyPI([_torch_info()], statuses={("torch", "2.13.0"): [503] * 10})
    result = _resolve([_dep("torch", "2.13.0")], fake)
    assert fake.calls == pypi._ATTEMPTS and result.failed == 1


def test_a_404_is_not_retried():
    fake = FakePyPI()
    _resolve([_dep("ghost", "1.0")], fake)
    assert fake.calls == 1


def test_an_exhausted_time_budget_degrades_without_raising():
    deps = [_dep("torch", "2.13.0")]
    result = _resolve(deps, FakePyPI([_torch_info()]), budget_seconds=0)
    assert "license" not in deps[0]
    assert result.failed == 1 and "time budget" in result.error


def test_unexpected_exception_is_contained():
    class Exploding:
        def get(self, *a, **kw):
            raise RuntimeError("boom")

    deps = [_dep("torch", "2.13.0")]
    result = _resolve(deps, Exploding())
    assert "license" not in deps[0] and result.failed == 1 and result.error


def test_the_default_session_pools_connections_for_every_worker():
    session = _REAL_DEFAULT_SESSION()
    adapter = session.get_adapter("https://pypi.org/")
    assert adapter._pool_maxsize == pypi._FETCH_WORKERS


def test_legal_status_is_never_written():
    deps = [_dep("torch", "2.13.0")]
    _resolve(deps, FakePyPI([_torch_info()]))
    assert "legal_status" not in deps[0]


# --------------------------------------------------------------------------
# Cache — repeat scans must not pay the network cost again
# --------------------------------------------------------------------------

def test_repeat_lookup_makes_no_network_call(tmp_path):
    first = FakePyPI([_torch_info()])
    _resolve([_dep("torch", "2.13.0")], first, cache_dir=tmp_path)
    assert first.calls == 1

    second = FakePyPI(fail=AssertionError("must not be called"))
    deps = [_dep("torch", "2.13.0")]
    result = _resolve(deps, second, cache_dir=tmp_path)
    assert second.calls == 0
    assert deps[0]["license"] == _torch_info()["license_expression"]
    assert result.resolved == 1 and result.error is None


def test_an_all_hit_lookup_does_not_rewrite_the_cache(tmp_path):
    import os

    _resolve([_dep("torch", "2.13.0")], FakePyPI([_torch_info()]), cache_dir=tmp_path)
    cache_file = tmp_path / pypi.CACHE_FILENAME
    os.utime(cache_file, (0, 0))
    _resolve([_dep("torch", "2.13.0")], FakePyPI(), cache_dir=tmp_path)
    assert cache_file.stat().st_mtime == 0


def test_a_cached_unknown_is_also_reused(tmp_path):
    _resolve([_dep("ghost", "1.0")], FakePyPI(), cache_dir=tmp_path)
    second = FakePyPI(fail=AssertionError("must not be called"))
    _resolve([_dep("ghost", "1.0")], second, cache_dir=tmp_path)
    assert second.calls == 0


def test_resolved_entries_outlive_unresolved_ones(tmp_path):
    now = time.time()
    _resolve([_dep("torch", "2.13.0"), _dep("ghost", "1.0")],
             FakePyPI([_torch_info()]), cache_dir=tmp_path, now=now)

    later = now + pypi.UNRESOLVED_TTL_SECONDS + 60
    fake = FakePyPI([_torch_info()])
    _resolve([_dep("torch", "2.13.0"), _dep("ghost", "1.0")],
             fake, cache_dir=tmp_path, now=later)
    assert fake.gets == ["https://pypi.org/pypi/ghost/1.0/json"]


def test_resolved_entries_expire_eventually(tmp_path):
    now = time.time()
    _resolve([_dep("torch", "2.13.0")], FakePyPI([_torch_info()]),
             cache_dir=tmp_path, now=now)
    fake = FakePyPI([_torch_info()])
    _resolve([_dep("torch", "2.13.0")], fake, cache_dir=tmp_path,
             now=now + pypi.RESOLVED_TTL_SECONDS + 60)
    assert fake.calls == 1


def test_a_failed_lookup_is_not_cached(tmp_path):
    _resolve([_dep("torch", "2.13.0")],
             FakePyPI(fail=requests.ConnectionError("down")), cache_dir=tmp_path)
    fake = FakePyPI([_torch_info()])
    deps = [_dep("torch", "2.13.0")]
    _resolve(deps, fake, cache_dir=tmp_path)
    assert fake.calls == 1 and deps[0]["license"]


def test_a_corrupt_cache_file_is_ignored(tmp_path):
    (tmp_path / pypi.CACHE_FILENAME).write_text("{not json")
    deps = [_dep("torch", "2.13.0")]
    _resolve(deps, FakePyPI([_torch_info()]), cache_dir=tmp_path)
    assert deps[0]["license"]


def test_a_cache_file_from_another_schema_is_ignored(tmp_path):
    (tmp_path / pypi.CACHE_FILENAME).write_text(json.dumps({
        "schema": 999,
        "entries": {"torch==2.13.0": {"fetched_at": time.time(),
                                      "license": "WRONG", "is_spdx": False}},
    }))
    deps = [_dep("torch", "2.13.0")]
    _resolve(deps, FakePyPI([_torch_info()]), cache_dir=tmp_path)
    assert deps[0]["license"] != "WRONG"


def test_a_tampered_cache_entry_is_refetched(tmp_path):
    (tmp_path / pypi.CACHE_FILENAME).write_text(json.dumps({
        "schema": pypi._CACHE_SCHEMA,
        "entries": {"torch==2.13.0": {"fetched_at": time.time(), "license": 7}},
    }))
    fake = FakePyPI([_torch_info()])
    deps = [_dep("torch", "2.13.0")]
    _resolve(deps, fake, cache_dir=tmp_path)
    assert fake.calls == 1 and deps[0]["license"]


def test_unwritable_cache_dir_still_resolves(tmp_path):
    blocked = tmp_path / "file-not-dir"
    blocked.write_text("")
    deps = [_dep("torch", "2.13.0")]
    result = _resolve(deps, FakePyPI([_torch_info()]), cache_dir=blocked)
    assert deps[0]["license"] and result.error is None


def test_default_cache_dir_is_the_aisbom_config_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("aisbom.telemetry.get_config_dir", lambda: tmp_path)
    _resolve([_dep("torch", "2.13.0")], FakePyPI([_torch_info()]),
             cache_dir=pypi._DEFAULT_CACHE_DIR)
    assert (tmp_path / pypi.CACHE_FILENAME).is_file()
