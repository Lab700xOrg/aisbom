"""CISA KEV lookup for `aisbom comply --framework fda`.

cisa.gov is never contacted from this suite. The catalogue below is a trimmed
copy of the real feed's shape (known_exploited_vulnerabilities.json).
"""

import json

import pytest
import requests

from aisbom import kev

# Captured at import, before conftest's autouse stub replaces it.
_REAL_DEFAULT_SESSION = kev._default_session

NOW = 1_800_000_000.0


def _catalogue(*entries):
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.11.25",
        "dateReleased": "2026-11-25T17:01:02.4123Z",
        "count": len(entries),
        "vulnerabilities": [
            {"cveID": cve, "vendorProject": "Example", "product": "Example",
             "dateAdded": added, "knownRansomwareCampaignUse": "Unknown"}
            for cve, added in entries
        ],
    }


DEFAULT = _catalogue(("CVE-2023-37920", "2024-01-10"), ("CVE-2021-44228", "2021-12-10"))


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeCisa:
    def __init__(self, payload=DEFAULT, fail=None, status=200):
        self.payload = payload
        self.fail = fail
        self.status = status
        self.gets = []

    def get(self, url, timeout=None, headers=None):
        assert timeout and timeout > 0
        assert headers and headers["User-Agent"].startswith("aisbom-cli/")
        self.gets.append(url)
        if self.fail:
            raise self.fail
        return FakeResponse(self.payload, self.status)


def _lookup(ids, session, cache_dir=None, now=NOW, **kw):
    return kev.lookup_known_exploited(ids, session=session, cache_dir=cache_dir,
                                      now=now, **kw)


# -- matching ---------------------------------------------------------------

def test_a_cve_in_the_catalogue_carries_its_date_added():
    result = _lookup(["CVE-2023-37920"], FakeCisa())
    assert result.added == {"CVE-2023-37920": "2024-01-10"}
    assert result.catalog_version == "2026.11.25"
    assert result.error is None


def test_a_cve_absent_from_the_catalogue_is_unmarked():
    result = _lookup(["CVE-2099-0001"], FakeCisa())
    assert result.added == {}
    assert result.error is None
    assert result.catalog_version == "2026.11.25"


def test_only_the_cves_asked_about_are_returned():
    result = _lookup(["CVE-2021-44228"], FakeCisa())
    assert result.added == {"CVE-2021-44228": "2021-12-10"}


def test_matching_ignores_case_and_surrounding_space():
    result = _lookup([" cve-2023-37920 "], FakeCisa())
    assert result.added == {"CVE-2023-37920": "2024-01-10"}


def test_non_cve_ids_are_not_looked_up_and_make_no_request():
    fake = FakeCisa()
    result = _lookup(["GHSA-xqr8-7jwr-rhp7", "PYSEC-2023-135"], fake)
    assert result.added == {}
    assert fake.gets == []
    assert result.catalog_version is None


def test_no_ids_makes_no_request():
    fake = FakeCisa()
    result = _lookup([], fake)
    assert fake.gets == [] and result.added == {} and result.error is None


def test_the_whole_catalogue_is_fetched_and_no_cve_leaves_the_machine():
    fake = FakeCisa()
    _lookup(["CVE-2023-37920"], fake)
    assert fake.gets == [kev.KEV_URL]
    assert "CVE" not in fake.gets[0]


def test_malformed_entries_are_skipped():
    payload = _catalogue(("CVE-2023-37920", "2024-01-10"))
    payload["vulnerabilities"] += [
        {"cveID": "CVE-2020-0001", "dateAdded": "not a date"},
        {"cveID": 42, "dateAdded": "2020-01-01"},
        "junk",
    ]
    result = _lookup(["CVE-2023-37920", "CVE-2020-0001"], FakeCisa(payload))
    assert result.added == {"CVE-2023-37920": "2024-01-10"}


# -- failure is enrichment lost, never the run --------------------------------

@pytest.mark.parametrize("fake", [
    FakeCisa(fail=requests.ConnectionError("down")),
    FakeCisa(fail=requests.Timeout("slow")),
    FakeCisa(status=503),
    FakeCisa(payload=ValueError("not json")),
    FakeCisa(payload={"title": "no vulnerabilities key"}),
    FakeCisa(payload=["not", "a", "dict"]),
])
def test_a_failed_fetch_returns_no_answers_and_an_error(fake):
    result = _lookup(["CVE-2023-37920"], fake)
    assert result.added == {}
    assert result.catalog_version is None
    assert result.error and "CISA KEV" in result.error


def test_an_unexpected_exception_does_not_escape():
    class Broken:
        def get(self, *a, **kw):
            raise RuntimeError("boom")

    result = _lookup(["CVE-2023-37920"], Broken())
    assert result.error and "RuntimeError" in result.error


def test_disabled_by_env():
    assert kev.disabled_by_env({"AISBOM_NO_KEV_LOOKUP": "1"})
    assert not kev.disabled_by_env({})


def test_default_session_is_a_requests_session():
    assert isinstance(_REAL_DEFAULT_SESSION(), requests.Session)


# -- cache --------------------------------------------------------------------

def test_a_fresh_cache_makes_no_request(tmp_path):
    _lookup(["CVE-2023-37920"], FakeCisa(), cache_dir=tmp_path)
    second = FakeCisa(fail=AssertionError("must not fetch"))
    result = _lookup(["CVE-2023-37920"], second, cache_dir=tmp_path, now=NOW + 3600)
    assert second.gets == []
    assert result.added == {"CVE-2023-37920": "2024-01-10"}
    assert result.catalog_version == "2026.11.25"


def test_a_stale_cache_is_refetched(tmp_path):
    _lookup(["CVE-2023-37920"], FakeCisa(), cache_dir=tmp_path)
    newer = FakeCisa(_catalogue(("CVE-2023-37920", "2024-01-10"),
                                ("CVE-2025-0002", "2025-06-01")))
    result = _lookup(["CVE-2025-0002"], newer, cache_dir=tmp_path,
                     now=NOW + kev.CACHE_TTL_SECONDS + 1)
    assert newer.gets == [kev.KEV_URL]
    assert result.added == {"CVE-2025-0002": "2025-06-01"}


def test_the_cache_ttl_is_24_hours():
    assert kev.CACHE_TTL_SECONDS == 24 * 60 * 60


def test_a_stale_cache_is_not_used_when_the_refetch_fails(tmp_path):
    _lookup(["CVE-2023-37920"], FakeCisa(), cache_dir=tmp_path)
    result = _lookup(["CVE-2023-37920"], FakeCisa(fail=requests.ConnectionError()),
                     cache_dir=tmp_path, now=NOW + kev.CACHE_TTL_SECONDS + 1)
    assert result.added == {} and result.error


@pytest.mark.parametrize("content", [
    "not json",
    json.dumps({"schema": 999}),
    json.dumps({"schema": 1, "fetched_at": "x", "added": {}}),
    json.dumps({"schema": 1, "fetched_at": NOW, "added": "x"}),
])
def test_an_unusable_cache_file_is_ignored(tmp_path, content):
    (tmp_path / kev.CACHE_FILENAME).write_text(content)
    fake = FakeCisa()
    result = _lookup(["CVE-2023-37920"], fake, cache_dir=tmp_path)
    assert fake.gets == [kev.KEV_URL]
    assert result.added == {"CVE-2023-37920": "2024-01-10"}


def test_the_cache_holds_only_ids_and_dates(tmp_path):
    _lookup(["CVE-2023-37920"], FakeCisa(), cache_dir=tmp_path)
    data = json.loads((tmp_path / kev.CACHE_FILENAME).read_text())
    assert data["added"] == {"CVE-2023-37920": "2024-01-10",
                             "CVE-2021-44228": "2021-12-10"}
    assert set(data) == {"schema", "fetched_at", "catalog_version", "added"}


def test_an_unwritable_cache_dir_is_not_an_error(tmp_path):
    missing = tmp_path / "does" / "not" / "exist"
    result = _lookup(["CVE-2023-37920"], FakeCisa(), cache_dir=missing)
    assert result.added == {"CVE-2023-37920": "2024-01-10"}
    assert result.error is None


def test_a_failed_fetch_writes_no_cache(tmp_path):
    _lookup(["CVE-2023-37920"], FakeCisa(status=500), cache_dir=tmp_path)
    assert not (tmp_path / kev.CACHE_FILENAME).exists()


def test_default_cache_dir_is_the_cli_config_dir(monkeypatch, tmp_path):
    monkeypatch.setattr("aisbom.telemetry.get_config_dir", lambda: tmp_path)
    kev.lookup_known_exploited(["CVE-2023-37920"], session=FakeCisa(), now=NOW)
    assert (tmp_path / kev.CACHE_FILENAME).exists()
