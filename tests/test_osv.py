"""OSV lookup for pinned requirements.txt dependencies — CVE-keyed VEX (#128).

The OSV API is never contacted from this suite. Every test drives a fake
session whose responses are shaped like real api.osv.dev payloads, so hit,
miss, malformed, failure, pagination and cache reuse are all exercised
deterministically and offline.
"""

import json
import time
from pathlib import Path

import pytest
import requests
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from jsonschema import Draft202012Validator

from aisbom import osv
from aisbom.vex import generate_cyclonedx_vex, generate_openvex

_REAL_DEFAULT_SESSION = osv._default_session


@pytest.fixture(autouse=True)
def _no_retry_pause(monkeypatch):
    """Retries are exercised here; their real-time backoff is not."""
    monkeypatch.setattr(osv, "_BACKOFF_SECONDS", 0)

SERIAL = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
_OPENVEX_SCHEMA = Path(__file__).parent / "schemas" / "openvex-0.2.0.schema.json"


# --------------------------------------------------------------------------
# Real OSV record shapes (trimmed to the fields AIsbom reads)
# --------------------------------------------------------------------------

def _requests_advisory():
    """GHSA-x84v-xcm2-53pg as OSV serves it: a GHSA id with a CVE alias."""
    return {
        "id": "GHSA-x84v-xcm2-53pg",
        "summary": "Insufficiently Protected Credentials in Requests",
        "details": "The Requests package before 2.20.0 sends an HTTP "
                   "Authorization header to an http URI upon receiving a "
                   "same-hostname https-to-http redirect.",
        "aliases": ["CVE-2018-18074"],
        "modified": "2024-09-26T20:11:51Z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests",
                            "purl": "pkg:pypi/requests"},
                "ranges": [
                    {"type": "ECOSYSTEM",
                     "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}
                ],
            }
        ],
    }


def _pysec_twin():
    """PYSEC-2018-28 — the same CVE published under a second OSV id."""
    return {
        "id": "PYSEC-2018-28",
        "details": "The Requests package before 2.20.0 ...",
        "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
        "modified": "2021-06-10T06:51:37Z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [
                    {"type": "ECOSYSTEM",
                     "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}
                ],
                "versions": ["2.19.0", "2.19.1"],
            }
        ],
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


class FakeOSV:
    """A stand-in for api.osv.dev that records every call made to it."""

    def __init__(self, records=(), matches=None, fail=None, batch_payload=None,
                 pages=None):
        self.records = {r["id"]: r for r in records}
        # {(name, version): [ids]} — what querybatch reports as matching.
        self.matches = matches or {}
        self.fail = fail
        self.batch_payload = batch_payload
        self.pages = pages or {}
        self.posts = []
        self.gets = []

    def post(self, url, json=None, timeout=None, headers=None):
        self.posts.append(json)
        if self.fail:
            raise self.fail
        if self.batch_payload is not None:
            return FakeResponse(self.batch_payload)
        results = []
        for query in json["queries"]:
            token = query.get("page_token")
            key = (query["package"]["name"], query["version"])
            if token:
                ids = self.pages[token]
                results.append({"vulns": [{"id": i} for i in ids]})
                continue
            ids = self.matches.get(key, [])
            entry = {"vulns": [{"id": i} for i in ids]} if ids else {}
            if key in self.pages:
                entry["next_page_token"] = f"tok-{key[0]}"
            results.append(entry)
        return FakeResponse({"results": results})

    def get(self, url, timeout=None, headers=None):
        self.gets.append(url)
        if self.fail:
            raise self.fail
        vuln_id = url.rsplit("/", 1)[-1]
        if vuln_id not in self.records:
            return FakeResponse({"code": 5, "message": "Bug not found"}, 404)
        return FakeResponse(self.records[vuln_id])

    @property
    def calls(self):
        return len(self.posts) + len(self.gets)


def _dep(name, version, pinned=True):
    return {"name": name, "version": version, "type": "library", "pinned": pinned}


def _lookup(deps, session, cache_dir=None, **kw):
    return osv.lookup_dependency_statements(
        deps, session=session, cache_dir=cache_dir, **kw
    )


# --------------------------------------------------------------------------
# Version-range matching — the part that must not be wrong in either direction
# --------------------------------------------------------------------------

def _range_record(events, name="demo-pkg", versions=None, ecosystem="PyPI",
                  range_type="ECOSYSTEM"):
    affected = {"package": {"ecosystem": ecosystem, "name": name},
                "ranges": [{"type": range_type, "events": events}]}
    if versions is not None:
        affected["versions"] = versions
    return {"id": "GHSA-demo", "affected": [affected]}


@pytest.mark.parametrize("version, expected", [
    ("2.2.9", False),     # just below introduced
    ("2.3.0", True),      # exactly at introduced
    ("2.19.1", True),     # inside
    ("2.20.0rc1", True),  # a pre-release of the fix is still before it
    ("2.20.0", False),    # exactly at fixed
    ("2.20.1", False),    # after fixed
])
def test_introduced_fixed_boundaries(version, expected):
    record = _range_record([{"introduced": "2.3.0"}, {"fixed": "2.20.0"}])
    assert osv.version_affected(record, "demo-pkg", version) is expected


@pytest.mark.parametrize("version, expected", [
    ("1.4.2", True),   # exactly at last_affected is still affected
    ("1.4.3", False),  # one past it is not
    ("0.9", True),
])
def test_last_affected_is_inclusive(version, expected):
    record = _range_record([{"introduced": "0"}, {"last_affected": "1.4.2"}])
    assert osv.version_affected(record, "demo-pkg", version) is expected


@pytest.mark.parametrize("version, expected", [
    ("1.0", True), ("1.7", False), ("2.1", True), ("2.2", False), ("0.5", False),
])
def test_disjoint_ranges_leave_the_gap_unaffected(version, expected):
    record = _range_record([
        {"introduced": "1.0"}, {"fixed": "1.5"},
        {"introduced": "2.0"}, {"fixed": "2.2"},
    ])
    assert osv.version_affected(record, "demo-pkg", version) is expected


def test_events_are_evaluated_in_version_order_not_listed_order():
    record = _range_record([{"fixed": "1.5"}, {"introduced": "1.0"}])
    assert osv.version_affected(record, "demo-pkg", "1.2") is True
    assert osv.version_affected(record, "demo-pkg", "1.5") is False


@pytest.mark.parametrize("version", ["0.dev0", "0rc1", "0a1", "0"])
def test_introduced_zero_covers_prereleases_below_release_zero(version):
    """OSV's "0" means "from the first version", not PEP 440's release 0."""
    record = _range_record([{"introduced": "0"}, {"fixed": "2.0"}])
    assert osv.version_affected(record, "demo-pkg", version) is True


def test_introduced_zero_with_no_fix_affects_every_version():
    record = _range_record([{"introduced": "0"}])
    assert osv.version_affected(record, "demo-pkg", "99.0") is True


def test_explicit_versions_list_matches_without_ranges():
    record = {"id": "PYSEC-demo", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "demo-pkg"},
         "versions": ["1.0.0", "1.0.1"]}
    ]}
    assert osv.version_affected(record, "demo-pkg", "1.0.1") is True
    # PEP 440 equality, not string equality.
    assert osv.version_affected(record, "demo-pkg", "1.0.1.0") is True
    assert osv.version_affected(record, "demo-pkg", "1.0.2") is False


def test_package_names_compare_canonically():
    record = _range_record([{"introduced": "0"}, {"fixed": "2.0"}],
                           name="Demo_Pkg")
    assert osv.version_affected(record, "demo.pkg", "1.0") is True


def test_an_entry_for_a_different_package_never_matches():
    record = _range_record([{"introduced": "0"}], name="requests-toolbelt")
    assert osv.version_affected(record, "requests", "1.0") is None


def test_a_non_pypi_entry_is_not_evaluated():
    record = _range_record([{"introduced": "0"}], ecosystem="npm")
    assert osv.version_affected(record, "demo-pkg", "1.0") is None


def test_git_ranges_cannot_be_evaluated_locally():
    record = _range_record([{"introduced": "abc123"}], range_type="GIT")
    assert osv.version_affected(record, "demo-pkg", "1.0") is None


def test_an_unparseable_pin_is_undetermined_rather_than_clean():
    record = _range_record([{"introduced": "0"}, {"fixed": "2.0"}])
    assert osv.version_affected(record, "demo-pkg", "not-a-version") is None


def test_an_unparseable_event_version_is_undetermined():
    record = _range_record([{"introduced": "garbage!"}, {"fixed": "2.0"}])
    assert osv.version_affected(record, "demo-pkg", "1.0") is None


# --------------------------------------------------------------------------
# Identifiers
# --------------------------------------------------------------------------

def test_cve_alias_becomes_the_primary_identifier():
    primary, aliases = osv.vulnerability_ids(_requests_advisory())
    assert primary == "CVE-2018-18074"
    assert aliases == ("GHSA-x84v-xcm2-53pg",)


def test_advisory_without_cve_keeps_its_osv_id():
    record = {"id": "GHSA-abcd-efgh-ijkl", "aliases": ["PYSEC-2024-1"]}
    primary, aliases = osv.vulnerability_ids(record)
    assert primary == "GHSA-abcd-efgh-ijkl"
    assert aliases == ("PYSEC-2024-1",)


# --------------------------------------------------------------------------
# Lookup — hit, miss, dedupe, pins
# --------------------------------------------------------------------------

def test_hit_produces_an_affected_cve_statement():
    fake = FakeOSV([_requests_advisory()],
                   matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})
    result = _lookup([_dep("requests", "2.19.0")], fake)

    assert result.error is None
    [stmt] = result.statements
    assert stmt.finding_class.id == "CVE-2018-18074"
    assert stmt.status == "affected"
    assert stmt.product_ref == "dependency-0-requests"
    assert stmt.justification is None
    assert "2.20.0" in stmt.action_statement
    assert stmt.finding_class.aliases == ("GHSA-x84v-xcm2-53pg",)
    assert stmt.finding_class.iri == "https://osv.dev/vulnerability/GHSA-x84v-xcm2-53pg"
    assert stmt.finding_class.source_name == "OSV"


def test_miss_produces_no_statement_and_no_negative_claim():
    fake = FakeOSV(matches={})
    result = _lookup([_dep("requests", "2.32.3")], fake)
    assert result.error is None
    assert result.statements == []
    assert result.queried == 1
    assert fake.gets == []


def test_twin_records_for_one_cve_yield_one_statement():
    fake = FakeOSV(
        [_requests_advisory(), _pysec_twin()],
        matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"]},
    )
    result = _lookup([_dep("requests", "2.19.0")], fake)
    [stmt] = result.statements
    assert stmt.finding_class.id == "CVE-2018-18074"
    assert set(stmt.finding_class.aliases) == {"GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"}


def test_unpinned_dependencies_are_skipped_and_counted():
    fake = FakeOSV()
    result = _lookup([_dep("torch", "2.0", pinned=False),
                      _dep("numpy", "unknown", pinned=False)], fake)
    assert result.statements == []
    assert result.skipped_unpinned == 2
    assert result.queried == 0
    assert fake.calls == 0


def test_dependency_refs_follow_the_dependency_index():
    fake = FakeOSV([_requests_advisory()],
                   matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})
    deps = [_dep("torch", "2.1.0"), _dep("requests", "2.19.0")]
    result = _lookup(deps, fake)
    assert [s.product_ref for s in result.statements] == ["dependency-1-requests"]


def test_osv_match_the_local_check_rejects_is_under_investigation():
    """OSV and the range check disagree: never a silent drop, never `affected`."""
    record = _requests_advisory()
    record["affected"][0]["ranges"][0]["events"] = [
        {"introduced": "0"}, {"fixed": "2.0.0"}
    ]
    fake = FakeOSV([record],
                   matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})
    [stmt] = _lookup([_dep("requests", "2.19.0")], fake).statements
    assert stmt.status == "under_investigation"
    assert stmt.action_statement is None


def test_osv_match_the_local_check_cannot_evaluate_is_under_investigation():
    record = _requests_advisory()
    record["affected"][0]["ranges"][0]["type"] = "GIT"
    fake = FakeOSV([record],
                   matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})
    [stmt] = _lookup([_dep("requests", "2.19.0")], fake).statements
    assert stmt.status == "under_investigation"


def test_affected_wins_when_twin_records_disagree():
    twin = _pysec_twin()
    twin["affected"][0]["ranges"][0]["type"] = "GIT"
    twin["affected"][0].pop("versions")
    fake = FakeOSV(
        [_requests_advisory(), twin],
        matches={("requests", "2.19.0"): ["PYSEC-2018-28", "GHSA-x84v-xcm2-53pg"]},
    )
    [stmt] = _lookup([_dep("requests", "2.19.0")], fake).statements
    assert stmt.status == "affected"


def test_withdrawn_advisories_are_skipped():
    record = _requests_advisory()
    record["withdrawn"] = "2024-01-01T00:00:00Z"
    fake = FakeOSV([record],
                   matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})
    assert _lookup([_dep("requests", "2.19.0")], fake).statements == []


def test_action_names_only_the_fix_that_closes_the_pinned_interval():
    """An older interval's fix is not an upgrade target (disjoint ranges)."""
    record = _requests_advisory()
    record["affected"][0]["ranges"][0]["events"] = [
        {"introduced": "1.0"}, {"fixed": "1.5"},
        {"introduced": "2.0"}, {"fixed": "2.2"},
    ]
    fake = FakeOSV([record],
                   matches={("requests", "2.1"): ["GHSA-x84v-xcm2-53pg"]})
    [stmt] = _lookup([_dep("requests", "2.1")], fake).statements
    assert stmt.status == "affected"
    assert "fixed in: 2.2)" in stmt.action_statement
    assert "1.5" not in stmt.action_statement


def test_action_offers_no_fix_when_the_pinned_interval_is_unfixed():
    record = _requests_advisory()
    record["affected"][0]["ranges"][0]["events"] = [
        {"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"},
    ]
    fake = FakeOSV([record],
                   matches={("requests", "2.1"): ["GHSA-x84v-xcm2-53pg"]})
    [stmt] = _lookup([_dep("requests", "2.1")], fake).statements
    assert "No fixed version" in stmt.action_statement


def test_a_fix_spelled_two_ways_is_listed_once():
    twin = _pysec_twin()
    twin["affected"][0]["ranges"][0]["events"][1] = {"fixed": "2.20"}
    fake = FakeOSV(
        [_requests_advisory(), twin],
        matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"]},
    )
    [stmt] = _lookup([_dep("requests", "2.19.0")], fake).statements
    assert "(fixed in: 2.20.0)" in stmt.action_statement


def test_a_fix_after_last_affected_is_not_the_pinned_intervals_fix():
    record = _range_record([
        {"introduced": "0"}, {"last_affected": "1.4"},
        {"introduced": "2.0"}, {"fixed": "2.5"},
    ])
    events = record["affected"][0]["ranges"][0]["events"]
    assert osv._closing_fix(events, osv.Version("1.2")) is None
    assert osv._closing_fix(events, osv.Version("2.1")) == "2.5"
    assert osv._closing_fix(events, osv.Version("1.8")) is None


def test_twin_records_contribute_one_fix_per_interval():
    twin = _pysec_twin()
    fake = FakeOSV(
        [_requests_advisory(), twin],
        matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"]},
    )
    [stmt] = _lookup([_dep("requests", "2.19.0")], fake).statements
    assert "(fixed in: 2.20.0)" in stmt.action_statement


def test_no_fixed_version_gets_an_honest_action():
    record = _requests_advisory()
    record["affected"][0]["ranges"][0]["events"] = [{"introduced": "0"}]
    fake = FakeOSV([record],
                   matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})
    [stmt] = _lookup([_dep("requests", "2.19.0")], fake).statements
    assert "No fixed version" in stmt.action_statement


def test_query_uses_canonical_name_and_pypi_ecosystem():
    fake = FakeOSV()
    _lookup([_dep("Scikit_Learn", "1.0.0")], fake)
    [query] = fake.posts[0]["queries"]
    assert query == {"package": {"name": "scikit-learn", "ecosystem": "PyPI"},
                     "version": "1.0.0"}


def test_paginated_querybatch_results_are_followed():
    fake = FakeOSV(
        [_requests_advisory(), _pysec_twin()],
        matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]},
        pages={("requests", "2.19.0"): True, "tok-requests": ["PYSEC-2018-28"]},
    )
    [stmt] = _lookup([_dep("requests", "2.19.0")], fake).statements
    assert len(fake.posts) == 2
    assert fake.posts[1]["queries"][0]["page_token"] == "tok-requests"
    assert "PYSEC-2018-28" in stmt.finding_class.aliases


# --------------------------------------------------------------------------
# Degradation — never a changed exit code, never a lost model finding
# --------------------------------------------------------------------------

@pytest.mark.parametrize("failure", [
    requests.ConnectionError("no route to host"),
    requests.Timeout("read timed out"),
])
def test_network_failure_degrades_to_no_statements(failure):
    fake = FakeOSV(fail=failure)
    result = _lookup([_dep("requests", "2.19.0")], fake)
    assert result.statements == []
    assert result.error


@pytest.mark.parametrize("payload", [
    ValueError("not json"),
    ["not", "an", "object"],
    {"results": "nope"},
    {"results": []},                       # wrong length
    {"results": [{"vulns": [{"no": "id"}]}]},
])
def test_malformed_querybatch_degrades_to_no_statements(payload):
    fake = FakeOSV(batch_payload=payload)
    result = _lookup([_dep("requests", "2.19.0")], fake)
    assert result.statements == []
    assert result.error


def test_a_record_that_is_not_the_one_asked_for_degrades():
    """A proxy or cache returning the wrong body must not become a statement."""
    wrong = _requests_advisory()
    wrong["id"] = "GHSA-something-else"
    fake = FakeOSV(matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})
    fake.records["GHSA-x84v-xcm2-53pg"] = wrong
    result = _lookup([_dep("requests", "2.19.0")], fake)
    assert result.statements == []
    assert result.error


def test_a_non_object_querybatch_result_degrades():
    fake = FakeOSV(batch_payload={"results": ["not-an-object"]})
    result = _lookup([_dep("requests", "2.19.0")], fake)
    assert result.statements == []
    assert result.error


def test_pagination_that_never_ends_degrades():
    class Endless:
        posts = 0

        def post(self, url, json=None, timeout=None, headers=None):
            Endless.posts += 1
            return FakeResponse({"results": [
                {"vulns": [{"id": "GHSA-x"}], "next_page_token": "again"}
            ]})

    result = _lookup([_dep("requests", "2.19.0")], Endless())
    assert result.statements == []
    assert "pagination" in result.error
    assert Endless.posts == osv._MAX_PAGES


def test_an_unparseable_listed_version_is_skipped_not_fatal():
    record = {"id": "PYSEC-demo", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "demo-pkg"},
         "versions": ["not a version", "1.0.1"]}
    ]}
    assert osv.version_affected(record, "demo-pkg", "1.0.1") is True


def test_a_cache_file_from_another_schema_is_ignored(tmp_path):
    (tmp_path / osv.CACHE_FILENAME).write_text(json.dumps({"schema": 999}))
    fake = _hit_fake()
    _lookup([_dep("requests", "2.19.0")], fake, cache_dir=tmp_path)
    assert fake.calls == 2


def _many_advisories(count):
    records = []
    for n in range(count):
        record = _requests_advisory()
        record["id"] = f"GHSA-many-{n:04d}"
        record["aliases"] = [f"CVE-2099-{n:05d}"]
        records.append(record)
    return records


def test_a_pin_with_many_advisories_gets_every_statement():
    """Real pins name 100+ advisories; all must land, in a stable order."""
    records = _many_advisories(140)
    fake = FakeOSV(records, matches={("requests", "2.19.0"): [r["id"] for r in records]})
    result = _lookup([_dep("requests", "2.19.0")], fake)
    assert result.error is None
    assert len(fake.gets) == 140
    assert [s.finding_class.id for s in result.statements] == \
           sorted(f"CVE-2099-{n:05d}" for n in range(140))


def test_one_failed_record_among_many_degrades_the_whole_lookup():
    records = _many_advisories(40)
    ids = [r["id"] for r in records]
    fake = FakeOSV(records[:-1], matches={("requests", "2.19.0"): ids})
    result = _lookup([_dep("requests", "2.19.0")], fake)
    assert result.statements == []
    assert result.error


def test_the_default_session_pools_connections_for_every_worker():
    # Bound at import, before conftest swaps the module attribute out.
    session = _REAL_DEFAULT_SESSION()
    assert isinstance(session, requests.Session)
    adapter = session.get_adapter("https://api.osv.dev/v1/querybatch")
    assert adapter._pool_maxsize == osv._FETCH_WORKERS


class FlakyOSV(FakeOSV):
    """Answers the first `flakes` record requests with `status`, then normally."""

    def __init__(self, *args, flakes=1, status=503, **kwargs):
        super().__init__(*args, **kwargs)
        self.flakes = flakes
        self.status = status

    def get(self, url, timeout=None, headers=None):
        if self.flakes:
            self.flakes -= 1
            self.gets.append(url)
            return FakeResponse("<html>503 Server Error</html>", self.status)
        return super().get(url, timeout=timeout, headers=headers)


def test_a_transient_503_is_retried_and_the_lookup_succeeds():
    """Observed live: one 503 in 140 record fetches must not cost every statement."""
    fake = FlakyOSV([_requests_advisory()],
                    matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})
    result = _lookup([_dep("requests", "2.19.0")], fake)
    assert result.error is None
    assert len(result.statements) == 1
    assert len(fake.gets) == 2


@pytest.mark.parametrize("status", [429, 500, 502, 504])
def test_other_transient_statuses_are_retried(status):
    fake = FlakyOSV([_requests_advisory()], status=status,
                    matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})
    assert len(_lookup([_dep("requests", "2.19.0")], fake).statements) == 1


def test_a_persistent_503_degrades_after_bounded_attempts():
    fake = FlakyOSV([_requests_advisory()], flakes=99,
                    matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})
    result = _lookup([_dep("requests", "2.19.0")], fake)
    assert result.statements == []
    assert result.error
    assert len(fake.gets) == osv._ATTEMPTS


def test_a_404_is_not_retried():
    fake = FakeOSV([], matches={("requests", "2.19.0"): ["GHSA-gone"]})
    _lookup([_dep("requests", "2.19.0")], fake)
    assert len(fake.gets) == 1


def test_a_connection_error_is_retried():
    class DropsFirst(FakeOSV):
        dropped = False

        def post(self, url, json=None, timeout=None, headers=None):
            if not self.dropped:
                self.dropped = True
                raise requests.ConnectionError("reset by peer")
            return super().post(url, json=json, timeout=timeout, headers=headers)

    fake = DropsFirst([_requests_advisory()],
                      matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})
    assert len(_lookup([_dep("requests", "2.19.0")], fake).statements) == 1


def test_a_retry_pause_that_would_overrun_the_budget_degrades(monkeypatch):
    monkeypatch.setattr(osv, "_BACKOFF_SECONDS", 3600)
    fake = FlakyOSV([_requests_advisory()],
                    matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})
    result = _lookup([_dep("requests", "2.19.0")], fake)
    assert result.statements == []
    assert "time budget" in result.error


def test_a_missing_vulnerability_record_degrades_the_whole_lookup():
    fake = FakeOSV([], matches={("requests", "2.19.0"): ["GHSA-gone"]})
    result = _lookup([_dep("requests", "2.19.0")], fake)
    assert result.statements == []
    assert result.error


def test_an_exhausted_time_budget_degrades(monkeypatch):
    fake = FakeOSV([_requests_advisory()],
                   matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})
    result = _lookup([_dep("requests", "2.19.0")], fake, budget_seconds=0)
    assert result.statements == []
    assert result.error
    assert fake.calls == 0


def test_unexpected_exception_is_contained():
    class Exploding:
        def post(self, *a, **kw):
            raise RuntimeError("boom")
    result = _lookup([_dep("requests", "2.19.0")], Exploding())
    assert result.statements == []
    assert result.error


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------

def _hit_fake():
    return FakeOSV([_requests_advisory()],
                   matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})


def test_repeat_lookup_makes_no_network_call(tmp_path):
    first = _hit_fake()
    r1 = _lookup([_dep("requests", "2.19.0")], first, cache_dir=tmp_path)
    assert first.calls == 2

    second = _hit_fake()
    r2 = _lookup([_dep("requests", "2.19.0")], second, cache_dir=tmp_path)
    assert second.calls == 0
    assert [s.finding_class.id for s in r2.statements] == \
           [s.finding_class.id for s in r1.statements]


def test_a_cached_miss_is_also_reused(tmp_path):
    _lookup([_dep("requests", "2.32.3")], FakeOSV(), cache_dir=tmp_path)
    second = FakeOSV()
    _lookup([_dep("requests", "2.32.3")], second, cache_dir=tmp_path)
    assert second.calls == 0


def test_only_the_uncached_pin_is_queried(tmp_path):
    _lookup([_dep("requests", "2.19.0")], _hit_fake(), cache_dir=tmp_path)
    second = _hit_fake()
    _lookup([_dep("requests", "2.19.0"), _dep("flask", "3.0.0")], second,
            cache_dir=tmp_path)
    assert [q["package"]["name"] for q in second.posts[0]["queries"]] == ["flask"]
    assert second.gets == []


def test_stale_cache_entries_are_refetched(tmp_path):
    _lookup([_dep("requests", "2.19.0")], _hit_fake(), cache_dir=tmp_path,
            now=time.time() - osv.CACHE_TTL_SECONDS - 60)
    second = _hit_fake()
    _lookup([_dep("requests", "2.19.0")], second, cache_dir=tmp_path)
    assert second.calls == 2


def test_a_corrupt_cache_file_is_ignored(tmp_path):
    (tmp_path / osv.CACHE_FILENAME).write_text("{not json")
    fake = _hit_fake()
    result = _lookup([_dep("requests", "2.19.0")], fake, cache_dir=tmp_path)
    assert len(result.statements) == 1
    assert fake.calls == 2


def test_a_failed_lookup_does_not_poison_the_cache(tmp_path):
    _lookup([_dep("requests", "2.19.0")],
            FakeOSV(fail=requests.ConnectionError("down")), cache_dir=tmp_path)
    fake = _hit_fake()
    result = _lookup([_dep("requests", "2.19.0")], fake, cache_dir=tmp_path)
    assert len(result.statements) == 1
    assert fake.calls == 2


def test_unwritable_cache_dir_still_returns_results(tmp_path):
    missing = tmp_path / "does-not-exist" / "nested"
    fake = _hit_fake()
    result = _lookup([_dep("requests", "2.19.0")], fake, cache_dir=missing)
    assert len(result.statements) == 1


# --------------------------------------------------------------------------
# Emitted documents
# --------------------------------------------------------------------------

def test_cve_statements_validate_in_both_flavors():
    fake = FakeOSV([_requests_advisory()],
                   matches={("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"]})
    statements = _lookup([_dep("requests", "2.19.0")], fake).statements

    with _OPENVEX_SCHEMA.open() as fh:
        Draft202012Validator(json.load(fh)).validate(
            json.loads(generate_openvex(statements, sbom_serial=SERIAL))
        )
    ovex = json.loads(generate_openvex(statements, sbom_serial=SERIAL))
    vuln = ovex["statements"][0]["vulnerability"]
    assert vuln["name"] == "CVE-2018-18074"
    assert vuln["@id"] == "https://osv.dev/vulnerability/GHSA-x84v-xcm2-53pg"
    assert vuln["aliases"] == ["GHSA-x84v-xcm2-53pg"]

    cdx_json = generate_cyclonedx_vex(statements, sbom_serial=SERIAL)
    assert JsonStrictValidator(SchemaVersion.V1_7).validate_str(cdx_json) is None
    entry = json.loads(cdx_json)["vulnerabilities"][0]
    assert entry["id"] == "CVE-2018-18074"
    assert entry["source"] == {
        "name": "OSV",
        "url": "https://osv.dev/vulnerability/GHSA-x84v-xcm2-53pg",
    }
    assert entry["references"] == [
        {"id": "GHSA-x84v-xcm2-53pg",
         "source": {"name": "GitHub Advisory Database"}}
    ]


# --------------------------------------------------------------------------
# Pin detection in the scanner
# --------------------------------------------------------------------------

@pytest.mark.parametrize("line, pinned", [
    ("requests==2.19.0", True),
    ("requests===2.19.0", True),
    ("requests == 2.19.0 ; python_version >= '3.8'", True),
    ("requests>=2.19.0", False),
    ("requests~=2.19.0", False),
    ("requests==2.*", False),
    ("requests>=2.0,<3", False),
    ("requests", False),
])
def test_scanner_marks_only_exact_pins(tmp_path, line, pinned):
    from aisbom.scanner import DeepScanner

    req = tmp_path / "requirements.txt"
    req.write_text(line + "\n")
    scanner = DeepScanner(str(tmp_path))
    scanner._parse_requirements(req)
    [dep] = scanner.dependencies
    assert dep["pinned"] is pinned


def test_disabled_env_var_is_read():
    assert osv.disabled_by_env({"AISBOM_NO_OSV": "1"}) is True
    assert osv.disabled_by_env({}) is False
