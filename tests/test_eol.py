"""End-of-support lookup against endoflife.date for `aisbom comply --framework fda`.

endoflife.date is never contacted from this suite. Payloads are trimmed copies
of real `/api/v1/products/<name>` responses (numpy, django, 2026-11-14).
"""

import pytest
import requests

from aisbom import eol

# Captured at import, before conftest's autouse stub replaces it.
_REAL_DEFAULT_SESSION = eol._default_session


def _numpy():
    return {"result": {
        "name": "numpy",
        "identifiers": [{"type": "purl", "id": "pkg:pypi/numpy"},
                        {"type": "cpe", "id": "cpe:2.3:a:numpy:numpy"}],
        "releases": [
            {"name": "2.5", "isEol": False, "eolFrom": "2028-06-22"},
            {"name": "2.2", "isEol": False, "eolFrom": "2026-12-09"},
            {"name": "1.26", "isEol": True, "eolFrom": "2025-09-16"},
            {"name": "1.2", "isEol": True, "eolFrom": "2010-01-01"},
        ],
    }}


def _django():
    return {"result": {
        "name": "django",
        "identifiers": [{"type": "purl", "id": "pkg:github/django/django"},
                        {"type": "purl", "id": "pkg:pypi/django"}],
        "releases": [
            {"name": "5.2", "isEol": False, "eolFrom": "2028-04-30"},
            {"name": "6.1", "isEol": False, "eolFrom": None},
        ],
    }}


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


class FakeEol:
    def __init__(self, products=None, fail=None, statuses=None):
        self.products = products or {}
        self.fail = fail
        self.statuses = statuses or {}
        self.gets = []

    def get(self, url, timeout=None, headers=None):
        assert timeout and timeout > 0
        assert headers and headers["User-Agent"].startswith("aisbom-cli/")
        self.gets.append(url)
        if self.fail:
            raise self.fail
        slug = url.rstrip("/").rsplit("/", 1)[-1]
        if slug in self.statuses:
            return FakeResponse({}, self.statuses[slug])
        if slug not in self.products:
            return FakeResponse({"message": "Not Found"}, 404)
        return FakeResponse(self.products[slug])


def lookup(pins, session, **kw):
    return eol.lookup_end_of_support(pins, session=session, **kw)


def test_a_tracked_pin_gets_its_cycle_end_of_support_date():
    result = lookup([("numpy", "2.2.6")], FakeEol({"numpy": _numpy()}))
    answer = result.answers[("numpy", "2.2.6")]
    assert answer.date == "2026-12-09"
    assert answer.cycle == "2.2"
    assert answer.source == "endoflife.date numpy 2.2"
    assert result.error is None


def test_the_cycle_match_respects_dot_boundaries():
    """`1.26.4` is cycle 1.26, never cycle 1.2."""
    result = lookup([("numpy", "1.26.4")], FakeEol({"numpy": _numpy()}))
    assert result.answers[("numpy", "1.26.4")].cycle == "1.26"


def test_an_exact_cycle_name_matches():
    result = lookup([("numpy", "2.5")], FakeEol({"numpy": _numpy()}))
    assert result.answers[("numpy", "2.5")].date == "2028-06-22"


def test_a_version_in_no_listed_cycle_has_no_answer():
    result = lookup([("numpy", "3.0.0")], FakeEol({"numpy": _numpy()}))
    assert ("numpy", "3.0.0") not in result.answers


def test_a_cycle_with_no_announced_date_has_no_answer():
    result = lookup([("django", "6.1.3")], FakeEol({"django": _django()}))
    assert ("django", "6.1.3") not in result.answers


def test_names_are_canonicalised_and_case_folded():
    result = lookup([("Django", "5.2.19")], FakeEol({"django": _django()}))
    assert result.answers[("Django", "5.2.19")].date == "2028-04-30"


def test_an_untracked_package_has_no_answer_and_is_not_an_error():
    result = lookup([("requests", "2.32.3")], FakeEol({}))
    assert result.answers == {}
    assert result.error is None


def test_a_product_that_does_not_name_the_pypi_package_is_refused():
    """A same-named product that is not the PyPI package (no pkg:pypi purl)
    must not lend its dates to the dependency."""
    impostor = _numpy()
    impostor["result"]["identifiers"] = [{"type": "purl", "id": "pkg:npm/numpy"}]
    result = lookup([("numpy", "2.2.6")], FakeEol({"numpy": impostor}))
    assert result.answers == {}


def test_one_request_per_product_whatever_the_pin_count():
    fake = FakeEol({"numpy": _numpy()})
    result = lookup([("numpy", "2.2.6"), ("numpy", "1.26.4"), ("numpy", "2.2.6")], fake)
    assert len(fake.gets) == 1
    assert len(result.answers) == 2


def test_the_request_goes_to_the_v1_products_endpoint():
    fake = FakeEol({"numpy": _numpy()})
    lookup([("numpy", "2.2.6")], fake)
    assert fake.gets == ["https://endoflife.date/api/v1/products/numpy"]


@pytest.mark.parametrize("failure", [requests.ConnectionError("down"),
                                     requests.Timeout("slow")])
def test_an_unreachable_service_degrades_to_no_answers(failure):
    result = lookup([("numpy", "2.2.6")], FakeEol(fail=failure))
    assert result.answers == {}
    assert "endoflife.date" in result.error


def test_a_server_error_is_reported_but_does_not_raise():
    result = lookup([("numpy", "2.2.6")], FakeEol(statuses={"numpy": 503}))
    assert result.answers == {}
    assert result.error


@pytest.mark.parametrize("payload", [
    ValueError("not json"), [], {"result": "x"}, {"result": {"releases": "x"}},
    {"result": {"identifiers": [{"type": "purl", "id": "pkg:pypi/numpy"}],
                "releases": [{"name": 2.2, "eolFrom": "2026-12-09"}, "junk"]}},
    {"result": {"identifiers": [{"type": "purl", "id": "pkg:pypi/numpy"}],
                "releases": [{"name": "2.2", "eolFrom": "next year"}]}},
])
def test_malformed_payloads_give_no_answer(payload):
    result = lookup([("numpy", "2.2.6")], FakeEol({"numpy": payload}))
    assert result.answers == {}


def test_an_exhausted_budget_degrades_without_raising():
    result = lookup([("numpy", "2.2.6")], FakeEol({"numpy": _numpy()}),
                    budget_seconds=0)
    assert result.answers == {}
    assert result.error


def test_no_pins_makes_no_request():
    fake = FakeEol({})
    assert lookup([], fake).answers == {}
    assert fake.gets == []


def test_unexpected_exceptions_are_contained():
    class Exploding:
        def get(self, *a, **k):
            raise RuntimeError("boom")

    result = lookup([("numpy", "2.2.6")], Exploding())
    assert result.answers == {} and result.error


def test_the_default_session_is_a_requests_session():
    assert isinstance(_REAL_DEFAULT_SESSION(), requests.Session)


def test_the_env_var_opts_out():
    assert eol.disabled_by_env({"AISBOM_NO_EOL_LOOKUP": "1"})
    assert not eol.disabled_by_env({})
