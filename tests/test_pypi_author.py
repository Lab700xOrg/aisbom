"""The author a PyPI release declares, recorded beside its licence.

`aisbom comply` offers it as a dependency's supplier (FDA minimum element). It
comes from the same `/pypi/<name>/<version>/json` request the licence lookup
already makes, so no new network call and no new disclosure.
"""

import json
import time

import pytest

from aisbom import pypi
from aisbom.cyclonedx_gen import build_cyclonedx_json

from tests.test_pypi import FakePyPI, _dep, _resolve, _torch_info


@pytest.fixture(autouse=True)
def _no_retry_pause(monkeypatch):
    monkeypatch.setattr(pypi, "_BACKOFF_SECONDS", 0)


@pytest.mark.parametrize("info, expected", [
    ({"author": "PyTorch Team"}, "PyTorch Team"),
    ({"author": "", "maintainer": "NumPy Developers"}, "NumPy Developers"),
    # Real transformers 4.x shape: author field set, email separate.
    ({"author": "The Hugging Face team (past and future)",
      "author_email": "transformers@huggingface.co"},
     "The Hugging Face team (past and future)"),
    # PEP 621 builds put the name inside author_email only.
    ({"author": None, "author_email": "Travis Oliphant <travis@example.org>, "
                                      "Other <o@example.org>"}, "Travis Oliphant"),
    ({"author": None, "maintainer_email": '"Jane Doe" <jane@example.org>'}, "Jane Doe"),
])
def test_declared_author_is_normalised(info, expected):
    assert pypi.normalize_author(info) == expected


@pytest.mark.parametrize("info", [
    {},
    {"author": "someone@example.org"},          # an email is not a name
    {"author": "UNKNOWN"},                      # setuptools placeholder
    {"author": "A\nB"},
    {"author": "x" * 200},
    {"author_email": "bare@example.org"},       # no display name
    {"author": 7},
    "not-a-mapping",
])
def test_unusable_author_declarations_resolve_nothing(info):
    assert pypi.normalize_author(info) is None


def test_author_is_written_onto_the_dependency():
    deps = [_dep("torch", "2.13.0")]
    _resolve(deps, FakePyPI([dict(_torch_info(), author="PyTorch Team")]))
    assert deps[0]["author"] == "PyTorch Team"
    assert deps[0]["author_source"] == "pypi"


def test_author_is_recorded_even_when_no_licence_resolves():
    info = {"name": "numpy", "version": "1.26.4", "license": None,
            "classifiers": [], "maintainer": "NumPy Developers"}
    deps = [_dep("numpy", "1.26.4")]
    result = _resolve(deps, FakePyPI([info]))
    assert deps[0]["author"] == "NumPy Developers"
    assert "license" not in deps[0]
    assert result.resolved == 0


def test_author_comes_back_from_the_cache(tmp_path):
    info = dict(_torch_info(), author="PyTorch Team")
    _resolve([_dep("torch", "2.13.0")], FakePyPI([info]), cache_dir=tmp_path)
    fake = FakePyPI([])
    deps = [_dep("torch", "2.13.0")]
    _resolve(deps, fake, cache_dir=tmp_path)
    assert fake.calls == 0
    assert deps[0]["author"] == "PyTorch Team"


def test_cache_entries_from_before_authors_were_recorded_are_refetched(tmp_path):
    """A schema-1 entry has no author field; reusing it would hide the author
    for up to 30 days, so the schema bump makes every old entry miss."""
    (tmp_path / pypi.CACHE_FILENAME).write_text(json.dumps({
        "schema": 1,
        "entries": {"torch==2.13.0": {"fetched_at": time.time(),
                                      "license": "MIT", "is_spdx": True}},
    }))
    fake = FakePyPI([dict(_torch_info(), author="PyTorch Team")])
    deps = [_dep("torch", "2.13.0")]
    _resolve(deps, fake, cache_dir=tmp_path)
    assert fake.calls == 1 and deps[0]["author"] == "PyTorch Team"


def test_author_becomes_a_dependency_property_in_the_sbom():
    results = {"artifacts": [], "dependencies": [
        {"name": "torch", "version": "2.13.0", "type": "library", "pinned": True,
         "author": "PyTorch Team", "author_source": "pypi"},
        {"name": "numpy", "version": "1.26.4", "type": "library", "pinned": True},
    ]}
    doc = json.loads(build_cyclonedx_json(results))
    by_name = {c["name"]: c for c in doc["components"]}
    torch_props = {p["name"]: p["value"] for p in by_name["torch"].get("properties", [])}
    assert torch_props[pypi.AUTHOR_PROPERTY] == "PyTorch Team"
    assert "properties" not in by_name["numpy"]
    # Declared, not asserted: the standard `supplier` field stays unset.
    assert "supplier" not in by_name["torch"]
