"""requirements.txt dependencies: a version only for exact pins, a purl for them.

The scanner used to record ``specs[0].version`` for any specifier, so
``torch>=2.0`` became a component at version ``2.0`` — a claim about what is
installed that the requirements file does not make. These tests pin the rule
across every layer that emits a dependency:

- the scanner records a version only for a single ``==``/``===`` pin without a
  wildcard, and keeps any other specifier as ``specifier``;
- CycloneDX gives exact pins a ``pkg:pypi`` purl and carries a range in the
  ``aisbom:requirement:specifier`` property;
- SPDX 2.3 and 3.0 follow the same rule (no version for non-pins, a purl
  external reference / ``software_packageUrl`` for pins);
- ``aisbom diff`` across the upgrade reports a range dependency's version as
  changed and nothing else.
"""

import json
from pathlib import Path

import pytest

from aisbom.cyclonedx_gen import build_cyclonedx_json
from aisbom.dependency import SPECIFIER_PROPERTY, dependency_purl
from aisbom.scanner import DeepScanner
from aisbom.spdx3_gen import generate_spdx3_sbom
from aisbom.spdx_gen import generate_spdx_sbom

_SPDX3_SCHEMA = Path(__file__).parent / "schemas" / "spdx-3.0.1-schema.json"

MIXED = (
    "torch>=2.0\n"
    "numpy\n"
    "transformers==5.13.1\n"
    "requests~=2.31\n"
    "scipy>=1.10,<2\n"
    "Zope_Interface==6.1\n"
    "zope.event===5.0\n"
    "pandas==2.*\n"
    "torchvision==0.19.0+cu118\n"
)


def _scan_deps(tmp_path, text=MIXED):
    (tmp_path / "requirements.txt").write_text(text)
    results = DeepScanner(tmp_path).scan()
    return results, {d["name"]: d for d in results["dependencies"]}


# --- scanner ---------------------------------------------------------------


def test_a_range_records_no_version_and_keeps_the_specifier(tmp_path):
    _, deps = _scan_deps(tmp_path)
    assert deps["torch"]["version"] == "unknown"
    assert deps["torch"]["specifier"] == ">=2.0"
    assert deps["torch"]["pinned"] is False


@pytest.mark.parametrize("name,version", [
    ("transformers", "5.13.1"),
    ("Zope_Interface", "6.1"),
    ("zope.event", "5.0"),
    ("torchvision", "0.19.0+cu118"),
])
def test_an_exact_pin_keeps_its_version(tmp_path, name, version):
    _, deps = _scan_deps(tmp_path)
    assert deps[name]["version"] == version
    assert deps[name]["pinned"] is True
    assert "specifier" not in deps[name]


@pytest.mark.parametrize("name", ["requests", "scipy", "pandas"])
def test_compatible_multi_and_wildcard_specifiers_are_not_versions(tmp_path, name):
    _, deps = _scan_deps(tmp_path)
    assert deps[name]["version"] == "unknown"
    assert deps[name]["pinned"] is False
    assert deps[name]["specifier"]


def test_a_multi_clause_specifier_is_kept_whole(tmp_path):
    _, deps = _scan_deps(tmp_path)
    # Clause order is the parser's, so compare the set of clauses.
    assert set(deps["scipy"]["specifier"].split(",")) == {">=1.10", "<2"}


def test_a_bare_name_has_no_specifier(tmp_path):
    _, deps = _scan_deps(tmp_path)
    assert deps["numpy"]["version"] == "unknown"
    assert "specifier" not in deps["numpy"]


# --- purl ------------------------------------------------------------------


@pytest.mark.parametrize("dep,expected", [
    ({"name": "transformers", "version": "5.13.1", "pinned": True},
     "pkg:pypi/transformers@5.13.1"),
    # Normalised as PEP 503 names are, which is how eol.py joins pkg:pypi.
    ({"name": "Zope_Interface", "version": "6.1", "pinned": True},
     "pkg:pypi/zope-interface@6.1"),
    ({"name": "zope.event", "version": "5.0", "pinned": True},
     "pkg:pypi/zope-event@5.0"),
    # `+` is reserved in a purl and must be percent-encoded.
    ({"name": "torchvision", "version": "0.19.0+cu118", "pinned": True},
     "pkg:pypi/torchvision@0.19.0%2Bcu118"),
])
def test_dependency_purl_for_exact_pins(dep, expected):
    assert dependency_purl(dep) == expected


@pytest.mark.parametrize("dep", [
    {"name": "torch", "version": "unknown", "pinned": False, "specifier": ">=2.0"},
    {"name": "numpy", "version": "unknown", "pinned": False},
    # No `pinned` flag means the caller did not establish an exact pin.
    {"name": "torch", "version": "2.10.0"},
    {"name": "", "version": "1.0", "pinned": True},
])
def test_no_purl_without_an_exact_pin(dep):
    assert dependency_purl(dep) is None


# --- CycloneDX -------------------------------------------------------------


def _cdx(results, version="1.7"):
    return json.loads(build_cyclonedx_json(results, version))


def _comp(doc, name):
    return next(c for c in doc["components"] if c["name"] == name)


def test_cyclonedx_range_has_no_version_no_purl_and_a_specifier_property(tmp_path):
    results, _ = _scan_deps(tmp_path)
    torch = _comp(_cdx(results), "torch")
    assert "version" not in torch
    assert "purl" not in torch
    assert {"name": SPECIFIER_PROPERTY, "value": ">=2.0"} in torch["properties"]


def test_cyclonedx_exact_pin_has_version_and_purl(tmp_path):
    results, _ = _scan_deps(tmp_path)
    comp = _comp(_cdx(results), "transformers")
    assert comp["version"] == "5.13.1"
    assert comp["purl"] == "pkg:pypi/transformers@5.13.1"
    assert "properties" not in comp


def test_cyclonedx_bare_name_is_unchanged(tmp_path):
    results, _ = _scan_deps(tmp_path)
    numpy = _comp(_cdx(results), "numpy")
    assert set(numpy) == {"bom-ref", "name", "type"}


@pytest.mark.parametrize("version", ["1.5", "1.6", "1.7"])
def test_cyclonedx_mixed_specifiers_validate_strictly(tmp_path, version):
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    results, _ = _scan_deps(tmp_path)
    validator = JsonStrictValidator(SchemaVersion.from_version(version))
    assert validator.validate_str(build_cyclonedx_json(results, version)) is None


# --- SPDX 2.3 --------------------------------------------------------------


def _spdx23_pkg(results, name):
    data = json.loads(generate_spdx_sbom(results))
    return next(p for p in data["packages"] if p["name"] == name)


def test_spdx23_range_has_no_version_and_no_purl(tmp_path):
    results, _ = _scan_deps(tmp_path)
    pkg = _spdx23_pkg(results, "torch")
    assert "versionInfo" not in pkg
    assert "externalRefs" not in pkg
    assert ">=2.0" in pkg["comment"]


def test_spdx23_bare_name_has_no_version(tmp_path):
    results, _ = _scan_deps(tmp_path)
    pkg = _spdx23_pkg(results, "numpy")
    assert "versionInfo" not in pkg
    assert "comment" not in pkg


def test_spdx23_exact_pin_has_version_and_purl_ref(tmp_path):
    results, _ = _scan_deps(tmp_path)
    pkg = _spdx23_pkg(results, "torchvision")
    assert pkg["versionInfo"] == "0.19.0+cu118"
    # spdx-tools writes the underscore spelling; the 2.3 JSON schema's enum
    # lists both `PACKAGE-MANAGER` and `PACKAGE_MANAGER`.
    assert pkg["externalRefs"] == [{
        "referenceCategory": "PACKAGE_MANAGER",
        "referenceType": "purl",
        "referenceLocator": "pkg:pypi/torchvision@0.19.0%2Bcu118",
    }]


def test_spdx23_mixed_specifiers_validate(tmp_path):
    from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
    from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

    results, _ = _scan_deps(tmp_path)
    document = JsonLikeDictParser().parse(json.loads(generate_spdx_sbom(results)))
    assert validate_full_spdx_document(document) == []


# --- SPDX 3.0 --------------------------------------------------------------


def _spdx3(results):
    return json.loads(generate_spdx3_sbom(results))


def _spdx3_pkg(data, name):
    return next(
        e for e in data["@graph"]
        if e.get("type") == "software_Package" and e["name"] == name
    )


def test_spdx3_range_has_no_version_and_no_purl(tmp_path):
    results, _ = _scan_deps(tmp_path)
    pkg = _spdx3_pkg(_spdx3(results), "torch")
    assert "software_packageVersion" not in pkg
    assert "software_packageUrl" not in pkg
    assert ">=2.0" in pkg["comment"]


def test_spdx3_exact_pin_has_version_and_purl(tmp_path):
    results, _ = _scan_deps(tmp_path)
    pkg = _spdx3_pkg(_spdx3(results), "Zope_Interface")
    assert pkg["software_packageVersion"] == "6.1"
    assert pkg["software_packageUrl"] == "pkg:pypi/zope-interface@6.1"
    assert "comment" not in pkg


def test_spdx3_mixed_specifiers_validate(tmp_path):
    from jsonschema import Draft202012Validator

    results, _ = _scan_deps(tmp_path)
    with _SPDX3_SCHEMA.open() as fh:
        validator = Draft202012Validator(json.load(fh))
    errors = list(validator.iter_errors(_spdx3(results)))
    assert not errors, [e.message for e in errors[:5]]


# --- aisbom diff across the upgrade -----------------------------------------


def test_diff_across_the_upgrade_reports_only_range_versions(tmp_path):
    """A baseline from an earlier version recorded `torch>=2.0` as 2.0.

    Against it, the range dependency shows `2.0 -> unknown`. Exact pins and
    bare names do not move: the purl and specifier property are not compared.
    """
    from aisbom.diff import SBOMDiff

    old_results = {"artifacts": [], "errors": [], "dependencies": [
        {"name": "torch", "version": "2.0", "type": "library", "pinned": False},
        {"name": "numpy", "version": "unknown", "type": "library", "pinned": False},
        {"name": "transformers", "version": "5.13.1", "type": "library", "pinned": True},
    ]}
    new_results, _ = _scan_deps(tmp_path, "torch>=2.0\nnumpy\ntransformers==5.13.1\n")

    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(build_cyclonedx_json(old_results))
    new.write_text(build_cyclonedx_json(new_results))

    result = SBOMDiff(old, new).compare()
    assert not result.added and not result.removed
    assert {c.name: c.version_diff for c in result.changed} == {
        "torch": ("2.0", "unknown"),
    }
