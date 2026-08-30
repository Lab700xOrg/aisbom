"""Tests for the extracted CycloneDX builder (#114).

`build_cyclonedx_json` was lifted out of `cli.scan` so `aisbom score` can grade
a scan target without duplicating document construction. These tests pin the
two deliberate output changes made at the same time, and assert that nothing
else about the document moved.
"""

import json

import pytest

from aisbom.cyclonedx_gen import build_cyclonedx_json


def _results(**overrides):
    results = {
        "artifacts": [
            {
                "name": "model.safetensors",
                "risk_level": "LOW",
                "framework": "SafeTensors",
                "legal_status": "OK",
                "license": "Apache-2.0",
                "hash": "a" * 64,
            },
        ],
        "dependencies": [
            {"name": "torch", "version": "2.10.0"},
            {"name": "numpy", "version": "unknown"},
        ],
        "errors": [],
    }
    results.update(overrides)
    return results


def _doc(**overrides):
    return json.loads(build_cyclonedx_json(_results(**overrides)))


def _by_name(doc, name):
    return next(c for c in doc["components"] if c["name"] == name)


# ---------------------------------------------------------------------------
# The two deliberate output changes.
# ---------------------------------------------------------------------------

def test_metadata_tools_identifies_aisbom():
    """An SBOM that does not say what produced it fails the NTIA minimum
    elements — and AIsbom's own completeness grade."""
    tools = _doc()["metadata"]["tools"]
    names = [c["name"] for c in tools["components"]]
    assert "aisbom-cli" in names


def test_placeholder_version_is_omitted_not_emitted():
    """`version: "unknown"` carried no information and cost grade points."""
    assert "version" not in _by_name(_doc(), "numpy")


def test_real_dependency_versions_are_preserved():
    assert _by_name(_doc(), "torch")["version"] == "2.10.0"


def test_dropping_the_placeholder_causes_no_diff_drift(tmp_path):
    """The upgrade hazard this change had to clear.

    Every existing user holds baseline SBOMs carrying `version: "unknown"`. If
    dropping the placeholder registered as a version change, the first `aisbom
    diff` after upgrading would report phantom drift on every dependency.
    `SBOMDiff` reads `component.get("version", "unknown")`, so absent and the
    literal string compare equal — asserted here against the real differ rather
    than trusted from reading the source.
    """
    from aisbom.diff import SBOMDiff

    old_doc = _doc()
    for component in old_doc["components"]:
        if component["name"] == "numpy":
            component["version"] = "unknown"      # the pre-#114 shape
    new_doc = _doc()                              # the post-#114 shape

    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(old_doc))
    new_path.write_text(json.dumps(new_doc))

    result = SBOMDiff(old_path, new_path).compare()
    assert not result.changed
    assert not result.added and not result.removed


def test_a_genuine_version_change_is_still_detected(tmp_path):
    """Guards the test above from passing vacuously: the differ must be live
    enough to notice a version change that is real."""
    from aisbom.diff import SBOMDiff

    old_doc = _doc()
    for component in old_doc["components"]:
        if component["name"] == "torch":
            component["version"] = "2.9.0"
    new_doc = _doc()                              # torch is 2.10.0

    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(old_doc))
    new_path.write_text(json.dumps(new_doc))

    result = SBOMDiff(old_path, new_path).compare()
    assert [(c.name, c.version_diff) for c in result.changed] == \
        [("torch", ("2.9.0", "2.10.0"))]


# ---------------------------------------------------------------------------
# Everything else about the document is unchanged.
# ---------------------------------------------------------------------------

def test_model_components_keep_their_stable_bom_ref():
    assert _by_name(_doc(), "model.safetensors")["bom-ref"] == \
        "artifact-0-model.safetensors"


def test_description_string_is_unchanged():
    desc = _by_name(_doc(), "model.safetensors")["description"]
    assert desc == ("Risk: LOW | Framework: SafeTensors | Legal: OK | "
                    "License: Apache-2.0")


def test_sha256_is_emitted_when_present():
    hashes = _by_name(_doc(), "model.safetensors")["hashes"]
    assert hashes[0]["alg"] == "SHA-256"
    assert hashes[0]["content"] == "a" * 64


@pytest.mark.parametrize("sentinel", ["remote_unhashed", "hash_error"])
def test_scanner_sentinels_are_never_emitted_as_digests(sentinel):
    """The bug #111 fixed: a sentinel shipped inside a SHA-256 entry made every
    remote SBOM fail CycloneDX validation."""
    results = _results()
    results["artifacts"][0]["hash"] = sentinel
    doc = json.loads(build_cyclonedx_json(results))
    assert "hashes" not in _by_name(doc, "model.safetensors")


def test_licenses_are_emitted_when_known():
    assert _by_name(_doc(), "model.safetensors")["licenses"]


def test_unknown_license_produces_no_licenses_entry():
    results = _results()
    results["artifacts"][0]["license"] = "Unknown"
    doc = json.loads(build_cyclonedx_json(results))
    assert "licenses" not in _by_name(doc, "model.safetensors")


def test_aisbom_properties_are_attached():
    props = _by_name(_doc(), "model.safetensors").get("properties", [])
    assert any(p["name"].startswith("aisbom:") for p in props)


# ---------------------------------------------------------------------------
# Schema-version behaviour is untouched by the extraction.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version", ["1.5", "1.6", "1.7"])
def test_requested_schema_version_is_honoured(version):
    doc = json.loads(build_cyclonedx_json(_results(), version))
    assert doc["specVersion"] == version


def test_model_card_is_spliced_into_17_only():
    results = _results(hf_model_card={
        "id": "org/model",
        "cardData": {"license": "apache-2.0", "datasets": ["bookcorpus"]},
        "pipeline_tag": "fill-mask",
    })
    at_17 = json.loads(build_cyclonedx_json(results, "1.7"))
    at_16 = json.loads(build_cyclonedx_json(results, "1.6"))
    assert "modelCard" in _by_name(at_17, "model.safetensors")
    assert "modelCard" not in _by_name(at_16, "model.safetensors")


def test_libraries_never_receive_a_model_card():
    results = _results(hf_model_card={"id": "org/model", "pipeline_tag": "fill-mask"})
    doc = json.loads(build_cyclonedx_json(results, "1.7"))
    assert "modelCard" not in _by_name(doc, "torch")


def test_an_empty_scan_still_produces_a_valid_document():
    doc = json.loads(build_cyclonedx_json({"artifacts": [], "dependencies": []}))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["metadata"]["tools"]
