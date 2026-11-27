"""SPDX 3.0 AI Profile export.

Every generated document is validated against the *official* SPDX 3.0.1 JSON
schema bundled at ``tests/schemas/spdx-3.0.1-schema.json``. That schema sets
``unevaluatedProperties: false`` throughout, so a misspelled or mis-namespaced
key (``energyConsumption`` instead of ``ai_energyConsumption``, ``AIPackage``
instead of ``ai_AIPackage``) fails the suite rather than shipping.

This matters more here than usual: ``spdx-tools`` 0.8.5 does ship an ``spdx3``
subpackage, but it implements a *pre-release draft* of the spec (bare
``AIPackage`` types, an object-valued ``@context``, ``energyConsumption`` as a
string) and its own metadata calls the support "neither complete nor stable".
Its output does not validate against released 3.0.1, which is why this module
builds the JSON-LD directly — the schema check below is what keeps that
hand-rolled mapping honest.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from aisbom.spdx3_gen import SPDX3Generator, generate_spdx3_sbom

SHA_A = "a" * 64
SHA_B = "b" * 64

_SCHEMA_PATH = Path(__file__).parent / "schemas" / "spdx-3.0.1-schema.json"


@pytest.fixture(scope="module")
def validator():
    with _SCHEMA_PATH.open() as fh:
        return Draft202012Validator(json.load(fh))


def _pytorch_artifact(name="model.pt", artifact_hash=SHA_A, **overrides):
    """An artifact dict shaped like the one ``DeepScanner`` emits."""
    art = {
        "name": name,
        "type": "machine-learning-model",
        "framework": "PyTorch",
        "risk_level": "MEDIUM (Pickle Present)",
        "license": "Unknown",
        "legal_status": "UNKNOWN",
        "hash": artifact_hash,
        "details": {},
    }
    art.update(overrides)
    return art


def _generate(artifacts=None, dependencies=None, hf_model_card=None):
    results = {
        "artifacts": artifacts or [],
        "dependencies": dependencies or [],
        "errors": [],
    }
    if hf_model_card is not None:
        results["hf_model_card"] = hf_model_card
    return json.loads(generate_spdx3_sbom(results))


def _graph(data, type_name):
    return [e for e in data["@graph"] if e.get("type") == type_name]


def _assert_valid(validator, data):
    errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
    assert not errors, "schema validation failed: " + "; ".join(
        f"{list(e.path)}: {e.message}" for e in errors[:5]
    )


# --- document shape ---------------------------------------------------------


def test_context_is_the_released_301_context(validator):
    data = _generate([_pytorch_artifact()])
    assert data["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
    _assert_valid(validator, data)


def test_creation_info_declares_spec_version_301():
    data = _generate([_pytorch_artifact()])
    (ci,) = _graph(data, "CreationInfo")
    assert ci["specVersion"] == "3.0.1"
    # The schema's `created` pattern rejects sub-second precision.
    assert ci["created"].endswith("Z") and "." not in ci["created"]


def test_document_declares_ai_profile_conformance():
    data = _generate([_pytorch_artifact()])
    (doc,) = _graph(data, "SpdxDocument")
    assert "ai" in doc["profileConformance"]
    assert "software" in doc["profileConformance"]


def test_tool_agent_reports_running_cli_version():
    data = _generate([_pytorch_artifact()])
    (agent,) = _graph(data, "SoftwareAgent")
    assert agent["name"].startswith("aisbom-cli-")


# --- AI profile mapping -----------------------------------------------------


def test_model_artifact_becomes_ai_aipackage(validator):
    data = _generate([_pytorch_artifact(name="model.pt")])
    (pkg,) = _graph(data, "ai_AIPackage")
    assert pkg["name"] == "model.pt"
    assert pkg["software_primaryPurpose"] == "model"
    _assert_valid(validator, data)


def test_type_of_model_carries_the_scanned_framework():
    data = _generate([_pytorch_artifact(framework="SafeTensors")])
    (pkg,) = _graph(data, "ai_AIPackage")
    assert pkg["ai_typeOfModel"] == ["SafeTensors"]


def test_dependencies_become_software_packages(validator):
    data = _generate(
        [_pytorch_artifact()],
        [{"name": "requests", "version": "2.28.1"}],
    )
    (pkg,) = _graph(data, "software_Package")
    assert pkg["name"] == "requests"
    assert pkg["software_packageVersion"] == "2.28.1"
    _assert_valid(validator, data)


# --- checksums: never assert a sentinel as a digest -------------------------


def test_checksum_emitted_for_local_artifact():
    data = _generate([_pytorch_artifact(artifact_hash=SHA_A)])
    (pkg,) = _graph(data, "ai_AIPackage")
    assert pkg["verifiedUsing"] == [
        {"type": "Hash", "algorithm": "sha256", "hashValue": SHA_A}
    ]


@pytest.mark.parametrize("sentinel", ["remote_unhashed", "hash_error"])
def test_checksum_omitted_not_faked_for_sentinels(sentinel, validator):
    data = _generate([_pytorch_artifact(artifact_hash=sentinel)])
    (pkg,) = _graph(data, "ai_AIPackage")
    assert "verifiedUsing" not in pkg
    _assert_valid(validator, data)


# --- dataset metadata (present and absent) ----------------------------------

_HF_WITH_DATASETS = {
    "id": "google-bert/bert-base-uncased",
    "pipeline_tag": "fill-mask",
    "cardData": {"datasets": ["bookcorpus", "wikipedia"], "license": "apache-2.0"},
}


def test_datasets_become_dataset_packages_with_trained_on(validator):
    data = _generate([_pytorch_artifact()], hf_model_card=_HF_WITH_DATASETS)
    datasets = _graph(data, "dataset_DatasetPackage")
    assert sorted(d["name"] for d in datasets) == ["bookcorpus", "wikipedia"]
    # `dataset_datasetType` is required by the schema; we cannot know the
    # modality from a card listing, so it must be an explicit noAssertion.
    assert all(d["dataset_datasetType"] == ["noAssertion"] for d in datasets)

    trained_on = [
        r for r in _graph(data, "Relationship")
        if r["relationshipType"] == "trainedOn"
    ]
    assert len(trained_on) == 1
    assert sorted(trained_on[0]["to"]) == sorted(d["spdxId"] for d in datasets)
    _assert_valid(validator, data)


def test_no_dataset_metadata_emits_no_dataset_elements(validator):
    data = _generate([_pytorch_artifact()])
    assert _graph(data, "dataset_DatasetPackage") == []
    assert not [
        r for r in _graph(data, "Relationship")
        if r["relationshipType"] == "trainedOn"
    ]
    (doc,) = _graph(data, "SpdxDocument")
    # The dataset profile is only claimed when dataset elements exist.
    assert "dataset" not in doc["profileConformance"]
    _assert_valid(validator, data)


def test_training_information_carried_from_card_when_present():
    data = _generate([_pytorch_artifact()], hf_model_card=_HF_WITH_DATASETS)
    (pkg,) = _graph(data, "ai_AIPackage")
    assert "bookcorpus" in pkg["ai_informationAboutTraining"]


def test_unpopulatable_ai_fields_are_omitted_not_guessed():
    """No source data exists for these; asserting a placeholder would lie."""
    data = _generate([_pytorch_artifact()], hf_model_card=_HF_WITH_DATASETS)
    (pkg,) = _graph(data, "ai_AIPackage")
    for field in (
        "ai_energyConsumption",
        "ai_metric",
        "ai_safetyRiskAssessment",
        "ai_hyperparameter",
    ):
        assert field not in pkg


# --- identifiers: deterministic, unique, valid IRIs --------------------------


def test_spdx_ids_are_iris():
    data = _generate([_pytorch_artifact()], [{"name": "requests", "version": "1.0"}])
    for element in data["@graph"]:
        if "spdxId" in element:
            assert element["spdxId"].startswith("https://")


def test_ids_deterministic_across_runs():
    def ids():
        data = _generate(
            [_pytorch_artifact(name="model.pt", artifact_hash=SHA_A)],
            [{"name": "requests", "version": "2.28.1"}],
        )
        return [e.get("spdxId") for e in data["@graph"]]

    assert ids() == ids()


def test_ids_unique_for_identical_name_and_hash(validator):
    data = _generate([_pytorch_artifact(), _pytorch_artifact()])
    ids = [p["spdxId"] for p in _graph(data, "ai_AIPackage")]
    assert len(set(ids)) == 2
    _assert_valid(validator, data)


def test_ids_unique_when_every_artifact_is_remote(validator):
    data = _generate([
        _pytorch_artifact(name="a.pt", artifact_hash="remote_unhashed"),
        _pytorch_artifact(name="a.pt", artifact_hash="remote_unhashed"),
    ])
    ids = [p["spdxId"] for p in _graph(data, "ai_AIPackage")]
    assert len(set(ids)) == 2
    _assert_valid(validator, data)


def test_different_scans_never_share_a_namespace():
    """Two unrelated scans must not claim the same IRIs.

    The namespace was originally a whole-second timestamp, so parallel CI jobs
    starting in the same second produced documents whose SpdxDocument, agent,
    package and relationship IRIs collided while describing different data —
    a store importing both could merge or overwrite unrelated results. Freezing
    the clock reproduces that exactly.
    """
    frozen = datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc)

    def doc(artifacts):
        return json.loads(SPDX3Generator(creation_time=frozen).generate(
            {"artifacts": artifacts, "dependencies": [], "errors": []}
        ))

    a = doc([_pytorch_artifact(name="a.pt", artifact_hash=SHA_A)])
    b = doc([_pytorch_artifact(name="b.pt", artifact_hash=SHA_B)])

    ids_a = {e["spdxId"] for e in a["@graph"] if "spdxId" in e}
    ids_b = {e["spdxId"] for e in b["@graph"] if "spdxId" in e}
    assert not (ids_a & ids_b), "distinct scans emitted colliding IRIs"


def test_identical_content_yields_identical_ids_across_time():
    """Determinism must come from content, not from two runs sharing a second."""
    def doc(moment):
        return json.loads(SPDX3Generator(creation_time=moment).generate(
            {
                "artifacts": [_pytorch_artifact(artifact_hash=SHA_A)],
                "dependencies": [{"name": "requests", "version": "2.28.1"}],
                "errors": [],
            }
        ))

    early = doc(datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc))
    later = doc(datetime(2026, 12, 25, 3, 30, 45, tzinfo=timezone.utc))

    assert [e.get("spdxId") for e in early["@graph"]] == \
           [e.get("spdxId") for e in later["@graph"]]


def test_id_derived_from_content_hash():
    data = _generate([_pytorch_artifact(artifact_hash=SHA_A)])
    (pkg,) = _graph(data, "ai_AIPackage")
    assert SHA_A[:12] in pkg["spdxId"]


# --- edge cases -------------------------------------------------------------


def test_empty_scan_still_produces_a_valid_document(validator):
    data = _generate()
    (doc,) = _graph(data, "SpdxDocument")
    assert doc["rootElement"] == [doc["spdxId"]]
    _assert_valid(validator, data)


def test_artifact_name_falls_back_when_missing(validator):
    art = _pytorch_artifact()
    del art["name"]
    data = _generate([art])
    (pkg,) = _graph(data, "ai_AIPackage")
    assert pkg["name"] == "unknown-model"
    _assert_valid(validator, data)


def test_full_scan_validates(validator):
    data = _generate(
        [
            _pytorch_artifact(name="mock_malware.pt", artifact_hash=SHA_A),
            _pytorch_artifact(
                name="weights.safetensors", artifact_hash=SHA_B,
                framework="SafeTensors",
            ),
            _pytorch_artifact(name="remote.pt", artifact_hash="remote_unhashed"),
        ],
        [
            {"name": "requests", "version": "2.28.1"},
            {"name": "torch", "version": "2.0.*"},
        ],
        hf_model_card=_HF_WITH_DATASETS,
    )
    _assert_valid(validator, data)


# --- declared licences ------------------------------------------------------
#
# Same sources and rules as SPDX 2.3 and CycloneDX: a dependency's licence is
# what PyPI declares for its exact pin, a model's is what its file declares.
# Only valid SPDX expressions are carried; free text and unresolved licences
# get no licence element at all rather than an invented LicenseRef or a
# placeholder.

_TORCH_DEP = {
    "name": "torch", "version": "2.13.0", "license": "BSD-3-Clause AND MIT",
    "license_is_spdx": True, "license_source": "pypi",
}


def _licences(data):
    return _graph(data, "simplelicensing_LicenseExpression")


def _declared_for(data, spdx_id):
    """The licence expressions declared for one element, via relationships."""
    by_id = {e["spdxId"]: e for e in _licences(data)}
    found = []
    for rel in _graph(data, "Relationship"):
        if rel["relationshipType"] == "hasDeclaredLicense" and rel["from"] == spdx_id:
            found.extend(by_id[t]["simplelicensing_licenseExpression"] for t in rel["to"])
    return found


def test_a_pypi_resolved_dependency_licence_is_declared(validator):
    data = _generate([_pytorch_artifact()], [_TORCH_DEP])
    (lib,) = _graph(data, "software_Package")
    assert _declared_for(data, lib["spdxId"]) == ["BSD-3-Clause AND MIT"]
    _assert_valid(validator, data)


def test_a_non_spdx_dependency_licence_is_not_declared(validator):
    data = _generate([_pytorch_artifact()], [{
        "name": "vendorlib", "version": "1.0", "license": "Proprietary",
        "license_is_spdx": False, "license_source": "pypi",
    }])
    assert _licences(data) == []
    assert not [r for r in _graph(data, "Relationship")
                if r["relationshipType"] == "hasDeclaredLicense"]
    _assert_valid(validator, data)


def test_an_invalid_spdx_flagged_licence_is_not_declared():
    data = _generate([_pytorch_artifact()], [{
        "name": "oddlib", "version": "1.0", "license": "MIT OR",
        "license_is_spdx": True, "license_source": "pypi",
    }])
    assert _licences(data) == []


def test_an_unresolved_dependency_licence_emits_nothing():
    data = _generate([_pytorch_artifact()], [{"name": "requests", "version": "2.28.1"}])
    assert _licences(data) == []


@pytest.mark.parametrize("declared, expected", [
    ("apache-2.0", "Apache-2.0"),
    ("Apache-2.0", "Apache-2.0"),
    ("cc-by-nc-4.0", "CC-BY-NC-4.0"),
])
def test_a_model_licence_matches_cyclonedx(declared, expected, validator):
    """The CycloneDX component for the same artifact names the same id."""
    from cyclonedx.factory.license import LicenseFactory

    data = _generate([_pytorch_artifact(name="w.safetensors", license=declared)])
    (pkg,) = _graph(data, "ai_AIPackage")
    assert _declared_for(data, pkg["spdxId"]) == [expected]
    assert LicenseFactory().make_from_string(declared).id == expected
    _assert_valid(validator, data)


@pytest.mark.parametrize("declared", [
    "Unknown", "", None, "llama2", "openrail", "cc-by-nc-4.0 (Non-Commercial)",
])
def test_a_model_with_no_spdx_licence_gets_none(declared):
    data = _generate([_pytorch_artifact(license=declared)])
    assert _licences(data) == []


def test_hf_card_licence_is_not_used():
    """The card's licence is a CycloneDX property, never the component licence."""
    card = {"cardData": {"license": "apache-2.0"}}
    data = _generate([_pytorch_artifact()], hf_model_card=card)
    assert _licences(data) == []


def test_licence_elements_are_shared_between_packages(validator):
    data = _generate(
        [_pytorch_artifact(license="MIT")],
        [{"name": "a", "version": "1", "license": "MIT", "license_is_spdx": True},
         {"name": "b", "version": "1", "license": "mit", "license_is_spdx": True}],
    )
    (lic,) = _licences(data)
    assert lic["simplelicensing_licenseExpression"] == "MIT"
    holders = [r["from"] for r in _graph(data, "Relationship")
               if r["relationshipType"] == "hasDeclaredLicense"]
    assert len(holders) == 3
    _assert_valid(validator, data)


def test_licences_are_in_the_described_set_and_profile(validator):
    data = _generate([_pytorch_artifact()], [_TORCH_DEP])
    (doc,) = _graph(data, "SpdxDocument")
    assert "simpleLicensing" in doc["profileConformance"]
    (lic,) = _licences(data)
    (describes,) = [r for r in _graph(data, "Relationship")
                    if r["relationshipType"] == "describes"]
    # A licence describes no artifact; it is reachable through the
    # package's relationship, not a root of the document.
    assert lic["spdxId"] not in describes["to"]
    assert lic["spdxId"] not in doc["rootElement"]


def test_no_licences_claims_no_licensing_profile():
    data = _generate([_pytorch_artifact()])
    (doc,) = _graph(data, "SpdxDocument")
    assert "simpleLicensing" not in doc["profileConformance"]


def test_licences_do_not_change_the_document_namespace():
    """The licence comes from a network lookup that may fail; the scan's
    identity must not flip between an online and an offline run."""
    without = _generate([_pytorch_artifact()], [{"name": "torch", "version": "2.13.0"}])
    with_lic = _generate([_pytorch_artifact()], [_TORCH_DEP])
    ns = lambda d: _graph(d, "SpdxDocument")[0]["spdxId"]  # noqa: E731
    assert ns(without) == ns(with_lic)


# --- CLI wiring -------------------------------------------------------------
#
# `--spdx-version` shipped declared-but-unread: it advertised "2.3 or 3.0"
# while nothing ever consulted it, so `--spdx-version 3.0` silently produced a
# 2.3 document. These tests pin the flag to real behaviour.

from typer.testing import CliRunner  # noqa: E402

from aisbom.cli import app  # noqa: E402
from aisbom.mock_generator import create_mock_malware_file  # noqa: E402

runner = CliRunner()


def _scan(tmp_path, *extra):
    out = tmp_path / "out.spdx.json"
    create_mock_malware_file(tmp_path)
    result = runner.invoke(app, [
        "scan", str(tmp_path),
        "--format", "spdx",
        "--output", str(out),
        "--no-fail-on-risk",
        *extra,
    ])
    return result, out


def test_cli_defaults_to_spdx_2_3(tmp_path):
    result, out = _scan(tmp_path)
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["spdxVersion"] == "SPDX-2.3"


def test_cli_spdx_version_3_0_emits_ai_profile(tmp_path, validator):
    result, out = _scan(tmp_path, "--spdx-version", "3.0")
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
    assert _graph(data, "ai_AIPackage"), "expected an AI Profile package"
    _assert_valid(validator, data)


def test_cli_2_3_output_unchanged_by_this_slice(tmp_path):
    """No-regression guard: the default path must not gain 3.0 artefacts."""
    _, out = _scan(tmp_path)
    data = json.loads(out.read_text())
    assert "@context" not in data and "@graph" not in data
    assert set(data) >= {"spdxVersion", "packages", "relationships"}


def test_cli_rejects_unsupported_spdx_version(tmp_path):
    result, out = _scan(tmp_path, "--spdx-version", "2.2")
    assert result.exit_code == 1
    assert "Unsupported SPDX version" in result.output
    # The old behaviour silently wrote a 2.3 document instead of failing.
    assert not out.exists()


def _fake_pypi(monkeypatch, calls):
    from aisbom import pypi

    def fake(dependencies, **_):
        calls.append([d["name"] for d in dependencies])
        for dep in dependencies:
            if dep.get("pinned"):
                dep.update(license="Apache-2.0", license_is_spdx=True,
                           license_source="pypi")
        return pypi.LicenseLookupResult(queried=1, resolved=1)

    monkeypatch.setattr(pypi, "resolve_dependency_licenses", fake)


def test_cli_spdx_3_0_resolves_dependency_licences(tmp_path, monkeypatch, validator):
    calls = []
    _fake_pypi(monkeypatch, calls)
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n")
    result, out = _scan(tmp_path, "--spdx-version", "3.0")
    assert result.exit_code == 0, result.output
    assert calls == [["requests"]]
    data = json.loads(out.read_text())
    (lib,) = _graph(data, "software_Package")
    assert _declared_for(data, lib["spdxId"]) == ["Apache-2.0"]
    _assert_valid(validator, data)


def test_cli_spdx_3_0_offline_makes_no_licence_lookup(tmp_path, monkeypatch):
    calls = []
    _fake_pypi(monkeypatch, calls)
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n")
    result, out = _scan(tmp_path, "--spdx-version", "3.0", "--offline")
    assert result.exit_code == 0, result.output
    assert calls == []
    assert _licences(json.loads(out.read_text())) == []
