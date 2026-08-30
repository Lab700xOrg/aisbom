"""VEX output — OpenVEX + CycloneDX VEX (#113).

Every generated OpenVEX document is validated against the *official* OpenVEX
0.2.0 JSON schema bundled at ``tests/schemas/openvex-0.2.0.schema.json``, and
every CycloneDX VEX document against the library's own strict 1.7 schema. Both
set ``additionalProperties: false``, so a misspelled key fails the suite rather
than shipping into a compliance artifact.

The schema check matters here for the same reason it did for SPDX 3.0 (#112):
the mapping from AIsbom's scan output to the VEX vocabulary is hand-built, and
a document that does not validate is one a consumer will reject.
"""

import json
from pathlib import Path

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from jsonschema import Draft202012Validator

from aisbom.vex import (
    FINDING_CLASSES_BY_ID,
    JUSTIFICATION_CODE_NOT_PRESENT,
    PUBLISHED_FINDING_CLASS_IDS,
    VEX_FINDING_CLASSES,
    VEX_NAMESPACE,
    baseline_findings,
    derive_statements,
    finding_classes_markdown,
    generate_cyclonedx_vex,
    generate_openvex,
    signals_from_component,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SERIAL = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"

_OPENVEX_SCHEMA = Path(__file__).parent / "schemas" / "openvex-0.2.0.schema.json"
_DOCS_REGISTRY = (
    Path(__file__).parent.parent / "docs" / "vex-finding-classes.md"
)


@pytest.fixture(scope="module")
def openvex_validator():
    with _OPENVEX_SCHEMA.open() as fh:
        return Draft202012Validator(json.load(fh))


def _artifact(name="model.pt", framework="PyTorch", artifact_hash=SHA_A, **details):
    """An artifact dict shaped like the one ``DeepScanner`` emits."""
    return {
        "name": name,
        "type": "machine-learning-model",
        "framework": framework,
        "risk_level": "LOW",
        "license": "Unknown",
        "legal_status": "UNKNOWN",
        "hash": artifact_hash,
        "details": dict(details),
    }


def _openvex(artifacts, baseline=None):
    return json.loads(
        generate_openvex(
            derive_statements(artifacts, baseline), sbom_serial=SERIAL
        )
    )


def _statuses(doc, class_id):
    """Every status asserted for one finding class in an OpenVEX document."""
    return [
        s["status"]
        for s in doc["statements"]
        if s["vulnerability"]["name"] == class_id
    ]


def _assert_cdx_valid(doc_json):
    """Validate against the library's own strict CycloneDX 1.7 schema."""
    errors = JsonStrictValidator(SchemaVersion.V1_7).validate_str(doc_json)
    assert errors is None, f"CycloneDX 1.7 validation failed: {errors}"


# --------------------------------------------------------------------------
# The vocabulary is an API
# --------------------------------------------------------------------------

def test_finding_class_ids_are_pinned():
    """The public ID set is an API. Changing it must be deliberate.

    These strings ship inside customers' compliance artifacts and are used to
    diff one scan against the next, so a rename is a breaking change for a
    consumer. Editing this list is the deliberate act that makes one.
    """
    assert [c.id for c in VEX_FINDING_CLASSES] == [
        "AISBOM-PICKLE-RCE",
        "AISBOM-PICKLE-CODE-OBJECT",
        "AISBOM-PICKLE-UNSCANNED",
        "AISBOM-KERAS-LAMBDA-RCE",
        "AISBOM-GGUF-TEMPLATE-INJECTION",
        "AISBOM-ONNX-CUSTOM-OP",
        "AISBOM-ONNX-EXTERNAL-DATA",
    ]


def test_every_published_identifier_is_still_resolvable():
    """The compatibility promise, mechanically enforced.

    These strings live in documents on other people's disks long after the
    scan — build gates match them, and year-on-year comparisons key on them.
    Dropping one breaks those *silently*, so the guarantee is not "never
    rename" but "never break a consumer": a retired identifier must still
    resolve, either because it is still emitted or because its successor
    carries it in `aliases`.

    If this fails, do not edit the published list — add the missing identifier
    to the successor class's `aliases` instead.
    """
    live = {c.id for c in VEX_FINDING_CLASSES}
    aliased = {alias for c in VEX_FINDING_CLASSES for alias in c.aliases}
    for published in PUBLISHED_FINDING_CLASS_IDS:
        assert published in live or published in aliased, (
            f"{published} was published and is no longer resolvable — alias it "
            "from whichever class replaced it."
        )


def test_published_list_covers_every_live_class():
    """A new class must be recorded as published, or the promise has a hole."""
    assert {c.id for c in VEX_FINDING_CLASSES} <= set(PUBLISHED_FINDING_CLASS_IDS)


def test_published_identifiers_are_unique():
    """An identifier is never reused for a different meaning."""
    assert len(set(PUBLISHED_FINDING_CLASS_IDS)) == len(PUBLISHED_FINDING_CLASS_IDS)


def test_a_renamed_class_still_reaches_the_documents_by_its_old_name(
    openvex_validator,
):
    """The escape hatch must work on the day it is needed, not in principle.

    `aliases` is empty for every class today, so without this test both
    emitters' alias branches would ship having never produced a document — and
    the migration path would be discovered broken at exactly the moment it was
    needed. Simulates the supported rename: the successor carries the retired
    identifier, and a consumer matching the old string still finds it in both
    flavors.
    """
    import dataclasses

    renamed = dataclasses.replace(
        FINDING_CLASSES_BY_ID["AISBOM-PICKLE-RCE"],
        id="AISBOM-PICKLE-EXEC",
        aliases=("AISBOM-PICKLE-RCE", "CVE-9999-0001"),
    )
    statements = [
        dataclasses.replace(s, finding_class=renamed)
        for s in derive_statements([_artifact(threats=["os.system"])])
        if s.finding_class.id == "AISBOM-PICKLE-RCE"
    ]

    ovex = json.loads(generate_openvex(statements, sbom_serial=SERIAL))
    openvex_validator.validate(ovex)
    assert ovex["statements"][0]["vulnerability"]["aliases"] == [
        "AISBOM-PICKLE-RCE", "CVE-9999-0001"
    ]

    cdx_json = generate_cyclonedx_vex(statements, sbom_serial=SERIAL)
    _assert_cdx_valid(cdx_json)
    cdx = json.loads(cdx_json)
    referenced = {r["id"] for r in cdx["vulnerabilities"][0]["references"]}
    assert "AISBOM-PICKLE-RCE" in referenced


def test_emitters_accept_a_statement_whose_class_is_not_in_the_registry(
    openvex_validator,
):
    """Both emitters must serialize a statement AIsbom did not define.

    This is the shape an OSV-sourced dependency CVE will arrive in: a real
    CVE identifier that is deliberately *not* a member of
    `VEX_FINDING_CLASSES`. The module's premise is that the emitters take
    statements and do not care where one came from, so this must work before
    that integration is written, not after.
    """
    from aisbom.vex import FindingClass, VexStatement

    cve = FindingClass(
        id="CVE-2024-3568",
        title="Arbitrary code execution in a pinned dependency",
        description="A published vulnerability in a requirements.txt pin.",
        action="Upgrade to the fixed version.",
        formats=frozenset({"pickle"}),
    )
    statements = [
        VexStatement(
            finding_class=cve,
            product_ref="artifact-0-model.pt",
            product_id="",
            product_hash=SHA_A,
            status="affected",
            status_notes="Reported by the dependency scanner.",
            action_statement=cve.action,
        )
    ]

    ovex = json.loads(generate_openvex(statements, sbom_serial=SERIAL))
    openvex_validator.validate(ovex)
    assert ovex["statements"][0]["vulnerability"]["name"] == "CVE-2024-3568"

    cdx_json = generate_cyclonedx_vex(statements, sbom_serial=SERIAL)
    _assert_cdx_valid(cdx_json)
    assert json.loads(cdx_json)["vulnerabilities"][0]["id"] == "CVE-2024-3568"


def test_registry_publishes_the_compatibility_policy():
    text = _DOCS_REGISTRY.read_text()
    assert "Compatibility policy" in text
    assert "never deleted" in text
    assert "never reused" in text
    assert "`aliases`" in text


def test_no_finding_class_is_shaped_like_a_cve():
    """A finding class must never be mistakable for a CVE identifier."""
    for cls in VEX_FINDING_CLASSES:
        assert cls.id.startswith("AISBOM-")
        assert not cls.id.startswith("CVE-")
        assert cls.iri == f"{VEX_NAMESPACE}{cls.id}"


def test_no_class_aliases_a_picklescan_cve():
    """The corpus CVEs are picklescan bugs, not model vulnerabilities.

    CVE-2025-1889/1944/1945, CVE-2025-10155/10156/10157 and CVE-2025-1716 all
    describe *another scanner* failing to detect something. Aliasing an AIsbom
    finding to one would assert a relationship that does not exist, in a
    document a regulator may read.
    """
    picklescan_cves = {
        "CVE-2025-1716", "CVE-2025-1889", "CVE-2025-1944", "CVE-2025-1945",
        "CVE-2025-10155", "CVE-2025-10156", "CVE-2025-10157",
    }
    for cls in VEX_FINDING_CLASSES:
        assert not (set(cls.aliases) & picklescan_cves)


def test_published_registry_matches_the_table():
    """`docs/vex-finding-classes.md` is generated; drift fails the suite."""
    assert _DOCS_REGISTRY.read_text() == finding_classes_markdown()


def test_registry_states_these_are_not_cves():
    text = _DOCS_REGISTRY.read_text()
    assert "not CVE identifiers" in text
    for cls in VEX_FINDING_CLASSES:
        assert f"`{cls.id}`" in text


# --------------------------------------------------------------------------
# Status paths — all four, both directions
# --------------------------------------------------------------------------

def test_affected_pickle_rce(openvex_validator):
    doc = _openvex([_artifact(threats=["os.system"])])
    openvex_validator.validate(doc)

    affected = [s for s in doc["statements"] if s["status"] == "affected"]
    assert len(affected) == 1
    stmt = affected[0]
    assert stmt["vulnerability"]["name"] == "AISBOM-PICKLE-RCE"
    assert stmt["vulnerability"]["@id"] == f"{VEX_NAMESPACE}AISBOM-PICKLE-RCE"
    assert "os.system" in stmt["status_notes"]
    # The spec says an `affected` statement SHOULD describe remediation.
    assert stmt["action_statement"]
    assert stmt["action_statement_timestamp"]
    # ...and MUST NOT carry a justification, which is a `not_affected` field.
    assert "justification" not in stmt


def test_not_affected_carries_a_justification(openvex_validator):
    doc = _openvex([_artifact(name="model.safetensors", framework="SafeTensors")])
    openvex_validator.validate(doc)

    pickle_rce = [
        s for s in doc["statements"]
        if s["vulnerability"]["name"] == "AISBOM-PICKLE-RCE"
    ]
    assert len(pickle_rce) == 1
    assert pickle_rce[0]["status"] == "not_affected"
    assert pickle_rce[0]["justification"] == JUSTIFICATION_CODE_NOT_PRESENT
    assert "no Python pickle stream" in pickle_rce[0]["status_notes"]
    assert "action_statement" not in pickle_rce[0]


def test_under_investigation_when_the_stream_was_not_fully_read(openvex_validator):
    """An incomplete scan must not be reported as a clean one.

    This is the nullifAI class (#107): a deliberately broken stream ends the
    disassembly early. Reporting `not_affected` there would turn an evasion
    into a clean bill of health.
    """
    doc = _openvex([_artifact(scan_incomplete=True)])
    openvex_validator.validate(doc)

    assert _statuses(doc, "AISBOM-PICKLE-RCE") == ["under_investigation"]
    assert _statuses(doc, "AISBOM-PICKLE-UNSCANNED") == ["under_investigation"]
    for stmt in doc["statements"]:
        if stmt["status"] == "under_investigation":
            assert "justification" not in stmt


def test_fixed_requires_a_baseline_that_saw_the_finding(openvex_validator):
    """`fixed` is the one status a single scan cannot honestly assert."""
    baseline = {
        "artifact-0-model.pt": {"AISBOM-PICKLE-RCE": "affected"},
    }
    doc = _openvex([_artifact()], baseline=baseline)
    openvex_validator.validate(doc)

    assert _statuses(doc, "AISBOM-PICKLE-RCE") == ["fixed"]
    fixed = [s for s in doc["statements"] if s["status"] == "fixed"][0]
    assert "Present in the baseline SBOM" in fixed["status_notes"]
    # `fixed` is not a `not_affected`, so it carries no justification.
    assert "justification" not in fixed


def test_no_baseline_means_no_fixed_statement(openvex_validator):
    doc = _openvex([_artifact()])
    openvex_validator.validate(doc)
    assert "fixed" not in {s["status"] for s in doc["statements"]}


def test_a_still_affected_finding_is_not_reported_fixed():
    """A baseline finding that is still present stays `affected`."""
    baseline = {"artifact-0-model.pt": {"AISBOM-PICKLE-RCE": "affected"}}
    doc = _openvex([_artifact(threats=["os.system"])], baseline=baseline)
    assert _statuses(doc, "AISBOM-PICKLE-RCE") == ["affected"]


# --------------------------------------------------------------------------
# Scoped negatives — the claim must match what AIsbom actually checked
# --------------------------------------------------------------------------

def test_negatives_are_scoped_to_formats_the_class_applies_to():
    """No vacuous statements: an ONNX class says nothing about SafeTensors."""
    doc = _openvex([_artifact(name="model.safetensors", framework="SafeTensors")])
    named = {s["vulnerability"]["name"] for s in doc["statements"]}
    assert named == {"AISBOM-PICKLE-RCE"}


def test_keras_never_receives_a_pickle_rce_claim():
    """`_inspect_keras` does not disassemble pickles, so it cannot clear one.

    The Keras path reads the model config with `scan_keras_config`, never
    `scan_pickle_stream`. A `not_affected` pickle-RCE claim on a `.keras`
    container would assert a check that never ran.
    """
    doc = _openvex([_artifact(name="m.keras", framework="Keras")])
    named = {s["vulnerability"]["name"] for s in doc["statements"]}
    assert "AISBOM-PICKLE-RCE" not in named
    assert named == {"AISBOM-KERAS-LAMBDA-RCE"}


def test_a_clean_scanned_pickle_gets_a_negative_on_its_own_terms():
    """`not_affected` for a real pickle reads as "disassembled, found nothing"."""
    doc = _openvex([_artifact()])
    pickle_rce = [
        s for s in doc["statements"]
        if s["vulnerability"]["name"] == "AISBOM-PICKLE-RCE"
    ][0]
    assert pickle_rce["status"] == "not_affected"
    assert "disassembled in full" in pickle_rce["status_notes"]


def test_an_unrecognised_format_produces_no_statements():
    doc = _openvex([_artifact(name="notes.txt", framework="Text")])
    assert doc["statements"] == []


@pytest.mark.parametrize(
    "framework,name,expected",
    [
        ("SafeTensors", "m.safetensors", {"AISBOM-PICKLE-RCE"}),
        ("GGUF", "m.gguf", {"AISBOM-PICKLE-RCE", "AISBOM-GGUF-TEMPLATE-INJECTION"}),
        (
            "ONNX",
            "m.onnx",
            {
                "AISBOM-PICKLE-RCE",
                "AISBOM-ONNX-CUSTOM-OP",
                "AISBOM-ONNX-EXTERNAL-DATA",
            },
        ),
        ("Keras", "m.keras", {"AISBOM-KERAS-LAMBDA-RCE"}),
        (
            "PyTorch",
            "m.pt",
            {
                "AISBOM-PICKLE-RCE",
                "AISBOM-PICKLE-CODE-OBJECT",
                "AISBOM-PICKLE-UNSCANNED",
            },
        ),
        (
            "Joblib",
            "m.joblib",
            {
                "AISBOM-PICKLE-RCE",
                "AISBOM-PICKLE-CODE-OBJECT",
                "AISBOM-PICKLE-UNSCANNED",
            },
        ),
    ],
)
def test_each_format_gets_exactly_its_own_classes(framework, name, expected):
    doc = _openvex([_artifact(name=name, framework=framework)])
    assert {s["vulnerability"]["name"] for s in doc["statements"]} == expected


# --------------------------------------------------------------------------
# Per-format detections
# --------------------------------------------------------------------------

def test_dill_code_objects_are_their_own_class():
    doc = _openvex([_artifact(dill_code_objects=True)])
    assert _statuses(doc, "AISBOM-PICKLE-CODE-OBJECT") == ["affected"]
    # No dangerous global was found, so the RCE class stays negative.
    assert _statuses(doc, "AISBOM-PICKLE-RCE") == ["not_affected"]


def test_keras_lambda_layer_is_affected_and_names_the_layer():
    doc = _openvex([
        _artifact(
            name="m.keras",
            framework="Keras",
            threats=["KERAS_LAMBDA: scrub"],
            lambda_layers=["scrub"],
        )
    ])
    stmt = [
        s for s in doc["statements"]
        if s["vulnerability"]["name"] == "AISBOM-KERAS-LAMBDA-RCE"
    ][0]
    assert stmt["status"] == "affected"
    assert "scrub" in stmt["status_notes"]
    assert "safe_mode=True" in stmt["action_statement"]


def test_gguf_template_threat_is_affected():
    doc = _openvex([
        _artifact(
            name="m.gguf",
            framework="GGUF",
            chat_template_present=True,
            chat_template_threats=["JINJA_SANDBOX_ESCAPE: __class__"],
        )
    ])
    assert _statuses(doc, "AISBOM-GGUF-TEMPLATE-INJECTION") == ["affected"]


def test_gguf_clean_template_is_distinguished_from_no_template():
    inspected = _openvex([
        _artifact(name="m.gguf", framework="GGUF", chat_template_present=True)
    ])
    absent = _openvex([_artifact(name="m.gguf", framework="GGUF")])

    inspected_note = [
        s for s in inspected["statements"]
        if s["vulnerability"]["name"] == "AISBOM-GGUF-TEMPLATE-INJECTION"
    ][0]["status_notes"]
    absent_note = [
        s for s in absent["statements"]
        if s["vulnerability"]["name"] == "AISBOM-GGUF-TEMPLATE-INJECTION"
    ][0]["status_notes"]

    assert "was inspected" in inspected_note
    assert "no chat template" in absent_note


def test_truncated_gguf_metadata_is_under_investigation():
    """"We did not finish looking" is not "nothing is there"."""
    doc = _openvex([
        _artifact(name="m.gguf", framework="GGUF", metadata_truncated=True)
    ])
    assert _statuses(doc, "AISBOM-GGUF-TEMPLATE-INJECTION") == [
        "under_investigation"
    ]


# --------------------------------------------------------------------------
# Incomplete reads must never be reported as clean.
#
# Found by scanning a live target, not by a fixture: `hf://google-bert/
# bert-base-uncased` ships a `tf_model.h5` whose Keras config exceeds the read
# budget over a range request, and the first version of this module answered
# "declares no Lambda layer" for it. For a remote `.h5` that is the *common*
# case, not an edge case.
# --------------------------------------------------------------------------

def test_truncated_keras_config_is_under_investigation():
    doc = _openvex([
        _artifact(
            name="tf_model.h5",
            framework="Keras",
            container="hdf5",
            config_found=True,
            truncated=True,
            threats=[],
        )
    ])
    assert _statuses(doc, "AISBOM-KERAS-LAMBDA-RCE") == ["under_investigation"]
    stmt = doc["statements"][0]
    assert "not read in full" in stmt["status_notes"]
    assert "justification" not in stmt


def test_keras_config_never_located_is_under_investigation():
    """No config was inspected, so there is nothing to clear."""
    doc = _openvex([
        _artifact(name="m.keras", framework="Keras", config_found=False)
    ])
    assert _statuses(doc, "AISBOM-KERAS-LAMBDA-RCE") == ["under_investigation"]


def test_fully_read_keras_config_is_still_cleared():
    """The guard must not swallow the negative it is scoping."""
    doc = _openvex([
        _artifact(
            name="m.keras",
            framework="Keras",
            config_found=True,
            truncated=False,
            threats=[],
        )
    ])
    assert _statuses(doc, "AISBOM-KERAS-LAMBDA-RCE") == ["not_affected"]


def test_a_truncated_keras_read_still_reports_a_payload_it_did_see():
    """Truncation downgrades a negative, never a positive."""
    doc = _openvex([
        _artifact(
            name="m.keras",
            framework="Keras",
            config_found=True,
            truncated=True,
            threats=["KERAS_LAMBDA: scrub"],
            lambda_layers=["scrub"],
        )
    ])
    assert _statuses(doc, "AISBOM-KERAS-LAMBDA-RCE") == ["affected"]


def test_truncated_onnx_graph_is_under_investigation():
    doc = _openvex([
        _artifact(name="m.onnx", framework="ONNX", parsed=True, truncated=True)
    ])
    assert _statuses(doc, "AISBOM-ONNX-CUSTOM-OP") == ["under_investigation"]
    assert _statuses(doc, "AISBOM-ONNX-EXTERNAL-DATA") == ["under_investigation"]


def test_unparsable_onnx_is_under_investigation():
    doc = _openvex([
        _artifact(name="m.onnx", framework="ONNX", parsed=False, truncated=False)
    ])
    assert _statuses(doc, "AISBOM-ONNX-CUSTOM-OP") == ["under_investigation"]


def test_fully_walked_onnx_graph_is_still_cleared():
    doc = _openvex([
        _artifact(name="m.onnx", framework="ONNX", parsed=True, truncated=False)
    ])
    assert _statuses(doc, "AISBOM-ONNX-CUSTOM-OP") == ["not_affected"]
    assert _statuses(doc, "AISBOM-ONNX-EXTERNAL-DATA") == ["not_affected"]


def test_onnx_custom_ops_and_external_data_are_separate_classes():
    doc = _openvex([
        _artifact(
            name="m.onnx",
            framework="ONNX",
            custom_ops=[{"domain": "com.evil", "op_type": "Run"}],
            external_data=[{"location": "../../etc/passwd"}],
            threats=["ONNX_EXTERNAL_DATA_ESCAPE: ../../etc/passwd"],
        )
    ])
    assert _statuses(doc, "AISBOM-ONNX-CUSTOM-OP") == ["affected"]
    escape = [
        s for s in doc["statements"]
        if s["vulnerability"]["name"] == "AISBOM-ONNX-EXTERNAL-DATA"
    ][0]
    assert escape["status"] == "affected"
    assert "outside the model directory" in escape["status_notes"]


# --------------------------------------------------------------------------
# Cross-reference to the SBOM (AC #3)
# --------------------------------------------------------------------------

def test_products_address_the_sbom_component_by_serial_and_bom_ref():
    doc = _openvex([_artifact(), _artifact(name="other.pt", artifact_hash=SHA_B)])
    ids = {s["products"][0]["@id"] for s in doc["statements"]}
    assert ids == {
        f"{SERIAL}#artifact-0-model.pt",
        f"{SERIAL}#artifact-1-other.pt",
    }


def test_same_named_artifacts_stay_distinct():
    """Artifact names are basenames, so two trees can hold the same one."""
    doc = _openvex([
        _artifact(name="model.pt", artifact_hash=SHA_A),
        _artifact(name="model.pt", artifact_hash=SHA_B),
    ])
    ids = {s["products"][0]["@id"] for s in doc["statements"]}
    assert ids == {
        f"{SERIAL}#artifact-0-model.pt",
        f"{SERIAL}#artifact-1-model.pt",
    }


def test_sentinel_hashes_are_never_emitted():
    """Remote scans store `remote_unhashed`; it is not a SHA-256."""
    doc = _openvex([_artifact(artifact_hash="remote_unhashed")])
    for stmt in doc["statements"]:
        assert "hashes" not in stmt["products"][0]


def test_real_hashes_are_emitted_under_the_spec_key():
    doc = _openvex([_artifact()])
    assert doc["statements"][0]["products"][0]["hashes"] == {"sha-256": SHA_A}


# --------------------------------------------------------------------------
# CycloneDX VEX
# --------------------------------------------------------------------------

def test_cyclonedx_vex_validates_against_the_strict_1_7_schema():
    statements = derive_statements([
        _artifact(threats=["os.system"]),
        _artifact(name="m.safetensors", framework="SafeTensors", artifact_hash=SHA_B),
    ])
    _assert_cdx_valid(generate_cyclonedx_vex(statements, sbom_serial=SERIAL))


def test_cyclonedx_vex_maps_every_openvex_status():
    """The two vocabularies differ; the mapping must be total."""
    baseline = {"artifact-3-fixed.pt": {"AISBOM-PICKLE-RCE": "affected"}}
    statements = derive_statements(
        [
            _artifact(name="bad.pt", threats=["os.system"]),
            _artifact(name="clean.safetensors", framework="SafeTensors"),
            _artifact(name="partial.pt", scan_incomplete=True),
            _artifact(name="fixed.pt"),
        ],
        baseline,
    )
    doc = json.loads(generate_cyclonedx_vex(statements, sbom_serial=SERIAL))
    states = {v["analysis"]["state"] for v in doc["vulnerabilities"]}
    assert states == {"exploitable", "not_affected", "in_triage", "resolved"}
    _assert_cdx_valid(generate_cyclonedx_vex(statements, sbom_serial=SERIAL))


def test_cyclonedx_vex_does_not_claim_one_state_for_conflicting_components():
    """A repo can hold a malicious .pt and a clean .safetensors at once.

    CycloneDX scopes one `analysis` per vulnerability entry, so the same class
    reaching different conclusions must split into separate entries — otherwise
    one of the two components is described wrongly.
    """
    statements = derive_statements([
        _artifact(name="bad.pt", threats=["os.system"]),
        _artifact(name="clean.safetensors", framework="SafeTensors", artifact_hash=SHA_B),
    ])
    doc = json.loads(generate_cyclonedx_vex(statements, sbom_serial=SERIAL))

    rce = [v for v in doc["vulnerabilities"] if v["id"] == "AISBOM-PICKLE-RCE"]
    assert len(rce) == 2
    by_state = {v["analysis"]["state"]: v for v in rce}
    assert by_state["exploitable"]["affects"] == [{"ref": "artifact-0-bad.pt"}]
    assert by_state["not_affected"]["affects"] == [
        {"ref": "artifact-1-clean.safetensors"}
    ]


def test_cyclonedx_vex_names_aisbom_as_the_source():
    """An unfamiliar ID must not read as an orphan."""
    statements = derive_statements([_artifact(threats=["os.system"])])
    doc = json.loads(generate_cyclonedx_vex(statements, sbom_serial=SERIAL))
    entry = doc["vulnerabilities"][0]
    assert entry["source"]["name"] == "AIsbom"
    assert entry["source"]["url"].startswith(VEX_NAMESPACE)
    assert entry["recommendation"]


def test_cyclonedx_vex_links_back_to_the_sbom():
    statements = derive_statements([_artifact()])
    doc = json.loads(generate_cyclonedx_vex(statements, sbom_serial=SERIAL))
    assert doc["serialNumber"] == SERIAL
    assert doc["externalReferences"][0]["type"] == "bom"
    assert doc["externalReferences"][0]["url"] == SERIAL


def test_cyclonedx_affects_refs_match_the_openvex_products():
    """Both flavors must address the same components (AC #3)."""
    artifacts = [
        _artifact(threats=["os.system"]),
        _artifact(name="m.gguf", framework="GGUF", artifact_hash=SHA_B),
    ]
    statements = derive_statements(artifacts)
    cdx = json.loads(generate_cyclonedx_vex(statements, sbom_serial=SERIAL))
    ovex = json.loads(generate_openvex(statements, sbom_serial=SERIAL))

    cdx_refs = {a["ref"] for v in cdx["vulnerabilities"] for a in v["affects"]}
    ovex_refs = {
        s["products"][0]["@id"].split("#", 1)[1] for s in ovex["statements"]
    }
    assert cdx_refs == ovex_refs


def test_cyclonedx_vex_is_empty_but_valid_when_nothing_was_scanned():
    doc_json = generate_cyclonedx_vex([], sbom_serial=SERIAL)
    _assert_cdx_valid(doc_json)
    assert json.loads(doc_json)["vulnerabilities"] == []


# --------------------------------------------------------------------------
# Baseline reading
# --------------------------------------------------------------------------

def test_baseline_findings_reads_structured_properties():
    sbom = {
        "components": [
            {
                "bom-ref": "artifact-0-model.pt",
                "name": "model.pt",
                "properties": [
                    {"name": "aisbom:format", "value": "pickle"},
                    {"name": "aisbom:pickle:opcode", "value": "os.system"},
                ],
            }
        ]
    }
    findings = baseline_findings(sbom)
    assert findings["artifact-0-model.pt"]["AISBOM-PICKLE-RCE"] == "affected"


def test_baseline_findings_degrades_to_the_description_for_pre_54_sboms():
    """A baseline older than #53/#54 carries no `aisbom:*` properties.

    Reading nothing there would report a clean baseline and turn every
    pre-existing finding into a spurious `fixed` — the worst possible failure
    mode for a remediation-evidence artifact.
    """
    sbom = {
        "components": [
            {
                "bom-ref": "artifact-0-model.pt",
                "name": "model.pt",
                "description": (
                    "Risk: CRITICAL (RCE Detected: os.system, builtins.eval) | "
                    "Framework: PyTorch | Legal: PASS | License: MIT"
                ),
            }
        ]
    }
    findings = baseline_findings(sbom)
    assert findings["artifact-0-model.pt"]["AISBOM-PICKLE-RCE"] == "affected"


def test_pre_54_baseline_does_not_manufacture_a_fixed_statement():
    """End to end: an old baseline still suppresses a false `fixed`."""
    sbom = {
        "components": [
            {
                "bom-ref": "artifact-0-model.pt",
                "description": (
                    "Risk: CRITICAL (RCE Detected: os.system) | "
                    "Framework: PyTorch | Legal: PASS | License: MIT"
                ),
            }
        ]
    }
    doc = _openvex([_artifact(threats=["os.system"])], baseline=baseline_findings(sbom))
    assert _statuses(doc, "AISBOM-PICKLE-RCE") == ["affected"]


def test_baseline_findings_accepts_a_path(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({
        "components": [
            {
                "bom-ref": "artifact-0-model.pt",
                "properties": [
                    {"name": "aisbom:format", "value": "pickle"},
                    {"name": "aisbom:pickle:opcode", "value": "os.system"},
                ],
            }
        ]
    }))
    findings = baseline_findings(str(path))
    assert findings["artifact-0-model.pt"]["AISBOM-PICKLE-RCE"] == "affected"


def test_baseline_findings_skips_components_without_a_ref_or_format():
    sbom = {
        "components": [
            {"name": "no-ref", "properties": [{"name": "aisbom:format", "value": "pickle"}]},
            {"bom-ref": "lib-1", "name": "torch", "version": "2.0.1"},
        ]
    }
    assert baseline_findings(sbom) == {}


def test_signals_from_component_reads_onnx_counts():
    sig = signals_from_component({
        "properties": [
            {"name": "aisbom:format", "value": "onnx"},
            {"name": "aisbom:onnx:custom_op_count", "value": "2"},
            {"name": "aisbom:onnx:external_data_count", "value": "1"},
            {"name": "aisbom:onnx:threat", "value": "ONNX_EXTERNAL_DATA_ESCAPE: ../x"},
        ]
    })
    assert sig["onnx_custom_ops"] == 2
    assert sig["onnx_external_data"] == 1
    assert sig["onnx_external_escape"] is True


def test_signals_from_component_splits_keras_lambda_csv():
    sig = signals_from_component({
        "properties": [
            {"name": "aisbom:format", "value": "keras"},
            {"name": "aisbom:keras:lambda_layers", "value": "scrub,decode"},
        ]
    })
    assert sig["keras_lambda_layers"] == ["scrub", "decode"]


# --------------------------------------------------------------------------
# Document shape
# --------------------------------------------------------------------------

def test_openvex_document_carries_the_required_metadata(openvex_validator):
    doc = _openvex([_artifact()])
    openvex_validator.validate(doc)
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert doc["@id"] == f"{SERIAL}#openvex"
    assert doc["author"] == "AIsbom"
    assert doc["version"] == 1
    assert doc["tooling"].startswith("aisbom-cli/")


def test_every_class_description_is_prose_a_reader_can_act_on():
    for cls in VEX_FINDING_CLASSES:
        assert cls.description.endswith(".")
        assert cls.action.endswith(".")
        assert len(cls.description) > 80
        assert FINDING_CLASSES_BY_ID[cls.id] is cls
