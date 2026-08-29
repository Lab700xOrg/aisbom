"""Tests for CycloneDX 1.7 ML-BOM `modelCard` generation (#111).

Three layers, because the splice bypasses the library's type checks:

1. Pure mapping — `build_model_card` against populated / sparse / absent HF
   metadata.
2. Injection — which components get a card, and which must not.
3. Schema validation — every generated document is checked against the
   bundled `bom-1.7.SNAPSHOT.schema.json` with the *strict* validator. The 1.7
   schema sets `additionalProperties: false` throughout, so a misspelled key
   or a wrongly-typed value fails here rather than shipping into a compliance
   artifact.

Plus a regression guard that 1.7 output is a strict superset of 1.6 output.
"""

import json

import pytest
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot6, JsonV1Dot7
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from aisbom.modelcard import build_model_card, inject_model_cards


# --- Fixtures -------------------------------------------------------------

# Shaped after the real https://huggingface.co/api/models/google-bert/
# bert-base-uncased payload (fields we read, verbatim keys).
FULL_HF_META = {
    "id": "google-bert/bert-base-uncased",
    "modelId": "google-bert/bert-base-uncased",
    "pipeline_tag": "fill-mask",
    "library_name": "transformers",
    "sha": "86b5e0934494bd15c9632b12f734a8a67f723594",
    "gated": False,
    "private": False,
    "cardData": {
        "license": "apache-2.0",
        "datasets": ["bookcorpus", "wikipedia"],
        "language": "en",
        "tags": ["exbert"],
    },
    "config": {
        "model_type": "bert",
        "architectures": ["BertForMaskedLM"],
    },
}


def artifact(name="model.safetensors", framework="SafeTensors", **details):
    return {
        "name": name,
        "framework": framework,
        "risk_level": "LOW",
        "legal_status": "OK",
        "details": details,
    }


def validate_1_7(doc):
    """Assert a document validates against the bundled strict 1.7 schema."""
    errors = JsonStrictValidator(SchemaVersion.V1_7).validate_str(
        json.dumps(doc) if isinstance(doc, dict) else doc
    )
    assert errors is None, f"1.7 schema validation failed: {errors}"


def build_sbom(artifacts, outputter=JsonV1Dot7):
    """Serialize artifacts the way cli.py does, without invoking the CLI."""
    bom = Bom()
    for art in artifacts:
        bom.components.add(
            Component(
                name=art["name"],
                type=ComponentType.MACHINE_LEARNING_MODEL,
                description=f"Risk: {art['risk_level']} | Framework: {art['framework']}",
            )
        )
    return outputter(bom).output_as_string()


# --- build_model_card: populated metadata ---------------------------------


def test_full_hf_metadata_populates_every_mapped_field():
    card = build_model_card(artifact(), FULL_HF_META)

    assert card["modelParameters"] == {
        "task": "fill-mask",
        "architectureFamily": "bert",
        "modelArchitecture": "BertForMaskedLM",
        "datasets": [
            {"type": "dataset", "name": "bookcorpus"},
            {"type": "dataset", "name": "wikipedia"},
        ],
    }
    props = {p["name"]: p["value"] for p in card["properties"]}
    assert props["aisbom:hf:repo_id"] == "google-bert/bert-base-uncased"
    assert props["aisbom:hf:license"] == "apache-2.0"
    assert props["aisbom:hf:library_name"] == "transformers"
    assert props["aisbom:hf:revision"] == FULL_HF_META["sha"]


def test_volatile_popularity_fields_are_never_emitted():
    """`downloads`/`likes` change hourly and would produce phantom drift."""
    meta = dict(FULL_HF_META, downloads=12_345_678, likes=42)
    card = build_model_card(artifact(), meta)
    serialized = json.dumps(card)
    assert "downloads" not in serialized
    assert "likes" not in serialized


def test_hf_license_does_not_leak_into_the_legal_verdict():
    """The card's license is reported, never merged into risk/legal fields.

    Backfilling `licenses`/`legal_status` from HF would change a compliance
    judgement the platform counts on — deliberately out of scope here.
    """
    card = build_model_card(artifact(), FULL_HF_META)
    assert "licenses" not in card
    assert "legal_status" not in json.dumps(card)


# --- build_model_card: sparse and absent metadata -------------------------


def test_no_metadata_and_no_file_details_emits_no_card():
    assert build_model_card(artifact()) is None
    assert build_model_card(artifact(), None) is None
    assert build_model_card(artifact(), {}) is None


def test_sparse_metadata_emits_only_what_is_known():
    """A card with nothing but an id — every optional branch skipped."""
    card = build_model_card(artifact(), {"id": "someone/bare-model"})
    assert card == {"properties": [{"name": "aisbom:hf:repo_id", "value": "someone/bare-model"}]}


def test_missing_config_omits_architecture_fields():
    meta = {k: v for k, v in FULL_HF_META.items() if k != "config"}
    card = build_model_card(artifact(), meta)
    assert "architectureFamily" not in card["modelParameters"]
    assert "modelArchitecture" not in card["modelParameters"]
    assert card["modelParameters"]["task"] == "fill-mask"


def test_empty_and_blank_values_are_treated_as_absent():
    meta = {
        "id": "  ",
        "pipeline_tag": "",
        "library_name": None,
        "cardData": {"license": "   ", "datasets": []},
        "config": {"model_type": "", "architectures": []},
    }
    assert build_model_card(artifact(), meta) is None


def test_wrongly_typed_metadata_does_not_raise():
    """A proxy interstitial or an API change must degrade, not crash a scan."""
    meta = {"cardData": "not-a-dict", "config": ["nope"], "pipeline_tag": 42}
    assert build_model_card(artifact(), meta) is None


# --- Datasets edge cases --------------------------------------------------


def test_single_dataset_given_as_a_bare_string():
    card = build_model_card(artifact(), {"cardData": {"datasets": "imagenet"}})
    assert card["modelParameters"]["datasets"] == [{"type": "dataset", "name": "imagenet"}]


def test_duplicate_datasets_are_collapsed():
    meta = {"cardData": {"datasets": ["c4", "c4", " c4 ", "pile"]}}
    card = build_model_card(artifact(), meta)
    assert card["modelParameters"]["datasets"] == [
        {"type": "dataset", "name": "c4"},
        {"type": "dataset", "name": "pile"},
    ]


# --- Local scans benefit without any network call -------------------------


def test_local_gguf_gets_an_architecture_family_with_no_hf_metadata():
    """The GGUF header carries the family itself — no HF call involved."""
    art = artifact(name="model.gguf", framework="GGUF", architecture="llama")
    card = build_model_card(art, None)
    assert card == {"modelParameters": {"architectureFamily": "llama"}}


def test_hf_config_wins_over_the_gguf_header_when_both_exist():
    art = artifact(name="model.gguf", framework="GGUF", architecture="llama")
    card = build_model_card(art, FULL_HF_META)
    assert card["modelParameters"]["architectureFamily"] == "bert"


# --- inject_model_cards ---------------------------------------------------


def test_injects_into_the_matching_model_component():
    arts = [artifact(name="model.safetensors")]
    out = json.loads(inject_model_cards(build_sbom(arts), arts, FULL_HF_META))
    (component,) = [c for c in out["components"] if c["name"] == "model.safetensors"]
    assert component["modelCard"]["modelParameters"]["task"] == "fill-mask"


def test_library_components_never_receive_a_model_card():
    bom = Bom()
    bom.components.add(Component(name="numpy", version="2.1.0", type=ComponentType.LIBRARY))
    bom.components.add(Component(name="model.safetensors", type=ComponentType.MACHINE_LEARNING_MODEL))
    arts = [artifact(name="model.safetensors"), artifact(name="numpy")]

    out = json.loads(inject_model_cards(JsonV1Dot7(bom).output_as_string(), arts, FULL_HF_META))
    by_name = {c["name"]: c for c in out["components"]}
    assert "modelCard" in by_name["model.safetensors"]
    assert "modelCard" not in by_name["numpy"], "a library is not a model"


def test_same_named_artifacts_each_get_a_card():
    """Basename collisions across directories: one card each, not one total."""
    bom = Bom()
    for bom_ref in ("a", "b"):
        bom.components.add(
            Component(name="model.bin", bom_ref=bom_ref, type=ComponentType.MACHINE_LEARNING_MODEL)
        )
    arts = [artifact(name="model.bin"), artifact(name="model.bin")]

    out = json.loads(inject_model_cards(JsonV1Dot7(bom).output_as_string(), arts, FULL_HF_META))
    assert all("modelCard" in c for c in out["components"])


def test_no_cards_returns_the_input_byte_for_byte():
    """The sparse path must not even re-serialize — no incidental reformatting."""
    arts = [artifact()]
    original = build_sbom(arts)
    assert inject_model_cards(original, arts, None) == original


def test_malformed_input_is_returned_unchanged():
    for junk in ("not json", "", "[1,2,3]", '{"components": "nope"}'):
        assert inject_model_cards(junk, [artifact()], FULL_HF_META) == junk


def test_injection_preserves_the_serializer_formatting():
    """Re-serialization must match the library's own separators exactly."""
    arts = [artifact()]
    original = build_sbom(arts)
    spliced = inject_model_cards(original, arts, FULL_HF_META)
    # Strip the only intended difference, then the strings must be identical.
    doc = json.loads(spliced)
    for component in doc["components"]:
        component.pop("modelCard", None)
    assert json.dumps(doc) == original


# --- Schema validation ----------------------------------------------------


def test_generated_sbom_validates_against_strict_1_7_schema():
    arts = [artifact(), artifact(name="model.gguf", framework="GGUF", architecture="llama")]
    validate_1_7(inject_model_cards(build_sbom(arts), arts, FULL_HF_META))


def test_sparse_metadata_sbom_also_validates():
    arts = [artifact()]
    validate_1_7(inject_model_cards(build_sbom(arts), arts, {"id": "someone/bare-model"}))


def test_sbom_with_no_model_cards_at_all_validates():
    arts = [artifact()]
    validate_1_7(inject_model_cards(build_sbom(arts), arts, None))


@pytest.mark.parametrize(
    "meta",
    [
        FULL_HF_META,
        {"id": "x/y"},
        {"cardData": {"datasets": ["only-a-dataset"]}},
        {"pipeline_tag": "text-generation"},
        {"config": {"architectures": ["LlamaForCausalLM"]}},
        {"id": "g/g", "gated": "auto", "private": True},
    ],
)
def test_every_metadata_shape_produces_a_schema_valid_document(meta):
    """Each optional branch, validated independently — a wrong key type in any
    one of them would otherwise only surface on the models that hit it."""
    arts = [artifact()]
    validate_1_7(inject_model_cards(build_sbom(arts), arts, meta))


# --- Additive-only regression guard ---------------------------------------

# Fields whose values are expected to differ run-to-run or by spec version.
_VOLATILE_TOP_LEVEL = {"specVersion", "$schema", "serialNumber", "metadata"}


def test_1_7_output_is_a_strict_superset_of_1_6():
    """Every component key/value in 1.6 survives verbatim into 1.7.

    This is the no-regression proof for the default flip: a consumer reading
    1.6 output finds each field it relied on, unchanged, in the 1.7 document.
    """
    arts = [artifact(), artifact(name="model.gguf", framework="GGUF", architecture="llama")]
    bom_1_6 = json.loads(build_sbom(arts, outputter=JsonV1Dot6))
    bom_1_7 = json.loads(inject_model_cards(build_sbom(arts), arts, FULL_HF_META))

    old = {c["name"]: c for c in bom_1_6["components"]}
    new = {c["name"]: c for c in bom_1_7["components"]}
    assert set(old) == set(new), "1.7 must contain exactly the same components"

    for name, old_component in old.items():
        for key, value in old_component.items():
            if key == "bom-ref":
                continue  # a random UUID per run in both documents
            assert new[name][key] == value, f"{name}.{key} changed between 1.6 and 1.7"

    # And the only added component key is modelCard.
    for name, new_component in new.items():
        added = set(new_component) - set(old[name])
        assert added <= {"modelCard"}, f"{name} grew unexpected keys: {added}"


def test_only_the_spec_version_changes_at_the_top_level():
    arts = [artifact()]
    bom_1_6 = json.loads(build_sbom(arts, outputter=JsonV1Dot6))
    bom_1_7 = json.loads(build_sbom(arts, outputter=JsonV1Dot7))

    assert bom_1_6["specVersion"] == "1.6"
    assert bom_1_7["specVersion"] == "1.7"
    assert set(bom_1_6) - _VOLATILE_TOP_LEVEL == set(bom_1_7) - _VOLATILE_TOP_LEVEL
