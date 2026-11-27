"""Declared model-card fields carried into the CycloneDX `modelCard`.

These are values the Hugging Face API already returns on the request the scan
makes, which `aisbom comply` pre-fills as *declared* values: base model,
languages, repo owner, first-published date, the server-side safetensors
parameter total, CO2 emissions and `model-index` evaluation results.
"""

import json

import pytest

from aisbom.modelcard import (
    HF_MIGRATION_CREATED_AT,
    MAX_PERFORMANCE_METRICS,
    QUANTIZATION_TAGS,
    build_model_card,
    inject_model_cards,
)

from tests.test_modelcard import artifact, build_sbom, validate_1_7

# Shaped after the real meta-llama/Llama-3.1-8B-Instruct and
# distilbert-base-uncased-finetuned-sst-2-english payloads (verbatim keys).
DECLARED_META = {
    "id": "acme/sentiment-ft",
    "author": "acme",
    "createdAt": "2024-07-18T08:56:00.000Z",
    "pipeline_tag": "text-classification",
    "safetensors": {"parameters": {"F32": 66955010}, "total": 66955010},
    "cardData": {
        "base_model": "distilbert/distilbert-base-uncased",
        "language": ["en", "de"],
        "co2_eq_emissions": {
            "emissions": 149.2,
            "source": "codecarbon",
            "training_type": "fine-tuning",
            "geographical_location": "Frankfurt, Germany",
            "hardware_used": "1 x A100",
        },
        "model-index": [
            {
                "name": "sentiment-ft",
                "results": [
                    {
                        "task": {"type": "text-classification", "name": "Text Classification"},
                        "dataset": {"name": "glue", "type": "glue", "config": "sst2",
                                    "split": "validation"},
                        "metrics": [
                            {"type": "accuracy", "value": 0.9105504587155964, "name": "Accuracy"},
                            {"type": "f1", "value": 0.914, "verified": True},
                        ],
                    }
                ],
            }
        ],
    },
}


def props_of(card):
    out = {}
    for p in card.get("properties", []):
        out.setdefault(p["name"], []).append(p["value"])
    return out


def test_declared_fields_become_hf_properties():
    props = props_of(build_model_card(artifact(), DECLARED_META))

    assert props["aisbom:hf:author"] == ["acme"]
    assert props["aisbom:hf:base_model"] == ["distilbert/distilbert-base-uncased"]
    assert props["aisbom:hf:language"] == ["en", "de"]
    assert props["aisbom:hf:created_at"] == ["2024-07-18T08:56:00.000Z"]
    assert props["aisbom:hf:parameters_total"] == ["66955010"]
    assert props["aisbom:hf:co2_eq_emissions"] == ["149.2"]
    assert props["aisbom:hf:co2_eq_emissions:source"] == ["codecarbon"]
    assert props["aisbom:hf:co2_eq_emissions:training_type"] == ["fine-tuning"]
    assert props["aisbom:hf:co2_eq_emissions:hardware_used"] == ["1 x A100"]
    assert props["aisbom:hf:co2_eq_emissions:geographical_location"] == ["Frankfurt, Germany"]


def test_model_index_results_become_typed_performance_metrics():
    card = build_model_card(artifact(), DECLARED_META)

    assert card["quantitativeAnalysis"]["performanceMetrics"] == [
        {"type": "accuracy", "value": "0.9105504587155964",
         "slice": "text-classification on glue (sst2, validation)"},
        {"type": "f1", "value": "0.914",
         "slice": "text-classification on glue (sst2, validation)"},
    ]
    assert "aisbom:hf:model_index_truncated" not in props_of(card)


def test_base_model_and_language_as_bare_string_or_list():
    meta = {"cardData": {"base_model": ["a/one", "b/two", "a/one"], "language": "fr"}}
    props = props_of(build_model_card(artifact(), meta))
    assert props["aisbom:hf:base_model"] == ["a/one", "b/two"]
    assert props["aisbom:hf:language"] == ["fr"]


def test_quantization_format_tags_are_recorded_as_declared():
    # Shaped after hugging-quants/Meta-Llama-3.1-8B-Instruct-AWQ-INT4's tags.
    meta = {"id": "a/b", "tags": [
        "transformers", "safetensors", "llama", "text-generation", "AWQ",
        "4-bit", "awq", "conversational", "region:us", "license:llama3.1",
    ]}
    props = props_of(build_model_card(artifact(), meta))
    # Recorded as Hugging Face states them, matched without regard to case,
    # and de-duplicated by that match: "AWQ" and "awq" are one declaration.
    assert props["aisbom:hf:quantization_tag"] == ["AWQ", "4-bit"]


def test_every_quantization_tag_in_the_fixed_set_is_recognised():
    meta = {"id": "a/b", "tags": sorted(QUANTIZATION_TAGS)}
    props = props_of(build_model_card(artifact(), meta))
    assert props["aisbom:hf:quantization_tag"] == sorted(QUANTIZATION_TAGS)


@pytest.mark.parametrize("tags", [None, "gguf", 7, [], ["transformers", "region:us"],
                                  [3, None, {"gguf": 1}], ["gguf-my-repo", "base_model:quantized:a/b"]])
def test_no_quantization_tag_without_a_listed_format_tag(tags):
    props = props_of(build_model_card(artifact(), {"id": "a/b", "tags": tags}))
    assert "aisbom:hf:quantization_tag" not in props


def test_co2_given_as_a_bare_number():
    meta = {"cardData": {"co2_eq_emissions": 42}}
    props = props_of(build_model_card(artifact(), meta))
    assert props["aisbom:hf:co2_eq_emissions"] == ["42"]
    assert "aisbom:hf:co2_eq_emissions:source" not in props


def test_hf_migration_timestamp_is_not_recorded_as_first_published():
    """Repos older than HF's 2022 migration all carry the same `createdAt`,
    which is when HF migrated them, not when they were published."""
    meta = {"id": "google-bert/bert-base-uncased", "createdAt": HF_MIGRATION_CREATED_AT}
    props = props_of(build_model_card(artifact(), meta))
    assert "aisbom:hf:created_at" not in props


@pytest.mark.parametrize("total", [0, -5, "110", None, True, 1.5])
def test_implausible_parameter_totals_are_ignored(total):
    meta = {"id": "a/b", "safetensors": {"total": total}}
    props = props_of(build_model_card(artifact(), meta))
    assert "aisbom:hf:parameters_total" not in props


@pytest.mark.parametrize(
    "card_data",
    [
        {"base_model": 7, "language": {"en": 1}, "co2_eq_emissions": "lots",
         "model-index": "nope"},
        {"model-index": [{"results": [{"metrics": [{"type": "acc"}]}]}]},  # no value
        {"model-index": [{"results": [{"metrics": [{"value": 0.5}]}]}]},   # no type
        {"model-index": [{"results": "bad"}]},
        {"co2_eq_emissions": {"source": "x"}},  # no emissions figure
    ],
)
def test_malformed_declared_fields_are_absent_not_raised(card_data):
    card = build_model_card(artifact(), {"id": "a/b", "cardData": card_data}) or {}
    props = props_of(card)
    for key in ("aisbom:hf:base_model", "aisbom:hf:language", "aisbom:hf:co2_eq_emissions"):
        assert key not in props
    assert "quantitativeAnalysis" not in card


def test_model_index_without_task_or_dataset_still_records_the_metric():
    meta = {"cardData": {"model-index": [{"results": [{"metrics": [
        {"type": "accuracy", "value": 0.5}]}]}]}}
    card = build_model_card(artifact(), meta)
    assert card["quantitativeAnalysis"]["performanceMetrics"] == [
        {"type": "accuracy", "value": "0.5"}
    ]


def test_model_index_is_capped_and_the_cap_is_recorded():
    metrics = [{"type": f"m{i}", "value": i} for i in range(MAX_PERFORMANCE_METRICS + 5)]
    meta = {"cardData": {"model-index": [{"results": [{"metrics": metrics}]}]}}
    card = build_model_card(artifact(), meta)
    assert len(card["quantitativeAnalysis"]["performanceMetrics"]) == MAX_PERFORMANCE_METRICS
    assert props_of(card)["aisbom:hf:model_index_truncated"] == [
        str(MAX_PERFORMANCE_METRICS + 5)
    ]


def test_declared_card_validates_against_strict_1_7_schema():
    art = artifact()
    doc = inject_model_cards(build_sbom([art]), [art], DECLARED_META)
    validate_1_7(doc)
    comp = json.loads(doc)["components"][0]
    assert comp["modelCard"]["quantitativeAnalysis"]["performanceMetrics"]


def test_existing_fields_are_unchanged_by_the_new_ones():
    """Additive only: the existing model-card fields come out exactly as before."""
    from tests.test_modelcard import FULL_HF_META

    before = build_model_card(artifact(), FULL_HF_META)
    after = build_model_card(artifact(), dict(FULL_HF_META, **{
        "author": "google-bert",
        "safetensors": {"total": 110106428},
    }))
    assert after["modelParameters"] == before["modelParameters"]
    old = [p for p in after["properties"] if p in before["properties"]]
    assert old == before["properties"]
