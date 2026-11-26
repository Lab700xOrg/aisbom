"""Build CycloneDX 1.7 (ECMA-424) ``modelCard`` blocks for scanned artifacts.

Two reasons this is a post-serialization splice rather than model objects:

1. ``cyclonedx-python-lib`` (11.x) has no ``modelCard`` support — ``Component``
   accepts no such argument and the serializer has nothing to emit it from.
   The spec has carried the field since 1.5; the library simply hasn't
   modelled it. Waiting for upstream would block the slice indefinitely.
2. Splicing keeps the change strictly additive. Every component the library
   already emits is serialized by the library, byte-identical to 1.6 output;
   this module only *adds* a ``modelCard`` key to machine-learning-model
   components. Nothing existing is rewritten, so no field can regress.

The cost is that correctness rests on the shape produced here rather than on
the library's type checks — which is why ``tests/test_modelcard.py`` validates
generated SBOMs against the bundled ``bom-1.7.SNAPSHOT.schema.json`` with the
*strict* validator (``additionalProperties: false`` throughout, so a misspelled
key fails the suite rather than shipping).

Sources, in order of preference:

* Hugging Face model-card metadata — task, architecture, training datasets,
  license, library. For an ``hf://`` scan, and for a local file proven to come
  from an HF repo (:mod:`aisbom.hf_match`).
* What the scanner already parsed out of the file itself — currently the GGUF
  header's architecture. This is why a purely local scan still gets a
  ``modelCard`` without any network call at all.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .hf_match import MATCH_PROPERTY

_ML_COMPONENT_TYPE = "machine-learning-model"

# HF metadata worth carrying that has no home in the typed `modelParameters`
# block. Each maps a key in the API payload to an `aisbom:hf:*` property name,
# matching the namespacing convention in `aisbom.properties`.
#
# `downloads` and `likes` are deliberately absent: they change hourly, and an
# SBOM that differs between two scans of an unchanged model produces phantom
# drift on the platform's diff.
_HF_SCALAR_PROPERTIES = (
    ("library_name", "aisbom:hf:library_name"),
    ("sha", "aisbom:hf:revision"),
    # The repo owner. Recorded as declared; whether the owner is the model's
    # *supplier* is a rule `aisbom comply` applies, not a fact the card states.
    ("author", "aisbom:hf:author"),
)

# Every repository that predates Hugging Face's 2022 storage migration reports
# this exact `createdAt` (bert-base-uncased, published in 2018, among them).
# It is when HF migrated the repo, so recording it as "first published on
# Hugging Face" would be wrong for every older model.
HF_MIGRATION_CREATED_AT = "2022-03-02T23:29:04.000Z"

# Leaderboard-style cards list hundreds of results. A compliance pack wants the
# declared evaluation, not every row, and an unbounded list bloats every SBOM.
MAX_PERFORMANCE_METRICS = 50

# Sub-fields of a dict-shaped `co2_eq_emissions` worth carrying, as declared.
_CO2_FIELDS = ("source", "training_type", "geographical_location", "hardware_used")


def _clean_str(value: Any) -> Optional[str]:
    """Return a non-empty stripped string, or None for anything else."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _card_data(hf_meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    data = (hf_meta or {}).get("cardData")
    return data if isinstance(data, dict) else {}


def _config(hf_meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    config = (hf_meta or {}).get("config")
    return config if isinstance(config, dict) else {}


def _datasets(hf_meta: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Map ``cardData.datasets`` to inline CycloneDX ``componentData`` entries.

    The 1.7 schema allows either an inline `componentData` or a `ref` pointing
    at a data component elsewhere in the BOM. Inline is the right call here:
    HF gives us a bare dataset name and nothing else, so a referenced data
    component would be an empty shell that inflates the component count the
    platform dashboard reports as "artifacts scanned".
    """
    raw = _card_data(hf_meta).get("datasets")
    # A single-dataset card may give a bare string rather than a list.
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []

    datasets: List[Dict[str, str]] = []
    seen = set()
    for entry in raw:
        name = _clean_str(entry)
        if name is None or name in seen:
            continue
        seen.add(name)
        # `type` is required by the schema's componentData; "dataset" is the
        # only honest value for a training corpus.
        datasets.append({"type": "dataset", "name": name})
    return datasets


def _str_list(raw: Any) -> List[str]:
    """A card field given as one string or a list of strings, de-duplicated."""
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    out: List[str] = []
    for entry in raw:
        value = _clean_str(entry)
        if value and value not in out:
            out.append(value)
    return out


def _number(value: Any) -> Optional[str]:
    """A JSON number as text; bools (a JSON number's lookalike) are refused."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return str(value)


def _declared_properties(hf_meta: Dict[str, Any]) -> List[Dict[str, str]]:
    """Model-card declarations `aisbom comply` offers as *declared* values.

    Each is recorded exactly as the card or API states it. None of them is
    asserted as the answer to a regulatory field: the card's languages are not
    necessarily the training data's, and an emissions figure is not energy.
    """
    props: List[Dict[str, str]] = []
    card = _card_data(hf_meta)

    for base in _str_list(card.get("base_model")):
        props.append({"name": "aisbom:hf:base_model", "value": base})
    for language in _str_list(card.get("language")):
        props.append({"name": "aisbom:hf:language", "value": language})

    created = _clean_str(hf_meta.get("createdAt"))
    if created and created != HF_MIGRATION_CREATED_AT:
        props.append({"name": "aisbom:hf:created_at", "value": created})

    # Hugging Face computes this server-side across every safetensors shard
    # in the repo, so it does not depend on how much of the repo was scanned.
    safetensors = hf_meta.get("safetensors")
    total = safetensors.get("total") if isinstance(safetensors, dict) else None
    if isinstance(total, int) and not isinstance(total, bool) and total > 0:
        props.append({"name": "aisbom:hf:parameters_total", "value": str(total)})

    co2 = card.get("co2_eq_emissions")
    emissions = _number(co2.get("emissions") if isinstance(co2, dict) else co2)
    if emissions is not None:
        props.append({"name": "aisbom:hf:co2_eq_emissions", "value": emissions})
        if isinstance(co2, dict):
            for key in _CO2_FIELDS:
                value = _clean_str(co2.get(key))
                if value:
                    props.append({"name": f"aisbom:hf:co2_eq_emissions:{key}", "value": value})
    return props


def _slice(result: Dict[str, Any]) -> Optional[str]:
    """`text-classification on glue (sst2, validation)` from a model-index result."""
    task = result.get("task")
    task_type = _clean_str(task.get("type")) if isinstance(task, dict) else None
    dataset = result.get("dataset")
    name = qualifiers = None
    if isinstance(dataset, dict):
        name = _clean_str(dataset.get("name")) or _clean_str(dataset.get("type"))
        qualifiers = [v for v in (_clean_str(dataset.get("config")),
                                  _clean_str(dataset.get("split"))) if v]
    if name and qualifiers:
        name = f"{name} ({', '.join(qualifiers)})"
    if task_type and name:
        return f"{task_type} on {name}"
    return task_type or name


def _performance_metrics(hf_meta: Dict[str, Any]) -> Tuple[List[Dict[str, str]], int]:
    """Map the card's `model-index` to typed `performanceMetrics`, capped.

    Returns the (capped) metrics and how many the card declared in all. These
    are the card's self-reported results; `comply` labels them as declared.
    """
    raw = _card_data(hf_meta).get("model-index")
    if raw is None:
        raw = hf_meta.get("model-index")
    if not isinstance(raw, list):
        return [], 0
    metrics: List[Dict[str, str]] = []
    for model in raw:
        results = model.get("results") if isinstance(model, dict) else None
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict) or not isinstance(result.get("metrics"), list):
                continue
            where = _slice(result)
            for metric in result["metrics"]:
                if not isinstance(metric, dict):
                    continue
                kind = _clean_str(metric.get("type"))
                value = metric.get("value")
                value = _number(value) or _clean_str(value)
                if not kind or value is None:
                    continue
                entry = {"type": kind, "value": value}
                if where:
                    entry["slice"] = where
                metrics.append(entry)
    return metrics[:MAX_PERFORMANCE_METRICS], len(metrics)


def _model_parameters(art: Dict[str, Any], hf_meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the typed ``modelParameters`` block. Empty dict when nothing known.

    ``approach.type`` is intentionally never set: the schema constrains it to a
    five-value enum (supervised / unsupervised / reinforcement-learning /
    semi-supervised / self-supervised) and HF metadata carries nothing that
    maps to it without guessing. A guessed learning type in a compliance
    artifact is worse than an absent one.
    """
    params: Dict[str, Any] = {}

    task = _clean_str((hf_meta or {}).get("pipeline_tag"))
    if task:
        params["task"] = task

    config = _config(hf_meta)
    # `model_type` is the family ("bert", "llama"); `architectures[0]` is the
    # concrete head ("BertForMaskedLM"). The schema draws exactly that
    # distinction, so they are not interchangeable.
    family = _clean_str(config.get("model_type"))
    if family is None:
        # No HF metadata (a local scan, or a repo with no config): the GGUF
        # header carries the architecture family itself. This is what makes
        # local scans benefit without a network call.
        details = art.get("details") or {}
        family = _clean_str(details.get("architecture"))
    if family:
        params["architectureFamily"] = family

    architectures = config.get("architectures")
    if isinstance(architectures, list) and architectures:
        architecture = _clean_str(architectures[0])
        if architecture:
            params["modelArchitecture"] = architecture

    datasets = _datasets(hf_meta)
    if datasets:
        params["datasets"] = datasets

    return params


def _properties(art: Dict[str, Any], hf_meta: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Untyped `aisbom:hf:*` name/value pairs the typed block has no slot for."""
    props: List[Dict[str, str]] = []
    if not hf_meta:
        return props

    repo_id = _clean_str(hf_meta.get("id")) or _clean_str(hf_meta.get("modelId"))
    if repo_id:
        props.append({"name": "aisbom:hf:repo_id", "value": repo_id})

    # The card's declared license is reported here rather than merged into the
    # component's `licenses` / `legal_status`. Those two drive the platform's
    # license_issue_count and the CLI's LEGAL RISK verdict, so backfilling them
    # from HF would silently change a compliance judgement — a separate,
    # non-additive decision that does not belong in a "widen the output" slice.
    license_id = _clean_str(_card_data(hf_meta).get("license"))
    if license_id:
        props.append({"name": "aisbom:hf:license", "value": license_id})

    for key, prop_name in _HF_SCALAR_PROPERTIES:
        value = _clean_str(hf_meta.get(key))
        if value:
            props.append({"name": prop_name, "value": value})

    # Gated/private repos are worth recording: they explain why a scan saw
    # fewer files than the repo actually contains.
    if hf_meta.get("gated"):
        props.append({"name": "aisbom:hf:gated", "value": str(hf_meta["gated"])})
    if hf_meta.get("private") is True:
        props.append({"name": "aisbom:hf:private", "value": "true"})

    props.extend(_declared_properties(hf_meta))
    return props


def build_model_card(
    art: Dict[str, Any],
    hf_meta: Optional[Dict[str, Any]] = None,
    match_source: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return a CycloneDX 1.7 ``modelCard`` dict for one artifact, or None.

    None means "emit no modelCard at all" — the sparse-metadata path. An empty
    `modelCard: {}` would validate, but it is noise in a compliance artifact
    and would make every local non-GGUF scan's SBOM look like it tried and
    failed to describe the model.

    ``match_source`` is set when ``hf_meta`` belongs to a repo a *local* file
    was matched to (see :mod:`aisbom.hf_match`). It is recorded on the card so
    an inferred link is never indistinguishable from an ``hf://`` scan.
    """
    card: Dict[str, Any] = {}

    params = _model_parameters(art, hf_meta)
    if params:
        card["modelParameters"] = params

    props = _properties(art, hf_meta)
    metrics, declared = _performance_metrics(hf_meta or {})
    if metrics:
        card["quantitativeAnalysis"] = {"performanceMetrics": metrics}
        if declared > len(metrics):
            props.append({"name": "aisbom:hf:model_index_truncated", "value": str(declared)})
    # Only alongside something the match actually contributed: a card holding
    # nothing but "this was matched" would describe nothing.
    if match_source and (params or props or metrics):
        props.append({"name": MATCH_PROPERTY, "value": match_source})
    if props:
        card["properties"] = props

    return card or None


def bom_ref_for(index: int, art: Dict[str, Any]) -> str:
    """Stable `bom-ref` for a scanned artifact, used as the injection join key.

    Both sides must derive this identically: ``cli.py`` stamps it onto the
    Component at construction, and :func:`inject_model_cards` looks it up in
    the serialized document.

    The index is load-bearing, not decoration. Artifact names are file
    *basenames*, so a tree holding two ``model.gguf`` files in different
    directories yields two components with the same name — and the library
    serializes its component collection in its own sorted order, not scan
    order. Joining on name alone could therefore hand a llama model's card to
    a bert component, producing a document whose `aisbom:gguf:architecture`
    property contradicts its own `modelCard`. The index is the only field that
    is unique across artifacts in every scan shape (remote scans share the
    `remote_unhashed` sentinel, so the hash cannot serve).
    """
    return f"artifact-{index}-{art.get('name', 'unknown')}"


def dependency_bom_ref(index: int, dep: Dict[str, Any]) -> str:
    """Stable `bom-ref` for a requirements.txt dependency component.

    Left to the library this is a fresh random string on every run, which is
    what `bom_ref_for` exists to avoid for models. Dependencies need the same
    once a VEX statement addresses one: the CVE statement and the SBOM
    component are written separately and must join on this value. The index
    keeps the same package listed in two requirements files distinct.
    """
    return f"dependency-{index}-{dep.get('name', 'unknown')}"


def inject_model_cards(
    bom_json: str,
    artifacts: List[Dict[str, Any]],
    hf_meta: Optional[Dict[str, Any]] = None,
    local_matches: Optional[Mapping[int, Any]] = None,
) -> str:
    """Splice ``modelCard`` blocks into a serialized CycloneDX document.

    Joined on the `bom-ref` that ``cli.py`` stamped on each model component —
    see :func:`bom_ref_for` for why a name-based join is not sufficient.

    ``hf_meta`` describes every artifact of an ``hf://`` scan. ``local_matches``
    maps an artifact index to the :class:`aisbom.hf_match.Match` found for that
    one local file, and takes precedence for it: in a local tree each file can
    come from a different repo, or from none.

    Returns the input unchanged if it does not parse or has no components, so a
    serializer change upstream degrades to 1.6-equivalent output rather than
    raising during a scan.
    """
    try:
        doc = json.loads(bom_json)
    except (ValueError, TypeError):
        return bom_json
    if not isinstance(doc, dict) or not isinstance(doc.get("components"), list):
        return bom_json

    cards_by_ref: Dict[str, Dict[str, Any]] = {}
    local_matches = local_matches or {}
    for index, art in enumerate(artifacts):
        match = local_matches.get(index)
        if match is not None:
            card = build_model_card(art, match.card, match.source)
        else:
            card = build_model_card(art, hf_meta)
        if card is not None:
            cards_by_ref[bom_ref_for(index, art)] = card

    if not cards_by_ref:
        return bom_json

    injected = False
    for component in doc["components"]:
        if not isinstance(component, dict):
            continue
        # Library components (requirements.txt deps) are not models and must
        # never grow a modelCard.
        if component.get("type") != _ML_COMPONENT_TYPE:
            continue
        card = cards_by_ref.get(component.get("bom-ref"))
        if card is None:
            continue
        component["modelCard"] = card
        injected = True

    if not injected:
        return bom_json

    # Re-serialized with json's default separators, which is exactly what
    # cyclonedx-python-lib's own `output_as_string()` emits — so a scan whose
    # artifacts yield no cards produces a byte-identical file to before, and
    # one that does differs only by the added key.
    return json.dumps(doc)
