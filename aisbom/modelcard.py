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

* Hugging Face model-card metadata (``hf://`` scans only) — task, architecture,
  training datasets, license, library.
* What the scanner already parsed out of the file itself — currently the GGUF
  header's architecture. This is why a purely local scan still gets a
  ``modelCard`` without any network call at all.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

_ML_COMPONENT_TYPE = "machine-learning-model"

# HF metadata worth carrying that has no home in the typed `modelParameters`
# block. Each maps a key in the API payload to an `aisbom:hf:*` property name,
# matching the namespacing convention in `aisbom.properties` (#28/#54).
#
# `downloads` and `likes` are deliberately absent: they change hourly, and an
# SBOM that differs between two scans of an unchanged model produces phantom
# drift on the platform's diff.
_HF_SCALAR_PROPERTIES = (
    ("library_name", "aisbom:hf:library_name"),
    ("sha", "aisbom:hf:revision"),
)


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

    return props


def build_model_card(
    art: Dict[str, Any], hf_meta: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """Return a CycloneDX 1.7 ``modelCard`` dict for one artifact, or None.

    None means "emit no modelCard at all" — the sparse-metadata path. An empty
    `modelCard: {}` would validate, but it is noise in a compliance artifact
    and would make every local non-GGUF scan's SBOM look like it tried and
    failed to describe the model.
    """
    card: Dict[str, Any] = {}

    params = _model_parameters(art, hf_meta)
    if params:
        card["modelParameters"] = params

    props = _properties(art, hf_meta)
    if props:
        card["properties"] = props

    return card or None


def inject_model_cards(
    bom_json: str,
    artifacts: List[Dict[str, Any]],
    hf_meta: Optional[Dict[str, Any]] = None,
) -> str:
    """Splice ``modelCard`` blocks into a serialized CycloneDX document.

    Matching is by component name against the artifact's name, FIFO within a
    name group. Names are file basenames, so a repo with two same-named files
    in different directories produces a collision — but such files come from
    one HF repo and share its metadata, so the cards are equal and the order
    within the group cannot change the output.

    `bom-ref` is deliberately not used as the join key: it is a random UUID per
    run today, and pinning it to something deterministic would change a field
    that already ships, breaking the additive-only guarantee this slice is
    held to.

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

    queued: Dict[str, List[Dict[str, Any]]] = {}
    for art in artifacts:
        card = build_model_card(art, hf_meta)
        if card is None:
            continue
        name = art.get("name")
        if not isinstance(name, str):
            continue
        queued.setdefault(name, []).append(card)

    if not queued:
        return bom_json

    injected = False
    for component in doc["components"]:
        if not isinstance(component, dict):
            continue
        # Library components (requirements.txt deps) are not models and must
        # never grow a modelCard.
        if component.get("type") != _ML_COMPONENT_TYPE:
            continue
        pending = queued.get(component.get("name"))
        if not pending:
            continue
        component["modelCard"] = pending.pop(0)
        injected = True

    if not injected:
        return bom_json

    # Re-serialized with json's default separators, which is exactly what
    # cyclonedx-python-lib's own `output_as_string()` emits — so a scan whose
    # artifacts yield no cards produces a byte-identical file to before, and
    # one that does differs only by the added key.
    return json.dumps(doc)
