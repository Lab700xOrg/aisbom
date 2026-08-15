"""Build structured, namespaced CycloneDX component properties from a scanned
artifact.

The scanner produces a per-artifact ``meta`` dict (see ``DeepScanner``); this
module maps that dict into a flat list of ``(name, value)`` property pairs using
``aisbom:*`` keys so downstream consumers (the web platform's artifact drawer)
can render format-specific findings directly, instead of re-parsing the human
readable ``description`` string.

Keys are namespaced under ``aisbom:`` so they never collide with properties
emitted by other tooling. The ``description`` string is left untouched for
backwards compatibility — these properties are purely additive.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

# Map the scanner's human "framework" label to a stable format token.
_FRAMEWORK_TO_FORMAT = {
    "PyTorch": "pickle",
    "SafeTensors": "safetensors",
    "GGUF": "gguf",
    "Keras": "keras",
    "ONNX": "onnx",
}


def _format_for(art: Dict[str, Any]) -> str | None:
    return _FRAMEWORK_TO_FORMAT.get(art.get("framework"))


def _csv(values) -> str:
    """Join an iterable of values into a stable comma-separated string."""
    return ",".join(str(v) for v in values if str(v) != "")


def build_component_properties(art: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Return ``(name, value)`` property pairs for a scanned artifact.

    Property names that would have an empty value are omitted. Risk/legal
    properties are emitted for any artifact carrying those fields; format and
    per-format findings are added only for recognised model formats.
    """
    props: List[Tuple[str, str]] = []

    # Risk and legal status are carried by every ML-model component (regardless
    # of format) so the platform receiver can read them structurally instead of
    # re-parsing the human ``description`` string. These mirror the ``Risk:`` /
    # ``Legal:`` description segments verbatim and are purely additive.
    risk = art.get("risk_level")
    if risk:
        props.append(("aisbom:risk", str(risk)))
    legal = art.get("legal_status")
    if legal:
        props.append(("aisbom:legal", str(legal)))

    fmt = _format_for(art)
    if fmt is None:
        return props

    details = art.get("details") or {}
    props.append(("aisbom:format", fmt))

    if fmt == "pickle":
        threats = details.get("threats") or []
        for threat in threats:
            props.append(("aisbom:pickle:opcode", str(threat)))
        props.append(("aisbom:pickle:opcode_count", str(len(threats))))

    elif fmt == "safetensors":
        tensor_count = details.get("tensors")
        if tensor_count is not None:
            props.append(("aisbom:safetensors:tensor_count", str(tensor_count)))
        dtypes = details.get("dtypes") or []
        if dtypes:
            props.append(("aisbom:safetensors:dtypes", _csv(dtypes)))
        header_keys = details.get("header_keys") or []
        if header_keys:
            props.append(("aisbom:safetensors:header_keys", _csv(header_keys)))

    elif fmt == "gguf":
        architecture = details.get("architecture")
        if architecture:
            props.append(("aisbom:gguf:architecture", str(architecture)))
        quantization = details.get("quantization")
        if quantization is not None and str(quantization) != "":
            props.append(("aisbom:gguf:quantization", str(quantization)))
        metadata_keys = details.get("metadata_keys") or []
        if metadata_keys:
            props.append(("aisbom:gguf:metadata_keys", _csv(metadata_keys)))

    elif fmt == "keras":
        container = details.get("container")
        if container:
            props.append(("aisbom:keras:container", str(container)))
        threats = details.get("threats") or []
        for threat in threats:
            props.append(("aisbom:keras:threat", str(threat)))
        props.append(("aisbom:keras:threat_count", str(len(threats))))
        lambda_layers = details.get("lambda_layers") or []
        if lambda_layers:
            props.append(("aisbom:keras:lambda_layers", _csv(lambda_layers)))
        layer_count = details.get("layer_count")
        if layer_count is not None:
            props.append(("aisbom:keras:layer_count", str(layer_count)))
        keras_version = details.get("keras_version")
        if keras_version:
            props.append(("aisbom:keras:version", str(keras_version)))

    elif fmt == "onnx":
        ir_version = details.get("ir_version")
        if ir_version is not None:
            props.append(("aisbom:onnx:ir_version", str(ir_version)))
        producer = details.get("producer_name")
        if producer:
            props.append(("aisbom:onnx:producer_name", str(producer)))
        producer_version = details.get("producer_version")
        if producer_version:
            props.append(("aisbom:onnx:producer_version", str(producer_version)))
        graph_name = details.get("graph_name")
        if graph_name:
            props.append(("aisbom:onnx:graph_name", str(graph_name)))

        # Opsets are emitted as "domain:version" pairs; the default domain is
        # the empty string, rendered as "ai.onnx" so the value is readable.
        opsets = details.get("opsets") or []
        if opsets:
            props.append(("aisbom:onnx:opsets", _csv(
                f"{o.get('domain') or 'ai.onnx'}:{o.get('version')}" for o in opsets
            )))

        node_count = details.get("node_count")
        if node_count is not None:
            props.append(("aisbom:onnx:node_count", str(node_count)))
        op_types = details.get("op_types") or []
        if op_types:
            props.append(("aisbom:onnx:op_types", _csv(op_types)))

        custom_ops = details.get("custom_ops") or []
        if custom_ops:
            props.append(("aisbom:onnx:custom_ops", _csv(
                f"{o.get('domain') or ''}.{o.get('op_type') or '?'}" for o in custom_ops
            )))
        props.append(("aisbom:onnx:custom_op_count", str(len(custom_ops))))

        external_data = details.get("external_data") or []
        for entry in external_data:
            location = (entry or {}).get("location")
            if location:
                props.append(("aisbom:onnx:external_data_location", str(location)))
        props.append(("aisbom:onnx:external_data_count", str(len(external_data))))

        for threat in details.get("threats") or []:
            props.append(("aisbom:onnx:threat", str(threat)))

    return props
