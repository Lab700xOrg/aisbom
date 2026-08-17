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
    # The non-torch pickle carriers. `Pickle` shares PyTorch's token because the
    # format genuinely is the same one; joblib and numpy get their own, because
    # the container is a real difference a consumer may want to filter on.
    "Pickle": "pickle",
    "Joblib": "joblib",
    "NumPy": "numpy",
}

# Formats whose findings are pickle opcodes. They share the `aisbom:pickle:*`
# vocabulary rather than each inventing a parallel one, so a consumer that knows
# how to read a threat off a `.pt` reads one off a `.joblib` unchanged.
_PICKLE_BEARING_FORMATS = {"pickle", "joblib", "numpy"}


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

    if fmt in _PICKLE_BEARING_FORMATS:
        threats = details.get("threats") or []
        for threat in threats:
            props.append(("aisbom:pickle:opcode", str(threat)))
        props.append(("aisbom:pickle:opcode_count", str(len(threats))))

        # The container the stream was found in — `bare`, `npy`, `npz`, or the
        # compression joblib used. Absent for `.pt`, which has its own shape.
        container = details.get("container")
        if container:
            props.append(("aisbom:pickle:container", str(container)))
        if details.get("scan_incomplete"):
            props.append(("aisbom:pickle:scan_incomplete", "true"))
        if details.get("dill_code_objects"):
            props.append(("aisbom:pickle:dill_code_objects", "true"))

        if fmt == "joblib":
            compression = details.get("compression")
            if compression:
                props.append(("aisbom:joblib:compression", str(compression)))
            decompressed = details.get("decompressed_bytes")
            if decompressed is not None:
                props.append(("aisbom:joblib:decompressed_bytes", str(decompressed)))

        elif fmt == "numpy":
            dtype = details.get("dtype")
            if dtype:
                props.append(("aisbom:numpy:dtype", str(dtype)))
            if details.get("object_dtype") is not None:
                props.append((
                    "aisbom:numpy:object_dtype",
                    "true" if details.get("object_dtype") else "false",
                ))
            shape = details.get("shape")
            if shape:
                props.append(("aisbom:numpy:shape", str(shape)))
            npy_version = details.get("npy_version")
            if npy_version:
                props.append(("aisbom:numpy:npy_version", str(npy_version)))
            internal_files = details.get("internal_files")
            if internal_files is not None:
                props.append(("aisbom:numpy:member_count", str(internal_files)))

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

        # Chat-template findings. The template itself is deliberately not
        # emitted — it can be hundreds of kilobytes and belongs in the model,
        # not in every SBOM that references it. Its digest is emitted instead,
        # which is enough to tell two templates apart or spot one changing.
        if details.get("chat_template_present"):
            props.append(("aisbom:gguf:chat_template", "present"))
            template_length = details.get("chat_template_length")
            if template_length is not None:
                props.append(("aisbom:gguf:chat_template_length", str(template_length)))
            template_digest = details.get("chat_template_sha256")
            if template_digest:
                props.append(("aisbom:gguf:chat_template_sha256", str(template_digest)))

        template_threats = details.get("chat_template_threats") or []
        for threat in template_threats:
            props.append(("aisbom:gguf:chat_template_threat", str(threat)))
        if details.get("chat_template_present"):
            props.append((
                "aisbom:gguf:chat_template_threat_count", str(len(template_threats))
            ))

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
