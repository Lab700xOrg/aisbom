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
}


def _format_for(art: Dict[str, Any]) -> str | None:
    return _FRAMEWORK_TO_FORMAT.get(art.get("framework"))


def _csv(values) -> str:
    """Join an iterable of values into a stable comma-separated string."""
    return ",".join(str(v) for v in values if str(v) != "")


def build_component_properties(art: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Return ``(name, value)`` property pairs for a scanned artifact.

    Returns an empty list for non-model artifacts (e.g. config files) or
    formats we don't emit structured findings for. Property names that would
    have an empty value are omitted.
    """
    fmt = _format_for(art)
    if fmt is None:
        return []

    details = art.get("details") or {}
    props: List[Tuple[str, str]] = [("aisbom:format", fmt)]

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

    return props
