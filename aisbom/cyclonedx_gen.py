"""Build the CycloneDX document from a completed scan.

Extracted from ``cli.scan`` (#114) so that ``aisbom score`` can grade a scan
target directly — scoring a directory or an ``hf://`` slug means producing a
document to score, and duplicating the construction in two places is how the
two drift apart. ``scan`` and ``score`` now emit byte-identical documents from
the same results, because they run the same code.

The ``modelCard`` splice lives here too, so callers get a finished document
rather than one they must remember to enrich (see ``modelcard`` for why the
block is spliced post-serialization rather than modelled).
"""

from __future__ import annotations

import importlib.metadata
from typing import Any, Dict

from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model import HashAlgorithm, HashType, Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot5, JsonV1Dot6, JsonV1Dot7

from .modelcard import bom_ref_for, inject_model_cards
from .properties import build_component_properties
from .spdx_gen import _sha256_or_none

_OUTPUTTERS = {
    "1.5": JsonV1Dot5,
    "1.6": JsonV1Dot6,
    "1.7": JsonV1Dot7,
}

# Version reported in `metadata.tools`. Read from installed metadata so a
# released build self-identifies accurately; the fallback covers running from
# a source checkout that was never installed.
try:  # pragma: no cover - trivial, and environment-dependent
    _AISBOM_VERSION = importlib.metadata.version("aisbom-cli")
except importlib.metadata.PackageNotFoundError:  # pragma: no cover
    _AISBOM_VERSION = "unknown"


def _tool_component() -> Component:
    """AIsbom's self-identification for ``metadata.tools``.

    An SBOM that does not say what produced it fails the NTIA minimum
    elements — and, since #114, AIsbom's own completeness grade. Emitting it
    is purely additive: no existing field changes value.
    """
    return Component(
        name="aisbom-cli",
        version=_AISBOM_VERSION,
        type=ComponentType.APPLICATION,
        bom_ref="aisbom-cli",
    )


def build_bom(results: Dict[str, Any]) -> Bom:
    """Assemble the ``Bom`` object for a completed scan's results."""
    bom = Bom()
    lf = LicenseFactory()

    bom.metadata.tools.components.add(_tool_component())

    for art_index, art in enumerate(results.get("artifacts", [])):
        c = Component(
            name=art["name"],
            type=ComponentType.MACHINE_LEARNING_MODEL,
            # An explicit, stable bom-ref. Left to the library this is a fresh
            # random string on every run, which nothing downstream can rely on
            # and which cannot be computed ahead of serialization — so the
            # modelCard splice would have no identifier to join on and would
            # fall back to matching by basename, which collides (#111).
            bom_ref=bom_ref_for(art_index, art),
            description=(
                f"Risk: {art['risk_level']} | Framework: {art['framework']} | "
                f"Legal: {art['legal_status']} | License: {art.get('license')}"
            ),
        )
        # Add SHA256 Hash only when the field actually holds one. The scanner
        # stores the sentinels `remote_unhashed` (range-request scans never
        # read the whole file) and `hash_error` in the same field, and the old
        # `!= 'hash_error'` guard let `remote_unhashed` through as a SHA-256
        # digest — which made every hf:// SBOM fail CycloneDX validation, at
        # 1.6 as well as 1.7. Reuses spdx_gen's predicate, which already had to
        # solve this for SPDX (#101), rather than blacklisting sentinel names:
        # a sentinel added later would silently reintroduce the bug.
        digest = _sha256_or_none(art.get("hash"))
        if digest:
            c.hashes.add(HashType(alg=HashAlgorithm.SHA_256, content=digest))

        if art.get("license") and art["license"] != "Unknown":
            c.licenses.add(lf.make_from_string(art["license"]))

        # Attach structured, namespaced per-format findings as CycloneDX
        # properties so consumers can render them directly (the description
        # string above is kept unchanged for backwards compatibility).
        for prop_name, prop_value in build_component_properties(art):
            c.properties.add(Property(name=prop_name, value=prop_value))

        bom.components.add(c)

    for dep in results.get("dependencies", []):
        version = dep.get("version")
        # `version: "unknown"` was a placeholder carrying no more information
        # than an absent field, and it cost the completeness grade real points
        # for nothing (#114). Omitting it is safe: `diff.SBOMDiff` already
        # reads `component.get("version", "unknown")`, so an absent field and
        # the literal string compare equal and no drift is reported.
        bom.components.add(Component(
            name=dep["name"],
            version=None if version == "unknown" else version,
            type=ComponentType.LIBRARY,
        ))

    return bom


def build_cyclonedx_json(results: Dict[str, Any], schema_version: str = "1.7") -> str:
    """Serialize a scan's results as a CycloneDX JSON document.

    ML-BOM enrichment (#111) applies to 1.7 only. ``modelCard`` exists from
    CycloneDX 1.5 on, but 1.5/1.6 output is what older platform receivers and
    third-party tools were pinned against, so asking for an older schema
    version keeps giving the document shape those consumers expect.
    """
    outputter = _OUTPUTTERS.get(schema_version, JsonV1Dot7)
    sbom_json = outputter(build_bom(results)).output_as_string()

    if schema_version == "1.7":
        sbom_json = inject_model_cards(
            sbom_json, results.get("artifacts", []), results.get("hf_model_card")
        )
    return sbom_json
