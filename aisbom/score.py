"""Grade a CycloneDX AIBOM for completeness and quality.

`aisbom score` answers a different question from `aisbom scan`: not "is this
model dangerous" but "is this document good enough to *be* the compliance
artifact you are about to hand someone". A scan can come back perfectly clean
and still produce an SBOM that names no licenses, carries no checksums and
describes none of the models — which is worth knowing before an auditor finds
out for you.

Scoring is deliberately **fixed-denominator**: every document is graded against
all seven dimensions, whether or not it had a realistic chance at each one. The
alternative — marking dimensions "not applicable" and renormalizing — makes two
grades incomparable, which is the whole value of having a grade. A remote
`hf://` scan therefore loses the checksum dimension, and the gap message says
why and what to do about it rather than pretending the dimension does not apply.

Dimensions and weights (summing to 100):

===================  ==  =====================================================
identity             20  NTIA minimum element: every component identifiable
checksums            20  NTIA minimum element: integrity of what was scanned
licenses             15  NTIA minimum element: what you are allowed to do
modelcard            15  The "AI" in AIBOM — task/architecture of each model
datasets             10  Training-data provenance
vex                  10  Exploitability statements alongside the inventory
docprov              10  NTIA minimum elements: SBOM author, timestamp, id
===================  ==  =====================================================

The split is 65 points of generic SBOM minimum elements, 25 of AI-specific
description, and 10 of VEX. A complete but generic SBOM tops out around 65, so
an A is only reachable with the AI metadata actually filled in.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

_ML_COMPONENT_TYPE = "machine-learning-model"

# The property #111 routes a Hugging Face card's declared license to. It is
# deliberately not merged into `licenses[]` there, because that field drives a
# compliance *judgement* (the platform's license_issue_count, the CLI's LEGAL
# RISK verdict) and backfilling it from HF metadata would silently change one.
# The license is nonetheless genuinely declared, so this dimension credits it
# and names where it came from — otherwise the grade would punish users for an
# architectural decision they cannot influence.
_HF_LICENSE_PROPERTY = "aisbom:hf:license"

# Placeholder versions that carry no more information than an absent field.
# `aisbom scan` emitted the literal string "unknown" for requirements.txt pins
# with no version until #114; other tools emit their own variants.
_PLACEHOLDER_VERSIONS = frozenset({"", "unknown", "none", "n/a", "noassertion", "*"})

# Grade bands, calibrated against real AIsbom output rather than the academic
# 90/80/70/60 scale: a local scan of an unlabelled model tree measures ~50 and
# an `hf://` scan ~53, both of which are genuinely mediocre AIBOMs but not
# failures. On an academic scale every document AIsbom produces would be an F,
# which reads as a miscalibrated grader rather than as actionable feedback.
GRADE_BANDS: Tuple[Tuple[float, str], ...] = (
    (85.0, "A"),
    (70.0, "B"),
    (55.0, "C"),
    (40.0, "D"),
    (0.0, "F"),
)


class ScoreInputError(Exception):
    """The input could not be read, or is not a CycloneDX document."""


@dataclass(frozen=True)
class Dimension:
    key: str
    label: str
    weight: int
    description: str


DIMENSIONS: Tuple[Dimension, ...] = (
    Dimension("identity", "Component identity", 20,
              "Every component carries a name, a stable bom-ref and a real version"),
    Dimension("checksums", "Checksums", 20,
              "Every model component carries a SHA-256 digest"),
    Dimension("licenses", "Licenses", 15,
              "Every component declares a license"),
    Dimension("modelcard", "Model-card coverage", 15,
              "Every model component describes its task and architecture"),
    Dimension("datasets", "Dataset provenance", 10,
              "Every model component names its training datasets"),
    Dimension("vex", "VEX presence", 10,
              "Exploitability statements accompany the inventory"),
    Dimension("docprov", "Document provenance", 10,
              "The document names its author, timestamp and identity"),
)

_BY_KEY = {d.key: d for d in DIMENSIONS}


@dataclass
class DimensionScore:
    key: str
    label: str
    weight: int
    score: float
    gaps: List[str] = field(default_factory=list)
    # One action that closes this dimension, or None when there is nothing the
    # user can do. Kept separate from `gaps` so the per-component list stays
    # terse: repeating the same remedy on every affected component is what
    # turns a 50-model scan's output into 150 lines nobody reads.
    remediation: Optional[str] = None
    summary: Optional[str] = None

    @property
    def points_recoverable(self) -> float:
        """Points this dimension would add if it were brought to 100."""
        return self.weight * (100.0 - self.score) / 100.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "weight": self.weight,
            "score": round(self.score, 1),
            "pointsRecoverable": round(self.points_recoverable, 1),
            "summary": self.summary,
            "remediation": self.remediation,
            "gaps": list(self.gaps),
        }


@dataclass
class ScoreReport:
    overall: float
    grade: str
    dimensions: List[DimensionScore]
    component_count: int
    model_count: int
    spec_version: Optional[str] = None

    @property
    def potential(self) -> float:
        """What this document would score with every gap closed."""
        return min(100.0, self.overall + sum(
            d.points_recoverable for d in self.dimensions
        ))

    def improvement_plan(self) -> List[DimensionScore]:
        """Incomplete dimensions, richest first.

        Ordering by points recoverable rather than by dimension is the whole
        point: a one-flag VEX fix is worth ten points and a missing version
        string is worth under one, and a list sorted by dimension gives them
        the same weight.
        """
        return sorted(
            (d for d in self.dimensions if d.points_recoverable > 0.05),
            key=lambda d: d.points_recoverable,
            reverse=True,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall": round(self.overall, 1),
            "potential": round(self.potential, 1),
            "grade": self.grade,
            "specVersion": self.spec_version,
            "components": self.component_count,
            "models": self.model_count,
            "dimensions": [d.to_dict() for d in self.dimensions],
        }


def grade_for(overall: float) -> str:
    """Map a 0-100 score onto a letter grade."""
    for threshold, letter in GRADE_BANDS:
        if overall >= threshold:
            return letter
    return "F"


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

def load_sbom(path: Path) -> Dict[str, Any]:
    """Read a CycloneDX JSON document, or explain why it cannot be scored.

    SPDX is rejected rather than partially scored. Its 2.3 form has no
    structured home for model-card or dataset metadata at all — AIsbom writes
    that into a free-text `comment` — so scoring it would mean either parsing
    prose or grading it on a smaller denominator, and a grade computed on a
    different denominator is not comparable with a CycloneDX one.
    """
    try:
        raw = path.read_text()
    except OSError as exc:
        raise ScoreInputError(f"Could not read {path}: {exc}") from exc

    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise ScoreInputError(f"{path} is not valid JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise ScoreInputError(f"{path} does not contain a JSON object.")

    if "spdxVersion" in doc or "@graph" in doc:
        raise ScoreInputError(
            f"{path} is an SPDX document. `aisbom score` grades CycloneDX only — "
            "SPDX scoring is tracked as a follow-up."
        )

    if doc.get("bomFormat") != "CycloneDX" and "specVersion" not in doc:
        raise ScoreInputError(
            f"{path} is not a CycloneDX document (no bomFormat/specVersion)."
        )

    return doc


def vex_paths_for(sbom_path: Path) -> List[Path]:
    """The VEX filenames `aisbom scan --vex` would have written next to this SBOM.

    Mirrors ``cli._vex_paths`` so a plain ``scan --vex`` followed by ``score``
    finds the documents with no extra flags. Requiring an explicit path would
    make the happy path silently lose the dimension's ten points, which reads
    as a bug rather than as a policy.
    """
    name = sbom_path.name
    stem = name[: -len(".json")] if name.endswith(".json") else name
    return [
        sbom_path.with_name(f"{stem}.openvex.json"),
        sbom_path.with_name(f"{stem}.vex.cdx.json"),
    ]


def discover_vex(sbom_path: Optional[Path]) -> List[Path]:
    """Sibling VEX documents that actually exist on disk."""
    if sbom_path is None:
        return []
    return [p for p in vex_paths_for(sbom_path) if p.is_file()]


def _vex_statement_count(path: Path) -> int:
    """How many statements a VEX document carries, or 0 if it is unreadable.

    An unreadable or empty VEX file scores as absent rather than raising: the
    dimension asks whether exploitability was stated, and a file that states
    nothing has not stated it.
    """
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return 0
    if not isinstance(doc, dict):
        return 0
    for key in ("statements", "vulnerabilities"):
        value = doc.get(key)
        if isinstance(value, list):
            return len(value)
    return 0


# ---------------------------------------------------------------------------
# Per-dimension scoring
# ---------------------------------------------------------------------------

def _pct(numerator: float, denominator: float) -> float:
    return 0.0 if denominator == 0 else 100.0 * numerator / denominator


def _components(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    comps = doc.get("components")
    if not isinstance(comps, list):
        return []
    return [c for c in comps if isinstance(c, dict)]


def _is_model(component: Dict[str, Any]) -> bool:
    return component.get("type") == _ML_COMPONENT_TYPE


def _name_of(component: Dict[str, Any]) -> str:
    return str(component.get("name") or "<unnamed component>")


def _model_parameters(component: Dict[str, Any]) -> Dict[str, Any]:
    card = component.get("modelCard")
    if not isinstance(card, dict):
        return {}
    params = card.get("modelParameters")
    return params if isinstance(params, dict) else {}


def _card_properties(component: Dict[str, Any]) -> List[Dict[str, Any]]:
    card = component.get("modelCard")
    if not isinstance(card, dict):
        return []
    props = card.get("properties")
    if not isinstance(props, list):
        return []
    return [p for p in props if isinstance(p, dict)]


def _score_identity(doc: Dict[str, Any], comps: List[Dict[str, Any]]) -> DimensionScore:
    gaps: List[str] = []
    if not comps:
        return DimensionScore(
            "identity", _BY_KEY["identity"].label, 20, 0.0,
            gaps=["The document declares no components at all."],
            summary="no components",
        )

    earned = 0.0
    for c in comps:
        checks = [bool(c.get("name")), bool(c.get("bom-ref")), bool(c.get("type"))]
        missing = []
        if not c.get("name"):
            missing.append("name")
        if not c.get("bom-ref"):
            missing.append("bom-ref")
        if not c.get("type"):
            missing.append("type")

        # A version is only meaningful for things that are versioned. A model
        # *file* has a digest, not a release number, so demanding one would
        # deduct from every local scan for a field that has nothing to hold.
        if not _is_model(c):
            version = str(c.get("version") or "").strip().lower()
            has_version = version not in _PLACEHOLDER_VERSIONS
            checks.append(has_version)
            if not has_version:
                missing.append("version")

        earned += sum(1 for ok in checks if ok) / len(checks)
        if missing:
            gaps.append(f"{_name_of(c)}: missing {', '.join(missing)}")

    return DimensionScore(
        "identity", _BY_KEY["identity"].label, 20, _pct(earned, len(comps)), gaps,
        remediation=(
            "Pin each component listed under --verbose to a real version "
            "in requirements.txt"
        ) if gaps else None,
        summary=(f"{len(gaps)} component(s) incompletely identified"
                 if gaps else None),
    )


def _score_checksums(models: List[Dict[str, Any]]) -> DimensionScore:
    label = _BY_KEY["checksums"].label
    if not models:
        return DimensionScore(
            "checksums", label, 20, 0.0,
            gaps=["No machine-learning-model components — this is a dependency "
                  "SBOM, not an AIBOM."],
            summary="no model components to checksum",
        )

    gaps: List[str] = []
    hashed = 0
    for c in models:
        hashes = c.get("hashes")
        digests = [h for h in hashes if isinstance(h, dict) and h.get("content")] \
            if isinstance(hashes, list) else []
        if digests:
            hashed += 1
        else:
            gaps.append(f"{_name_of(c)}: no checksum")

    missing = len(models) - hashed
    return DimensionScore(
        "checksums", label, 20, _pct(hashed, len(models)), gaps,
        # Naming the cause matters: a remote scan streams byte ranges and never
        # reads a whole file, so there is no digest to emit. The fix is to scan
        # a local copy, not to file a bug against the scanner.
        remediation=(
            "aisbom scan <local-path>  — remote scans stream byte ranges and "
            "never read a whole file, so they cannot produce digests"
        ) if missing else None,
        summary=(f"{missing} of {len(models)} model(s) carry no digest"
                 if missing else None),
    )


def _score_licenses(comps: List[Dict[str, Any]]) -> DimensionScore:
    label = _BY_KEY["licenses"].label
    if not comps:
        return DimensionScore("licenses", label, 15, 0.0,
                              ["The document declares no components at all."])

    gaps: List[str] = []
    licensed = 0
    for c in comps:
        licenses = c.get("licenses")
        if isinstance(licenses, list) and licenses:
            licensed += 1
            continue
        hf_license = next(
            (p.get("value") for p in _card_properties(c)
             if p.get("name") == _HF_LICENSE_PROPERTY and p.get("value")),
            None,
        )
        if hf_license:
            licensed += 1
            gaps.append(
                f"{_name_of(c)}: license '{hf_license}' declared via "
                f"{_HF_LICENSE_PROPERTY} rather than licenses[] "
                "(credited — third-party tools reading only licenses[] will miss it)"
            )
            continue
        gaps.append(f"{_name_of(c)}: no license declared")

    missing = len(comps) - licensed
    return DimensionScore(
        "licenses", label, 15, _pct(licensed, len(comps)), gaps,
        remediation=(
            "Declare a license on each component listed under --verbose — "
            "dependency licenses are not yet resolved automatically"
        ) if missing else None,
        summary=(f"{missing} of {len(comps)} component(s) declare no license"
                 if missing else None),
    )


def _score_modelcard(models: List[Dict[str, Any]]) -> DimensionScore:
    label = _BY_KEY["modelcard"].label
    if not models:
        return DimensionScore(
            "modelcard", label, 15, 0.0,
            gaps=["No machine-learning-model components to describe."],
            summary="no model components to describe",
        )

    gaps: List[str] = []
    described = 0
    for c in models:
        params = _model_parameters(c)
        if any(params.get(k) for k in ("task", "architectureFamily", "modelArchitecture")):
            described += 1
        else:
            gaps.append(f"{_name_of(c)}: no modelCard task/architecture")

    missing = len(models) - described
    return DimensionScore(
        "modelcard", label, 15, _pct(described, len(models)), gaps,
        remediation=(
            "aisbom scan hf://<org>/<model>  — task and architecture are read "
            "from the Hugging Face model card"
        ) if missing else None,
        summary=(f"{missing} of {len(models)} model(s) declare no task or "
                 f"architecture" if missing else None),
    )


def _score_datasets(models: List[Dict[str, Any]]) -> DimensionScore:
    label = _BY_KEY["datasets"].label
    if not models:
        return DimensionScore(
            "datasets", label, 10, 0.0,
            gaps=["No machine-learning-model components to trace."],
            summary="no model components to trace",
        )

    gaps: List[str] = []
    traced = 0
    for c in models:
        datasets = _model_parameters(c).get("datasets")
        if isinstance(datasets, list) and datasets:
            traced += 1
        else:
            gaps.append(f"{_name_of(c)}: no training datasets named")

    missing = len(models) - traced
    return DimensionScore(
        "datasets", label, 10, _pct(traced, len(models)), gaps,
        remediation=(
            "aisbom scan hf://<org>/<model>  — training datasets come from the "
            "model card's `datasets` field"
        ) if missing else None,
        summary=(f"{missing} of {len(models)} model(s) name no training data"
                 if missing else None),
    )


def _score_vex(doc: Dict[str, Any], vex_documents: Sequence[Path]) -> DimensionScore:
    label = _BY_KEY["vex"].label

    inline = doc.get("vulnerabilities")
    if isinstance(inline, list) and inline:
        return DimensionScore("vex", label, 10, 100.0, [])

    for path in vex_documents:
        if _vex_statement_count(path) > 0:
            return DimensionScore("vex", label, 10, 100.0, [])

    return DimensionScore(
        "vex", label, 10, 0.0,
        gaps=["No VEX statements accompany this SBOM."],
        remediation=(
            "aisbom scan . --vex --output sbom.json  — states whether each "
            "finding is actually exploitable"
        ),
        summary="no exploitability statements",
    )


def _score_docprov(doc: Dict[str, Any]) -> DimensionScore:
    label = _BY_KEY["docprov"].label
    metadata = doc.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}

    checks = {
        "metadata.tools (which tool produced this SBOM)": bool(metadata.get("tools")),
        "metadata.timestamp (when it was produced)": bool(metadata.get("timestamp")),
        "serialNumber (a stable document identity)": bool(doc.get("serialNumber")),
        "specVersion (which CycloneDX version)": bool(doc.get("specVersion")),
    }
    gaps = [f"missing {name}" for name, ok in checks.items() if not ok]
    return DimensionScore(
        "docprov", label, 10, _pct(sum(checks.values()), len(checks)), gaps,
        remediation=(
            "Regenerate with a current aisbom — `metadata.tools`, timestamp and "
            "serial number are emitted automatically"
        ) if gaps else None,
        summary=(f"{len(gaps)} document-level field(s) absent" if gaps else None),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def score_sbom(
    doc: Dict[str, Any],
    *,
    vex_documents: Optional[Sequence[Path]] = None,
) -> ScoreReport:
    """Grade a parsed CycloneDX document across all seven dimensions."""
    comps = _components(doc)
    models = [c for c in comps if _is_model(c)]
    vex_documents = vex_documents or []

    dimensions = [
        _score_identity(doc, comps),
        _score_checksums(models),
        _score_licenses(comps),
        _score_modelcard(models),
        _score_datasets(models),
        _score_vex(doc, vex_documents),
        _score_docprov(doc),
    ]

    overall = sum(d.score * d.weight for d in dimensions) / 100.0
    spec_version = doc.get("specVersion")
    return ScoreReport(
        overall=overall,
        grade=grade_for(overall),
        dimensions=dimensions,
        component_count=len(comps),
        model_count=len(models),
        spec_version=spec_version if isinstance(spec_version, str) else None,
    )
