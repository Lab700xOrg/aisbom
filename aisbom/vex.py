"""VEX (Vulnerability Exploitability eXchange) output — OpenVEX + CycloneDX VEX.

Why the statements are keyed on AIsbom finding classes
------------------------------------------------------

VEX exists to say, per vulnerability, whether a product is actually affected.
That normally means a CVE. AIsbom has no CVE feed: what it detects is content
*inside a model file* — a pickle stream importing ``os.system``, a Keras Lambda
layer carrying marshalled code, a Jinja chat template with a sandbox escape.
None of those have a CVE and none ever will, because they are not defects in a
published component; the file itself is the payload.

So the statements are keyed on a small, stable vocabulary of **finding
classes** owned by AIsbom (``VEX_FINDING_CLASSES`` below). Deliberate
consequences of that choice:

* They are **not** CVE identifiers and are never shaped like one. The docs and
  the README say so in those words. A compliance artifact that implied a CVE
  association it does not have would be worse than one that omits the finding.
* ``aliases`` is supported by both emitters and is **empty for every class
  today**. The CVEs AIsbom's bypass corpus knows (CVE-2025-1889/1944/1945,
  CVE-2025-10155/10156/10157, CVE-2025-1716) are vulnerabilities in
  *picklescan* — a different scanner failing to detect something — not in the
  scanned model. Aliasing a finding to one would be a factual error.
* The vocabulary is **coarse on purpose**: seven class-level IDs, not one per
  opcode. A small vocabulary is cheap to keep stable forever; a granular one is
  not, and these strings are permanent the moment they reach a customer.
* Each class carries a dereferenceable ``@id`` under ``https://aisbom.io/vex/``
  so a consumer meeting an unfamiliar identifier can resolve it, and CycloneDX
  output names AIsbom as the ``source`` rather than leaving the ID an orphan.

Compatibility policy
--------------------

These identifiers live in documents on other people's disks — an FDA
submission folder, a CI artifact, an audit archive — long after the scan that
produced them. Two things depend on them, and both fail *silently* rather than
loudly: automated rules ("fail the build if ``AISBOM-PICKLE-RCE`` is
affected"), and longitudinal comparison, where a renamed class reads as one
finding resolved and a different one opened — the exact wrong conclusion in the
document meant to prevent wrong conclusions.

The promise is therefore not "a class is never renamed" — that is a promise
about future judgement, which is hard to keep. It is **a consumer is never
broken**:

1. A class is never deleted, and an identifier is never reused for a different
   meaning.
2. If a class is renamed, the successor carries the old identifier in
   ``aliases``, so a rule matching the old string keeps matching. This is what
   the VEX ``aliases`` field is for — it means "other names for this same
   finding", which a retired identifier is. (The same field also carries real
   CVE identifiers when one applies; both uses are "another name for this".)
3. Every identifier ever published is listed in
   :data:`PUBLISHED_FINDING_CLASS_IDS`, which is **append-only**, and a test
   asserts each one is still resolvable — either currently emitted or aliased
   by its successor. That makes the policy mechanically enforced rather than a
   comment someone has to remember.

When OSV/CVE mapping for the dependency components lands, those statements join
the same ``statements`` list with no change visible to a consumer — the
emitters take a list of :class:`VexStatement` and do not care where one came
from.

Scoping of negative statements
------------------------------

A ``not_affected`` claim is only worth making where AIsbom actually looked. A
class is therefore asserted — positively or negatively — only for the formats
listed in its ``formats`` set, and never for a format the class cannot arise in
(no ONNX custom-operator statement about a ``.safetensors``).

The one non-obvious exclusion is Keras. ``AISBOM-PICKLE-RCE`` covers every
format whose pickle content AIsbom disassembles, plus the formats that
structurally cannot carry a pickle stream at all (SafeTensors, GGUF, ONNX) —
for which the negative is the strongest claim in the document. Keras is in
neither group: ``_inspect_keras`` reads the model config with
``scan_keras_config``, not ``scan_pickle_stream``, so a pickle embedded in a
``.keras`` container is not disassembled. Asserting ``not_affected`` there
would be an over-claim, so Keras receives only its own class.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from .modelcard import bom_ref_for
from .properties import _FRAMEWORK_TO_FORMAT, _PICKLE_BEARING_FORMATS
from .spdx_gen import _sha256_or_none, _tool_version

# The released OpenVEX context IRI. The spec pins the document's `@context`, so
# this is not a formatting preference.
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

# Where a finding class ID resolves. Making the identifier dereferenceable is
# what keeps an unfamiliar namespace usable to a consumer rather than opaque.
VEX_NAMESPACE = "https://aisbom.io/vex/"

VEX_AUTHOR = "AIsbom"

# The four OpenVEX statuses. CycloneDX names the same concepts differently, so
# OpenVEX is treated as canonical and mapped on emit.
STATUS_AFFECTED = "affected"
STATUS_NOT_AFFECTED = "not_affected"
STATUS_FIXED = "fixed"
STATUS_UNDER_INVESTIGATION = "under_investigation"

# The single justification AIsbom ever asserts. OpenVEX offers five and
# CycloneDX nine, and the two vocabularies do not line up: mapping more of them
# would mean choosing an inexact CycloneDX analogue for at least one, which in
# a compliance artifact is a lie with extra steps. `vulnerable_code_not_present`
# maps exactly onto CycloneDX's `code_not_present`, and it is also the only
# justification AIsbom can actually support from a static read of a file — it
# never observes an execute path, a perimeter control or a runtime mitigation.
JUSTIFICATION_CODE_NOT_PRESENT = "vulnerable_code_not_present"

# OpenVEX status -> CycloneDX `analysis.state`.
_CDX_STATE = {
    STATUS_AFFECTED: "exploitable",
    STATUS_NOT_AFFECTED: "not_affected",
    STATUS_FIXED: "resolved",
    STATUS_UNDER_INVESTIGATION: "in_triage",
}

# OpenVEX justification -> CycloneDX `analysis.justification`.
_CDX_JUSTIFICATION = {
    JUSTIFICATION_CODE_NOT_PRESENT: "code_not_present",
}

# Format tokens (as `properties.py` assigns them) that cannot carry a pickle
# stream at all. The negative pickle-RCE statement on these is a structural
# claim about the format, not a result of disassembly.
_PICKLE_FREE_FORMATS = frozenset({"safetensors", "gguf", "onnx"})

# Formats the pickle-RCE class is assertable on, positively or negatively.
_PICKLE_RCE_FORMATS = frozenset(_PICKLE_BEARING_FORMATS) | _PICKLE_FREE_FORMATS


@dataclass(frozen=True)
class FindingClass:
    """One entry in AIsbom's VEX vocabulary.

    This table is the single source of truth for the namespace: the emitters,
    ``docs/vex-finding-classes.md`` and the pinned-ID test all read it, so a
    class cannot be added, renamed or dropped in only one of those places.
    """

    id: str
    title: str
    description: str
    #: Remediation text used as `action_statement` on an `affected` statement.
    action: str
    #: Format tokens this class may be asserted on. See the module docstring.
    formats: frozenset
    #: Real CVE/GHSA identifiers for the same issue. Empty for every class
    #: today — see the module docstring for why.
    aliases: tuple = ()

    @property
    def iri(self) -> str:
        return f"{VEX_NAMESPACE}{self.id}"


VEX_FINDING_CLASSES: tuple = (
    FindingClass(
        id="AISBOM-PICKLE-RCE",
        title="Pickle stream imports a code-executing global",
        description=(
            "The artifact carries a Python pickle stream whose opcodes import a "
            "global that executes code when the stream is deserialized "
            "(os.system, subprocess.Popen, builtins.eval and similar). "
            "Deserialization is the execution — no separate trigger is needed."
        ),
        action=(
            "Do not load this file with torch.load/pickle.load. Obtain the model "
            "in a non-executable format (SafeTensors) or from a trusted source, "
            "and treat the file as active malware rather than as a defective "
            "dependency to patch."
        ),
        formats=_PICKLE_RCE_FORMATS,
    ),
    FindingClass(
        id="AISBOM-PICKLE-CODE-OBJECT",
        title="Serialized Python code objects embedded in the pickle stream",
        description=(
            "The pickle stream carries dill-serialized code objects — whole "
            "Python functions marshalled into the file. The bytecode is "
            "reconstructed on load, so what the model does is not limited to "
            "what its declared imports suggest."
        ),
        action=(
            "Do not load this file outside an isolated sandbox. Re-export the "
            "model from its source framework so that weights, not code, are "
            "what is serialized."
        ),
        formats=frozenset(_PICKLE_BEARING_FORMATS),
    ),
    FindingClass(
        id="AISBOM-PICKLE-UNSCANNED",
        title="Pickle data present but not fully disassembled",
        description=(
            "A pickle stream was found but could not be read to completion — a "
            "truncated or malformed stream, an unreadable archive member, or a "
            "container AIsbom does not decompress. Absence of a finding here is "
            "not evidence of absence: this is the nullifAI evasion class, where "
            "a deliberately broken stream is used to end a scan early."
        ),
        action=(
            "Re-scan the artifact from its original archive, or decompress the "
            "container and scan the members individually, before loading it."
        ),
        formats=frozenset(_PICKLE_BEARING_FORMATS),
    ),
    FindingClass(
        id="AISBOM-KERAS-LAMBDA-RCE",
        title="Keras Lambda layer or marshalled code object executes on load",
        description=(
            "The Keras model config declares a Lambda layer or carries a "
            "marshalled Python code object. keras.models.load_model "
            "reconstructs and can invoke it, so loading the model runs "
            "attacker-chosen bytecode."
        ),
        action=(
            "Load with safe_mode=True (Keras 3), or rebuild the layer in your "
            "own code and load weights only. Do not load with "
            "safe_mode=False or on Keras 2."
        ),
        formats=frozenset({"keras"}),
    ),
    FindingClass(
        id="AISBOM-GGUF-TEMPLATE-INJECTION",
        title="GGUF chat template contains a sandbox escape or dangerous call",
        description=(
            "The Jinja chat template stored in the GGUF metadata contains "
            "constructs that reach outside the template sandbox or invoke "
            "dangerous callables. The template is evaluated on every inference "
            "request, so this executes at serving time rather than at load."
        ),
        action=(
            "Replace the chat template with one you control, or serve the model "
            "through a runtime that does not evaluate the embedded template."
        ),
        formats=frozenset({"gguf"}),
    ),
    FindingClass(
        id="AISBOM-ONNX-CUSTOM-OP",
        title="ONNX graph references operators outside the standard domains",
        description=(
            "The graph calls operators that are not part of the standard ONNX "
            "domains, so executing it requires loading a third-party operator "
            "library. What that library does is outside the model file and "
            "outside this scan."
        ),
        action=(
            "Identify and review the operator library the graph requires before "
            "running inference, or re-export the model using standard operators."
        ),
        formats=frozenset({"onnx"}),
    ),
    FindingClass(
        id="AISBOM-ONNX-EXTERNAL-DATA",
        title="ONNX tensor data stored outside the model file",
        description=(
            "Tensor data is held in separate files referenced by the graph, so "
            "the model's weights are not covered by this artifact's hash. A "
            "reference that resolves outside the model directory additionally "
            "turns loading the model into a read of a file the author chose."
        ),
        action=(
            "Scan and pin the external tensor files alongside the model, and "
            "reject any reference that resolves outside the model directory."
        ),
        formats=frozenset({"onnx"}),
    ),
)

FINDING_CLASSES_BY_ID: Dict[str, FindingClass] = {
    c.id: c for c in VEX_FINDING_CLASSES
}

#: Every finding-class identifier this project has ever published, in the order
#: it was introduced. **Append-only.**
#:
#: Deleting an entry is what silently breaks somebody's build gate, so the test
#: suite asserts each of these is still resolvable: either emitted by a class in
#: ``VEX_FINDING_CLASSES``, or listed in a current class's ``aliases`` because
#: it was renamed. Adding a class means adding it here too; retiring one means
#: aliasing it from its successor, never removing the line.
PUBLISHED_FINDING_CLASS_IDS: tuple = (
    "AISBOM-PICKLE-RCE",
    "AISBOM-PICKLE-CODE-OBJECT",
    "AISBOM-PICKLE-UNSCANNED",
    "AISBOM-KERAS-LAMBDA-RCE",
    "AISBOM-GGUF-TEMPLATE-INJECTION",
    "AISBOM-ONNX-CUSTOM-OP",
    "AISBOM-ONNX-EXTERNAL-DATA",
)


@dataclass(frozen=True)
class VexStatement:
    """One assertion: a finding class, a product, a status and why."""

    finding_class: FindingClass
    product_ref: str
    product_id: str
    product_hash: Optional[str]
    status: str
    justification: Optional[str] = None
    status_notes: str = ""
    action_statement: Optional[str] = None


# --------------------------------------------------------------------------
# Signals — the one shape both derivation paths agree on.
#
# A live scan reads the scanner's `details` dict; a baseline SBOM reads the
# `aisbom:*` component properties. Normalising both into the same dict is what
# keeps the taxonomy in one place: `_classify` is written once, against
# signals, and never learns which side it came from.
# --------------------------------------------------------------------------

def _empty_signals() -> Dict[str, Any]:
    return {
        "format": None,
        "pickle_opcodes": [],
        "pickle_scan_incomplete": False,
        "pickle_code_objects": False,
        "keras_threats": [],
        "keras_lambda_layers": [],
        "keras_incomplete": False,
        "gguf_template_present": False,
        "gguf_template_threats": [],
        "gguf_metadata_truncated": False,
        "onnx_custom_ops": 0,
        "onnx_external_data": 0,
        "onnx_external_escape": False,
        "onnx_incomplete": False,
    }


def signals_from_artifact(art: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a scanner artifact dict into the shared signal shape."""
    sig = _empty_signals()
    sig["format"] = _FRAMEWORK_TO_FORMAT.get(art.get("framework"))
    details = art.get("details") or {}
    fmt = sig["format"]

    # An inspection that raised produced whatever it had reached and stopped.
    # The scanner records that as `error` — at the artifact level in most
    # inspectors and under `details` in the GGUF one — and the resulting detail
    # dict is simply sparse, which is indistinguishable from "looked and found
    # nothing" unless it is treated as incompleteness here. It feeds the
    # per-format flags below so it routes through the same
    # `under_investigation` paths rather than needing its own branch.
    inspection_error = bool(art.get("error") or details.get("error"))

    if fmt in _PICKLE_BEARING_FORMATS:
        sig["pickle_opcodes"] = list(details.get("threats") or [])
        sig["pickle_scan_incomplete"] = (
            bool(details.get("scan_incomplete")) or inspection_error
        )
        sig["pickle_code_objects"] = bool(details.get("dill_code_objects"))
    elif fmt == "keras":
        sig["keras_threats"] = list(details.get("threats") or [])
        sig["keras_lambda_layers"] = list(details.get("lambda_layers") or [])
        # The config read stops at a byte budget, and a Lambda layer sitting
        # after the cut would never have been seen — padding a config with
        # harmless layers is cheap and keeps the archive small and loadable.
        # A config that was never located at all cannot be cleared either.
        sig["keras_incomplete"] = (
            bool(details.get("truncated"))
            or not details.get("config_found")
            or inspection_error
        )
    elif fmt == "gguf":
        sig["gguf_template_present"] = bool(details.get("chat_template_present"))
        sig["gguf_template_threats"] = list(details.get("chat_template_threats") or [])
        sig["gguf_metadata_truncated"] = (
            bool(details.get("metadata_truncated")) or inspection_error
        )
    elif fmt == "onnx":
        sig["onnx_custom_ops"] = len(details.get("custom_ops") or [])
        external = details.get("external_data") or []
        sig["onnx_external_data"] = len(external)
        sig["onnx_external_escape"] = any(
            str(t).startswith("ONNX_EXTERNAL_DATA_ESCAPE:")
            for t in (details.get("threats") or [])
        )
        # A graph read only to the byte budget may hold custom operators or
        # external-data entries past the cut. ``details["truncated"]`` is
        # computed from the buffered read, so a large *local* file that the
        # streamed re-walk did cover in full still reports truncated — this
        # errs toward "we may not have finished looking", which is the safe
        # direction for a compliance claim. See the follow-ups on #113.
        sig["onnx_incomplete"] = (
            bool(details.get("truncated"))
            or not details.get("parsed", True)
            or inspection_error
        )
    return sig


_RCE_DESC_RE = re.compile(r"RCE Detected:\s*([^)]*)\)")


def signals_from_component(component: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a serialized CycloneDX component into the shared signal shape.

    Reads the structured ``aisbom:*`` properties that #53/#54 added. A baseline
    SBOM produced before those shipped carries none, so the pickle-RCE signal
    degrades to the ``description`` string — which has always named the
    offending globals — rather than silently reporting a clean baseline and
    turning every pre-existing finding into a spurious ``fixed``.
    """
    sig = _empty_signals()
    props: Dict[str, List[str]] = {}
    for prop in component.get("properties") or []:
        name = prop.get("name")
        if name:
            props.setdefault(name, []).append(prop.get("value"))

    fmt_values = props.get("aisbom:format")
    sig["format"] = fmt_values[0] if fmt_values else None

    if props:
        sig["pickle_opcodes"] = list(props.get("aisbom:pickle:opcode") or [])
        sig["pickle_scan_incomplete"] = "true" in (
            props.get("aisbom:pickle:scan_incomplete") or []
        )
        sig["pickle_code_objects"] = "true" in (
            props.get("aisbom:pickle:dill_code_objects") or []
        )
        sig["keras_threats"] = list(props.get("aisbom:keras:threat") or [])
        sig["keras_lambda_layers"] = [
            v for csv in (props.get("aisbom:keras:lambda_layers") or [])
            for v in str(csv).split(",") if v
        ]
        sig["gguf_template_present"] = "present" in (
            props.get("aisbom:gguf:chat_template") or []
        )
        sig["gguf_template_threats"] = list(
            props.get("aisbom:gguf:chat_template_threat") or []
        )
        custom_op_count = props.get("aisbom:onnx:custom_op_count")
        sig["onnx_custom_ops"] = int(custom_op_count[0]) if custom_op_count else 0
        external_count = props.get("aisbom:onnx:external_data_count")
        sig["onnx_external_data"] = int(external_count[0]) if external_count else 0
        sig["onnx_external_escape"] = any(
            str(t).startswith("ONNX_EXTERNAL_DATA_ESCAPE:")
            for t in (props.get("aisbom:onnx:threat") or [])
        )
        return sig

    # Pre-#54 baseline: recover what the description string carries.
    description = component.get("description") or ""
    match = _RCE_DESC_RE.search(description)
    if match:
        sig["pickle_opcodes"] = [
            part.strip() for part in match.group(1).split(",") if part.strip()
        ]
    framework = re.search(r"Framework:\s*([^|]+)", description)
    if framework:
        sig["format"] = _FRAMEWORK_TO_FORMAT.get(framework.group(1).strip())
    return sig


def _classify(cls: FindingClass, sig: Dict[str, Any]) -> Optional[tuple]:
    """Return ``(status, notes)`` for one class against one artifact's signals.

    ``None`` means the class is not assertable here — either the format is
    outside its scope, or AIsbom did not look. That is different from
    ``not_affected``, which is a claim.
    """
    fmt = sig.get("format")
    if fmt is None or fmt not in cls.formats:
        return None

    if cls.id == "AISBOM-PICKLE-RCE":
        opcodes = sig["pickle_opcodes"]
        if opcodes:
            return (
                STATUS_AFFECTED,
                "Pickle disassembly found code-executing global(s): "
                + ", ".join(str(o) for o in opcodes)
                + ". The file is the payload, not a component with a patchable "
                "defect — there is no fixed version to upgrade to.",
            )
        if fmt in _PICKLE_FREE_FORMATS:
            return (
                STATUS_NOT_AFFECTED,
                f"The {fmt} format carries no Python pickle stream, so no "
                "deserialization code path exists in this artifact.",
            )
        if sig["pickle_scan_incomplete"]:
            # The stream was not read to the end, so "no dangerous global" is
            # not something this scan is entitled to assert.
            return (
                STATUS_UNDER_INVESTIGATION,
                "The pickle stream could not be disassembled to completion, so "
                "the absence of a code-executing global is not established.",
            )
        return (
            STATUS_NOT_AFFECTED,
            "The pickle stream was disassembled in full and imports no "
            "code-executing global.",
        )

    if cls.id == "AISBOM-PICKLE-CODE-OBJECT":
        if sig["pickle_code_objects"]:
            return (
                STATUS_AFFECTED,
                "The stream carries dill-serialized code objects.",
            )
        if sig["pickle_scan_incomplete"]:
            return (
                STATUS_UNDER_INVESTIGATION,
                "The pickle stream could not be disassembled to completion.",
            )
        return (
            STATUS_NOT_AFFECTED,
            "No serialized code objects were found in the pickle stream.",
        )

    if cls.id == "AISBOM-PICKLE-UNSCANNED":
        if sig["pickle_scan_incomplete"]:
            return (
                STATUS_UNDER_INVESTIGATION,
                "Pickle data was found but not read to completion, so this scan "
                "does not establish what the stream contains.",
            )
        return (
            STATUS_NOT_AFFECTED,
            "The pickle data in this artifact was read to completion.",
        )

    if cls.id == "AISBOM-KERAS-LAMBDA-RCE":
        if sig["keras_threats"] or sig["keras_lambda_layers"]:
            named = ", ".join(dict.fromkeys(sig["keras_lambda_layers"]))
            detail = f" Lambda layer(s): {named}." if named else ""
            return (
                STATUS_AFFECTED,
                "The Keras model config declares executable content."
                + detail
                + " Loading the model reconstructs and can invoke it.",
            )
        if sig["keras_incomplete"]:
            return (
                STATUS_UNDER_INVESTIGATION,
                "The Keras model config was not read in full, so a Lambda layer "
                "declared beyond the read limit would not have been seen.",
            )
        return (
            STATUS_NOT_AFFECTED,
            "The Keras model config declares no Lambda layer and carries no "
            "marshalled code object.",
        )

    if cls.id == "AISBOM-GGUF-TEMPLATE-INJECTION":
        if sig["gguf_template_threats"]:
            return (
                STATUS_AFFECTED,
                "The embedded Jinja chat template contains: "
                + "; ".join(str(t) for t in sig["gguf_template_threats"])
                + ".",
            )
        if sig["gguf_metadata_truncated"]:
            return (
                STATUS_UNDER_INVESTIGATION,
                "The GGUF metadata block did not fit the scan window, so any "
                "chat template beyond it was never read.",
            )
        if sig["gguf_template_present"]:
            return (
                STATUS_NOT_AFFECTED,
                "The embedded chat template was inspected and contains no "
                "sandbox escape or dangerous call.",
            )
        return (
            STATUS_NOT_AFFECTED,
            "The GGUF metadata carries no chat template.",
        )

    if cls.id == "AISBOM-ONNX-CUSTOM-OP":
        if sig["onnx_custom_ops"]:
            return (
                STATUS_AFFECTED,
                f"The graph references {sig['onnx_custom_ops']} operator(s) "
                "outside the standard ONNX domains.",
            )
        if sig["onnx_incomplete"]:
            return (
                STATUS_UNDER_INVESTIGATION,
                "The ONNX graph was not walked in full, so an operator beyond "
                "the read limit would not have been seen.",
            )
        return (
            STATUS_NOT_AFFECTED,
            "Every operator in the graph belongs to a standard ONNX domain.",
        )

    if cls.id == "AISBOM-ONNX-EXTERNAL-DATA":
        if sig["onnx_external_data"]:
            escape = (
                " At least one reference resolves outside the model directory."
                if sig["onnx_external_escape"]
                else ""
            )
            return (
                STATUS_AFFECTED,
                f"The graph stores tensor data in {sig['onnx_external_data']} "
                "file(s) outside the model, which this artifact's hash does not "
                "cover." + escape,
            )
        if sig["onnx_incomplete"]:
            return (
                STATUS_UNDER_INVESTIGATION,
                "The ONNX graph was not walked in full, so an external-data "
                "entry beyond the read limit would not have been seen.",
            )
        return (
            STATUS_NOT_AFFECTED,
            "All tensor data is stored inside the model file.",
        )

    return None  # pragma: no cover - every class is handled above


def _prior_for(
    art: Dict[str, Any],
    digest: Optional[str],
    baseline: Optional[BaselineIndex],
    name_counts: Dict[str, int],
) -> Dict[str, str]:
    """Find this artifact's findings in the baseline, or nothing.

    Content hash first, then a basename unique on *both* sides. Anything
    ambiguous yields no prior: a missed ``fixed`` costs the document a nice-to
    -have, while a mis-attributed one asserts a remediation that never
    happened. See :class:`BaselineIndex`.
    """
    if baseline is None:
        return {}
    if digest and digest in baseline.by_hash:
        return baseline.by_hash[digest]
    name = art.get("name")
    if name and name_counts.get(name) == 1:
        return baseline.by_name.get(name, {})
    return {}


def derive_statements(
    artifacts: Sequence[Dict[str, Any]],
    baseline: Optional[BaselineIndex] = None,
) -> List[VexStatement]:
    """Build the VEX statements for one scan.

    ``baseline`` is the index returned by :func:`baseline_findings`. A class
    that was ``affected`` in the baseline and is ``not_affected`` now becomes
    ``fixed`` — the only way AIsbom can honestly assert that status, since a
    single scan observes one point in time.
    """
    name_counts: Dict[str, int] = {}
    for art in artifacts:
        name = art.get("name")
        if name:
            name_counts[name] = name_counts.get(name, 0) + 1

    statements: List[VexStatement] = []
    for index, art in enumerate(artifacts):
        sig = signals_from_artifact(art)
        if sig["format"] is None:
            continue
        ref = bom_ref_for(index, art)
        digest = _sha256_or_none(art.get("hash"))
        prior = _prior_for(art, digest, baseline, name_counts)

        for cls in VEX_FINDING_CLASSES:
            classified = _classify(cls, sig)
            if classified is None:
                continue
            status, notes = classified

            if (
                status == STATUS_NOT_AFFECTED
                and prior.get(cls.id) == STATUS_AFFECTED
            ):
                status = STATUS_FIXED
                notes = (
                    "Present in the baseline SBOM and absent from this scan. "
                    + notes
                )

            statements.append(
                VexStatement(
                    finding_class=cls,
                    product_ref=ref,
                    product_id="",  # filled in by the emitters, which know the serial
                    product_hash=digest,
                    status=status,
                    justification=(
                        JUSTIFICATION_CODE_NOT_PRESENT
                        if status == STATUS_NOT_AFFECTED
                        else None
                    ),
                    status_notes=notes,
                    action_statement=cls.action if status == STATUS_AFFECTED else None,
                )
            )
    return statements


@dataclass(frozen=True)
class BaselineIndex:
    """A previous scan's findings, addressable by an identity that survives it.

    **Not** keyed on ``bom-ref``. That identifier embeds the artifact's
    enumeration index (``artifact-<n>-<name>``, see
    :func:`aisbom.modelcard.bom_ref_for`), which is stable *within* a scan —
    which is all #111 needed it for — and not across two. Adding one file
    earlier in the tree shifts every later index, so matching on it would miss
    a genuinely remediated finding and report ``not_affected`` instead of
    ``fixed``.

    The serious case is worse than a miss. Artifact names are basenames, so a
    tree holding ``a/model.pt`` and ``b/model.pt`` yields two components whose
    refs differ only by index. If their order swaps between scans, the affected
    baseline entry lands on the *other*, always-clean artifact and the document
    claims it was fixed — a fabricated remediation, in the artifact whose whole
    purpose is evidencing remediation.

    So identity is content first, name second, and neither when ambiguous:

    * ``by_hash`` — SHA-256 is unforgeable identity, but only proves the file
      is byte-identical. Remediation usually *changes* the file, so this mostly
      serves to disambiguate same-named artifacts rather than to find fixes.
    * ``by_name`` — holds only names that appear exactly once in the baseline.
      A duplicated basename is dropped rather than guessed at.

    The caller additionally requires the name to be unique in the *current*
    scan. Where identity cannot be established, no prior is claimed and the
    finding is simply reported on its own merits — a missed ``fixed`` is a
    disappointing document; a fabricated one is a false statement.
    """

    by_hash: Dict[str, Dict[str, str]] = field(default_factory=dict)
    by_name: Dict[str, Dict[str, str]] = field(default_factory=dict)


def baseline_findings(sbom: Any) -> BaselineIndex:
    """Build a :class:`BaselineIndex` of ``{finding class id: status}`` from a
    previous CycloneDX SBOM.

    Accepts a path, a JSON string or an already-parsed document. Only
    ``affected`` entries matter to the caller (they are what a later scan can
    report as ``fixed``), but the full classification is kept so the mapping
    stays useful if that changes.
    """
    if isinstance(sbom, dict):
        document = sbom
    else:
        text = sbom
        if not (isinstance(sbom, str) and sbom.lstrip().startswith("{")):
            with open(sbom, "r") as fh:
                text = fh.read()
        document = json.loads(text)

    by_hash: Dict[str, Dict[str, str]] = {}
    by_name: Dict[str, Dict[str, str]] = {}
    seen_names: Dict[str, int] = {}

    for component in document.get("components") or []:
        sig = signals_from_component(component)
        if sig["format"] is None:
            continue
        per_class = {}
        for cls in VEX_FINDING_CLASSES:
            classified = _classify(cls, sig)
            if classified is not None:
                per_class[cls.id] = classified[0]

        for entry in component.get("hashes") or []:
            if str(entry.get("alg")).upper().replace("_", "-") == "SHA-256":
                digest = _sha256_or_none(entry.get("content"))
                if digest:
                    by_hash[digest] = per_class

        name = component.get("name")
        if name:
            seen_names[name] = seen_names.get(name, 0) + 1
            by_name[name] = per_class

    # A basename that occurs more than once identifies nothing.
    for name, count in seen_names.items():
        if count > 1:
            by_name.pop(name, None)

    return BaselineIndex(by_hash=by_hash, by_name=by_name)


# --------------------------------------------------------------------------
# Emitters
# --------------------------------------------------------------------------

def _timestamp(value: Optional[datetime] = None) -> str:
    return (value or datetime.now(timezone.utc)).isoformat(timespec="seconds")


def _product_id(sbom_serial: str, ref: str) -> str:
    """Address a component inside the SBOM this scan produced.

    The serial number identifies the document and the fragment identifies the
    component within it, so a consumer holding both files can join them without
    guessing — which is what makes the VEX statements about *this* scan rather
    than about a filename that may recur across scans.
    """
    return f"{sbom_serial}#{ref}"


def generate_openvex(
    statements: Sequence[VexStatement],
    *,
    sbom_serial: str,
    timestamp: Optional[datetime] = None,
    document_id: Optional[str] = None,
) -> str:
    """Serialize statements as an OpenVEX 0.2.0 document."""
    now = _timestamp(timestamp)
    doc: Dict[str, Any] = {
        "@context": OPENVEX_CONTEXT,
        "@id": document_id or f"{sbom_serial}#openvex",
        "author": VEX_AUTHOR,
        "timestamp": now,
        "version": 1,
        "tooling": f"aisbom-cli/{_tool_version()}",
        "statements": [],
    }

    for stmt in statements:
        cls = stmt.finding_class
        vulnerability: Dict[str, Any] = {
            "@id": cls.iri,
            "name": cls.id,
            "description": cls.description,
        }
        if cls.aliases:
            vulnerability["aliases"] = list(cls.aliases)

        product: Dict[str, Any] = {"@id": _product_id(sbom_serial, stmt.product_ref)}
        if stmt.product_hash:
            product["hashes"] = {"sha-256": stmt.product_hash}

        entry: Dict[str, Any] = {
            "vulnerability": vulnerability,
            "timestamp": now,
            "products": [product],
            "status": stmt.status,
        }
        if stmt.justification:
            entry["justification"] = stmt.justification
        if stmt.status_notes:
            entry["status_notes"] = stmt.status_notes
        if stmt.action_statement:
            entry["action_statement"] = stmt.action_statement
            entry["action_statement_timestamp"] = now
        doc["statements"].append(entry)

    return json.dumps(doc, indent=2)


def generate_cyclonedx_vex(
    statements: Sequence[VexStatement],
    *,
    sbom_serial: str,
    timestamp: Optional[datetime] = None,
    spec_version: str = "1.7",
) -> str:
    """Serialize statements as a CycloneDX VEX document.

    One ``vulnerabilities`` entry per finding class, with every product carrying
    that class's status listed under ``affects``. That is the shape CycloneDX
    models — a vulnerability affecting components — where OpenVEX models a
    statement per assertion, so the two documents carry the same facts in each
    format's own idiom rather than one being a transliteration of the other.

    Built as JSON directly rather than through ``cyclonedx-python-lib``'s
    ``Vulnerability`` model: the library scopes one ``analysis`` block per
    vulnerability, but AIsbom routinely reaches different conclusions about the
    same class on different artifacts in one scan (a repository holding both a
    malicious ``.pt`` and a clean ``.safetensors``). Splitting those into one
    ``analysis`` per state is what keeps each component's status truthful.
    """
    now = _timestamp(timestamp)

    # Group by (class, status) so each analysis block describes exactly the
    # components it is true of.
    grouped: Dict[tuple, List[VexStatement]] = {}
    for stmt in statements:
        grouped.setdefault((stmt.finding_class.id, stmt.status), []).append(stmt)

    vulnerabilities = []
    for (class_id, status), group in grouped.items():
        # Taken from the statement, never looked up in the module-level table.
        # A statement is self-contained by design, and the emitters must not
        # require its class to be one AIsbom currently ships: OSV-sourced CVE
        # statements will not be in `VEX_FINDING_CLASSES` at all, and neither
        # is a retired class being aliased through a rename. Re-deriving it
        # from the registry raised KeyError in both cases.
        cls = group[0].finding_class
        analysis: Dict[str, Any] = {"state": _CDX_STATE[status]}
        justification = group[0].justification
        if justification and justification in _CDX_JUSTIFICATION:
            analysis["justification"] = _CDX_JUSTIFICATION[justification]
        detail = "; ".join(dict.fromkeys(s.status_notes for s in group if s.status_notes))
        if detail:
            analysis["detail"] = detail

        entry: Dict[str, Any] = {
            "bom-ref": f"vex-{class_id}-{status}",
            "id": class_id,
            "source": {"name": VEX_AUTHOR, "url": cls.iri},
            "description": cls.description,
            "detail": cls.title,
            "analysis": analysis,
            "affects": [{"ref": s.product_ref} for s in group],
        }
        if cls.aliases:
            entry["references"] = [
                {"id": alias, "source": {"name": "NVD"}} for alias in cls.aliases
            ]
        if status == STATUS_AFFECTED:
            entry["recommendation"] = cls.action
        vulnerabilities.append(entry)

    doc = {
        "$schema": f"http://cyclonedx.org/schema/bom-{spec_version}.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": sbom_serial,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "aisbom-cli",
                        "version": _tool_version(),
                    }
                ]
            },
        },
        "externalReferences": [
            {
                "type": "bom",
                "url": sbom_serial,
                "comment": "The CycloneDX SBOM these statements describe.",
            }
        ],
        "vulnerabilities": vulnerabilities,
    }
    return json.dumps(doc, indent=2)


def finding_classes_markdown() -> str:
    """Render the registry that ``docs/vex-finding-classes.md`` publishes.

    Generated from the table rather than written by hand so the published
    registry cannot drift from the vocabulary the CLI actually emits; a test
    asserts the file on disk matches this output.
    """
    lines = [
        "<!-- Generated from aisbom/vex.py by tests/test_vex.py. Do not edit by hand. -->",
        "",
        "# AIsbom VEX finding classes",
        "",
        "These are **AIsbom finding classes, not CVE identifiers.** They name",
        "categories of content AIsbom detects inside a model file — things that",
        "have no CVE and never will, because the file itself is the payload",
        "rather than a published component with a patchable defect.",
        "",
        "They appear as the `vulnerability.name` of an OpenVEX statement and",
        "the `id` of a CycloneDX VEX entry, and resolve under "
        f"`{VEX_NAMESPACE}`.",
        "",
        "CVE-keyed statements about a project's Python dependencies are a",
        "separate, additive concern and arrive with OSV mapping; they will join",
        "the same document without changing anything below.",
        "",
        "## Compatibility policy",
        "",
        "These identifiers outlive the scan that produced them — they sit in",
        "submission folders, CI artifacts and audit archives. If one changed",
        "meaning or vanished, a build gate matching it would stop firing",
        "silently, and a year-on-year comparison would read the change as a",
        "finding resolved and a different one opened.",
        "",
        "So the guarantee is **not** that a class is never renamed. It is that",
        "a consumer is never broken:",
        "",
        "1. A class is **never deleted**, and an identifier is **never reused**",
        "   for a different meaning.",
        "2. If a class is renamed, its successor carries the old identifier in",
        "   `aliases`, so a rule matching the old string keeps matching.",
        "3. Every identifier ever published is tracked in an append-only list",
        "   in `aisbom/vex.py`, and the test suite fails if any of them stops",
        "   being resolvable. The policy is enforced, not merely stated.",
        "",
        "`aliases` carries real CVE identifiers too, where one applies. Both",
        "uses mean the same thing: another name for this same finding.",
        "",
        "## Classes",
        "",
    ]
    for cls in VEX_FINDING_CLASSES:
        lines.extend([
            f"## `{cls.id}`",
            "",
            f"**{cls.title}**",
            "",
            cls.description,
            "",
            f"- **Applies to:** {', '.join(sorted(cls.formats))}",
            f"- **Identifier:** {cls.iri}",
            f"- **Aliases:** {', '.join(cls.aliases) if cls.aliases else 'none'}",
            f"- **Remediation:** {cls.action}",
            "",
        ])
    return "\n".join(lines)
