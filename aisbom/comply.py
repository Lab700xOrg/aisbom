"""Regulator-facing documentation packs pre-filled from a scan (`aisbom comply`).

Two frameworks:

* ``eu-ai-act`` — an EU AI Act Annex XI technical-documentation skeleton and
  an Article 53(1)(d) public summary of training content, laid out section by
  section like the European Commission's template (published 24 July 2025).
* ``fda`` — the files an FD&C Act §524B premarket submission's SBOM package is
  assembled from: the SBOM, VEX, and a component support table.

The rule every builder here follows: **a field is filled only from something
the scan actually read, and says where it came from.** Everything else is a
``TODO (provider)`` placeholder. A regulator-facing document with a guessed
value in it is worse than one with a visible gap. Where a value is derived
rather than read, the derivation is narrow and labelled: a parameter count is
summed only over a provably complete set of safetensors files, and an
interpretation of a declared value (modality from the task, supplier from the
repository owner) is tagged *AIsbom's mapping*. A declared value that is not
the field's answer (model-card languages, CO2 emissions, the HF repository's
creation date) gets its own "declared" row and leaves the field itself TODO.

The builders read the serialized CycloneDX document rather than the scanner's
raw results. That is the file the pack bundles as ``sbom.json``, so every
pre-filled value can be traced back to a field a reader can inspect.

Wording follows the aisbom.io compliance guides: the documents describe what
the files contain and never pass a verdict on the provider. The test suite
fails on the same verdict words the platform bans.

The provider can fill the TODOs from an answers file (``--answers``), keyed
by the stable field ids every field carries. Answers are written as given and
tagged ``provider-supplied``; a value the scan read is never replaced, and
when both exist the pack shows both.
"""

from __future__ import annotations

import csv
import datetime
import difflib
import io
import json
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import yaml

# Bump on every change to the wording or field mapping of a generated
# document, so a pack in someone's submission folder can be traced to the
# exact template that produced it.
TEMPLATE_VERSION = "2026-11-15.2"

TODO = "TODO (provider)"

SOURCE_HF = "Hugging Face model card"
SOURCE_HF_REPO = "Hugging Face repository metadata"
SOURCE_HF_PARAMETERS = "Hugging Face safetensors metadata"
SOURCE_HEADER = "model file header"
SOURCE_SCAN = "AIsbom scan"
SOURCE_SCAN_PARAMETERS = "AIsbom scan of safetensors headers"
SOURCE_PROVIDER = "provider-supplied"
# Interpretive values: AIsbom's reading of a declared fact, not the fact itself.
MAPPING = "AIsbom's mapping"
SOURCE_MODALITY = f"{MAPPING} from the declared task"
SOURCE_SUPPLIER_HF = f"Hugging Face repository owner ({MAPPING})"
SOURCE_SUPPLIER_PYPI = f"PyPI author ({MAPPING})"

# Input / output modality for the Hugging Face tasks whose modalities follow
# from the task itself. A task missing here leaves both fields TODO rather
# than guessing. Listed in docs/comply.md; extend both together.
TASK_MODALITIES: Dict[str, Tuple[str, str]] = {
    "fill-mask": ("text", "text"),
    "text-generation": ("text", "text"),
    "text2text-generation": ("text", "text"),
    "text-classification": ("text", "text (class labels)"),
    "token-classification": ("text", "text (per-token labels)"),
    "zero-shot-classification": ("text", "text (class labels)"),
    "question-answering": ("text", "text"),
    "summarization": ("text", "text"),
    "translation": ("text", "text"),
    "sentence-similarity": ("text", "similarity scores"),
    "feature-extraction": ("text", "numeric vectors (embeddings)"),
    "table-question-answering": ("tables and text", "text"),
    "image-classification": ("image", "text (class labels)"),
    "object-detection": ("image", "bounding boxes with class labels"),
    "image-segmentation": ("image", "segmentation masks"),
    "image-to-text": ("image", "text"),
    "image-to-image": ("image", "image"),
    "text-to-image": ("text", "image"),
    "zero-shot-image-classification": ("image and text", "text (class labels)"),
    "visual-question-answering": ("image and text", "text"),
    "automatic-speech-recognition": ("audio", "text"),
    "audio-classification": ("audio", "text (class labels)"),
    "text-to-speech": ("text", "audio"),
    "text-to-audio": ("text", "audio"),
}

# A shard of a sharded safetensors release: `model-00002-of-00004.safetensors`.
_SHARD = re.compile(r"^(?P<stem>.+)-(?P<index>\d{5})-of-(?P<total>\d{5})\.safetensors$")

# Wording that reads as a regulatory verdict about the provider. AIsbom's own
# text never uses it (the test suite checks every generated file); provider
# answers that use it are written as given, with a warning. Keep in step with
# the list the aisbom.io compliance guides are held to.
VERDICT_WORDS = (
    "compliant",
    "compliance verdict",
    "certified",
    "certifies",
    "guarantee",
    "guaranteed",
    "meets the requirement",
    "satisfies the requirement",
    "legally",
    "approved by",
    "audit-proof",
)

ANNEX_XI_FILE = "annex-xi-technical-documentation.md"
ART53_FILE = "art53-training-content-summary.md"
SUPPORT_FILE = "component-support.csv"
README_FILE = "README.md"
SBOM_FILE = "sbom.json"

DISCLAIMER = (
    "AIsbom pre-filled this document from what a scan could read from the "
    "model files. It does not assess, certify or attest to regulatory status, "
    "and it describes files, not your processes, risk management or product "
    "safety. Check every pre-filled value and complete every TODO before use. "
    "This is not legal advice, and responsibility for these obligations rests "
    "with you as the provider."
)

_ML_COMPONENT_TYPE = "machine-learning-model"

_EUR_LEX_AI_ACT = "https://eur-lex.europa.eu/eli/reg/2024/1689/oj"
_COMMISSION_TEMPLATE = (
    "https://digital-strategy.ec.europa.eu/en/library/"
    "explanatory-notice-and-template-public-summary-training-content-general-purpose-ai-models"
)
_GUIDE_ART53 = "https://aisbom.io/compliance/eu-ai-act-article-53"
_GUIDE_FDA = "https://aisbom.io/compliance/fda-524b"
# The field-id list and answers-file guide. Linked online because a pip
# install ships only the `aisbom` package, not `docs/`.
DOCS_URL = "https://github.com/Lab700xOrg/aisbom/blob/main/docs/comply.md"


def _filling_todos(w: "_Writer", what: str) -> None:
    w.heading(2, "Filling in the TODOs")
    w.para(
        f"Write {what} once in an answers file and every later pack comes out "
        "filled. Rerun the same command with `--write-answers-template "
        "comply.yaml` to get a starter file listing every field, fill in what "
        "you can, then rerun with `--answers comply.yaml`. Answers are tagged "
        f"_({SOURCE_PROVIDER})_ and never replace a value the scan read. "
        f"Field ids and examples: {DOCS_URL}"
    )


# ---------------------------------------------------------------------------
# Reading the SBOM
# ---------------------------------------------------------------------------

def _components(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    comps = doc.get("components") if isinstance(doc, dict) else None
    if not isinstance(comps, list):
        return []
    return [c for c in comps if isinstance(c, dict)]


def _props(entries: Any) -> List[Tuple[str, str]]:
    if not isinstance(entries, list):
        return []
    return [
        (str(p.get("name")), str(p.get("value")))
        for p in entries
        if isinstance(p, dict) and p.get("name") and p.get("value") is not None
    ]


def _prop_values(component: Dict[str, Any], name: str) -> List[str]:
    return [v for n, v in _props(component.get("properties")) if n == name]


def _card(component: Dict[str, Any]) -> Dict[str, Any]:
    card = component.get("modelCard")
    return card if isinstance(card, dict) else {}


def _card_prop(component: Dict[str, Any], name: str) -> Optional[str]:
    for n, v in _props(_card(component).get("properties")):
        if n == name:
            return v
    return None


def _params(component: Dict[str, Any]) -> Dict[str, Any]:
    params = _card(component).get("modelParameters")
    return params if isinstance(params, dict) else {}


def _sha256(component: Dict[str, Any]) -> Optional[str]:
    hashes = component.get("hashes")
    if not isinstance(hashes, list):
        return None
    for entry in hashes:
        if not isinstance(entry, dict):
            continue
        alg = str(entry.get("alg") or "").upper().replace("_", "-")
        content = str(entry.get("content") or "")
        if alg in ("SHA-256", "SHA256") and len(content) == 64:
            return content
    return None


def _licenses(component: Dict[str, Any]) -> List[str]:
    found: List[str] = []
    entries = component.get("licenses")
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("expression"):
                found.append(str(entry["expression"]))
                continue
            lic = entry.get("license")
            if isinstance(lic, dict):
                value = lic.get("id") or lic.get("name")
                if value:
                    found.append(str(value))
    return found


def _distinct(pairs: Iterable[Tuple[Optional[str], str]]) -> List[Tuple[str, str]]:
    """Drop empty values and repeats, keeping first-seen order."""
    seen = set()
    out: List[Tuple[str, str]] = []
    for value, source in pairs:
        if not value or not str(value).strip():
            continue
        key = (str(value).strip(), source)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


@dataclass
class _Facts:
    """Everything the documents may pre-fill, each value paired with its source."""

    models: List[Dict[str, Any]]
    dependencies: List[Dict[str, Any]]
    repos: List[Tuple[str, str]]
    versioned_names: List[Tuple[str, str]]
    tasks: List[Tuple[str, str]]
    families: List[Tuple[str, str]]
    architectures: List[Tuple[str, str]]
    datasets: List[Tuple[str, str]]
    licenses: List[Tuple[str, str]]
    libraries: List[Tuple[str, str]]
    formats: List[Tuple[str, str]]
    base_models: List[Tuple[str, str]] = field(default_factory=list)
    languages: List[Tuple[str, str]] = field(default_factory=list)
    first_published: List[Tuple[str, str]] = field(default_factory=list)
    parameter_counts: List[Tuple[str, str]] = field(default_factory=list)
    input_modalities: List[Tuple[str, str]] = field(default_factory=list)
    output_modalities: List[Tuple[str, str]] = field(default_factory=list)
    hardware: List[Tuple[str, str]] = field(default_factory=list)
    co2: List[Tuple[str, str]] = field(default_factory=list)
    evaluations: List[Tuple[str, str]] = field(default_factory=list)


def _card_props(component: Dict[str, Any], name: str) -> List[str]:
    return [v for n, v in _props(_card(component).get("properties")) if n == name]


def _co2_line(component: Dict[str, Any]) -> Optional[str]:
    """`149.2 g CO2eq (source: codecarbon; training type: fine-tuning; …)`."""
    emissions = _card_prop(component, "aisbom:hf:co2_eq_emissions")
    if emissions is None:
        return None
    details = [
        f"{label}: {value}"
        for key, label in (("source", "source"), ("training_type", "training type"),
                           ("geographical_location", "location"))
        for value in [_card_prop(component, f"aisbom:hf:co2_eq_emissions:{key}")]
        if value
    ]
    # The model-card spec gives `co2_eq_emissions` in grams.
    line = f"{emissions} g CO2eq"
    return f"{line} ({'; '.join(details)})" if details else line


def _evaluations(component: Dict[str, Any]) -> List[str]:
    metrics = _card(component).get("quantitativeAnalysis")
    metrics = metrics.get("performanceMetrics") if isinstance(metrics, dict) else None
    out: List[str] = []
    for m in metrics if isinstance(metrics, list) else []:
        if isinstance(m, dict) and m.get("type") and m.get("value") is not None:
            line = f"{m['type']} {m['value']}"
            out.append(f"{line} ({m['slice']})" if m.get("slice") else line)
    return out


def _int_prop(component: Dict[str, Any], name: str) -> Optional[int]:
    values = _prop_values(component, name)
    try:
        value = int(values[0]) if len(values) == 1 else None
    except ValueError:
        return None
    return value if value is not None and value >= 0 else None


def _local_parameter_counts(models: Sequence[Dict[str, Any]]) -> List[Tuple[str, str]]:
    """Parameter counts summed from safetensors headers, only for complete sets.

    A set is one unsharded `.safetensors` file (its own count), or a sharded
    release the scanner marked complete with `aisbom:safetensors:set_parameters`.
    Completeness is never re-derived here from component names: those are
    basenames for local scans, so shards from two unrelated directories would
    look like one complete set. A partial sum would understate the model, and
    Annex XI 1(d) is pre-filled from this.
    """
    out: List[Tuple[str, str]] = []
    for m in models:
        name = posixpath.basename(str(m.get("name") or ""))
        if not name.endswith(".safetensors"):
            continue
        shard = _SHARD.match(name)
        if shard is None:
            count = _int_prop(m, "aisbom:safetensors:parameters")
            if count is not None:
                out.append((f"{count:,} ({name})", SOURCE_SCAN_PARAMETERS))
            continue
        total = _int_prop(m, "aisbom:safetensors:set_parameters")
        shards = _int_prop(m, "aisbom:safetensors:set_shards")
        if total is not None and shards:
            out.append((
                f"{total:,} ({shard['stem']}-*-of-{shards:05d}.safetensors, {shards} shards)",
                SOURCE_SCAN_PARAMETERS,
            ))
    return out


def _collect(doc: Dict[str, Any]) -> _Facts:
    comps = _components(doc)
    models = [c for c in comps if c.get("type") == _ML_COMPONENT_TYPE]
    deps = [c for c in comps if c.get("type") != _ML_COMPONENT_TYPE]

    repos, names, tasks, families, archs = [], [], [], [], []
    datasets, licenses, libraries, formats = [], [], [], []
    bases, languages, published, hf_params = [], [], [], []
    inputs, outputs, hardware, co2, evaluations = [], [], [], [], []
    for m in models:
        for base in _card_props(m, "aisbom:hf:base_model"):
            bases.append((base, SOURCE_HF))
        for language in _card_props(m, "aisbom:hf:language"):
            languages.append((language, SOURCE_HF))
        published.append((_card_prop(m, "aisbom:hf:created_at"), SOURCE_HF_REPO))
        total = _card_prop(m, "aisbom:hf:parameters_total")
        if total and total.isdigit():
            hf_params.append((f"{int(total):,}", SOURCE_HF_PARAMETERS))
        task = _params(m).get("task")
        if isinstance(task, str) and task in TASK_MODALITIES:
            inputs.append((TASK_MODALITIES[task][0], SOURCE_MODALITY))
            outputs.append((TASK_MODALITIES[task][1], SOURCE_MODALITY))
        hardware.append((_card_prop(m, "aisbom:hf:co2_eq_emissions:hardware_used"), SOURCE_HF))
        co2.append((_co2_line(m), SOURCE_HF))
        for line in _evaluations(m):
            evaluations.append((line, SOURCE_HF))
        repo = _card_prop(m, "aisbom:hf:repo_id")
        # Card values come from Hugging Face whenever the card names a repo;
        # without one, the only source the card builder has is the file header.
        card_source = SOURCE_HF if repo else SOURCE_HEADER
        params = _params(m)
        if repo:
            repos.append((repo, SOURCE_HF))
            revision = _card_prop(m, "aisbom:hf:revision")
            names.append((f"{repo}@{revision}" if revision else repo, SOURCE_HF))
        tasks.append((params.get("task"), card_source))
        families.append((params.get("architectureFamily"), card_source))
        archs.append((params.get("modelArchitecture"), card_source))
        for ds in params.get("datasets") or []:
            if isinstance(ds, dict):
                datasets.append((ds.get("name"), card_source))
        for lic in _licenses(m):
            licenses.append((lic, SOURCE_SCAN))
        licenses.append((_card_prop(m, "aisbom:hf:license"), SOURCE_HF))
        libraries.append((_card_prop(m, "aisbom:hf:library_name"), SOURCE_HF))
        for fmt in _prop_values(m, "aisbom:format"):
            formats.append((fmt, SOURCE_SCAN))

    return _Facts(
        models=models,
        dependencies=deps,
        repos=_distinct(repos),
        versioned_names=_distinct(names),
        tasks=_distinct(tasks),
        families=_distinct(families),
        architectures=_distinct(archs),
        datasets=_distinct(datasets),
        licenses=_distinct(licenses),
        libraries=_distinct(libraries),
        formats=_distinct(formats),
        base_models=_distinct(bases),
        languages=_distinct(languages),
        first_published=_distinct(published),
        parameter_counts=_distinct(hf_params + _local_parameter_counts(models)),
        input_modalities=_distinct(inputs),
        output_modalities=_distinct(outputs),
        hardware=_distinct(hardware),
        co2=_distinct(co2),
        evaluations=_distinct(evaluations),
    )


# ---------------------------------------------------------------------------
# Writing Markdown
# ---------------------------------------------------------------------------

def _esc(value: Any) -> str:
    """Make a value safe inside a Markdown table cell or inline span."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


@dataclass
class _Field:
    """One answerable field, as the answers file and its template see it."""

    fid: str
    label: str
    hint: str
    heading: str
    scan: bool  # the scan pre-fills it when it can read a value
    doc: str = ""


def _provider_value(answer: str) -> Tuple[str, List[str]]:
    """Render an answer: the inline part, plus indented lines for a
    multi-line answer so its paragraphs survive inside the list item."""
    if "\n" not in answer:
        return f"{answer} _({SOURCE_PROVIDER})_", []
    block = [f"  {line}" if line.strip() else "" for line in answer.split("\n")]
    return f"_({SOURCE_PROVIDER}, below)_", block


@dataclass
class _Writer:
    answers: Dict[str, str] = field(default_factory=dict)
    lines: List[str] = field(default_factory=list)
    filled: int = 0
    provided: int = 0
    todo: int = 0
    both: List[str] = field(default_factory=list)
    fields: List[_Field] = field(default_factory=list)
    _heading: str = ""

    def heading(self, level: int, text: str) -> None:
        if self.lines and self.lines[-1] != "":
            self.lines.append("")
        self.lines.extend([f"{'#' * level} {text}", ""])
        self._heading = text

    def para(self, text: str) -> None:
        if self.lines and self.lines[-1] != "":
            self.lines.append("")
        self.lines.extend([text, ""])

    def fact(self, fid: str, label: str, values: Sequence[Tuple[str, str]],
             hint: str = "") -> None:
        """A field pre-filled from the scan, or a TODO when the scan had nothing.

        A provider answer never replaces a scan-read value: both are shown,
        scan first, and the field is listed for the provider to reconcile.
        """
        self.fields.append(_Field(fid, label, hint, self._heading, scan=True))
        answer = self.answers.get(fid)
        if not values:
            self._answer_or_todo(label, hint, answer)
            return
        self.filled += 1
        line = f"- **{label}:** " + ", ".join(f"`{_esc(v)}` _({src})_" for v, src in values)
        block: List[str] = []
        if answer is not None:
            self.both.append(fid)
            inline, block = _provider_value(answer)
            line += f"; {inline}"
        if hint:
            line += f" — {hint}"
        self.lines.append(line)
        self.lines.extend(block)

    def ask(self, fid: str, label: str, hint: str = "") -> None:
        """A field only the provider can answer."""
        self.fields.append(_Field(fid, label, hint, self._heading, scan=False))
        self._answer_or_todo(label, hint, self.answers.get(fid))

    def _answer_or_todo(self, label: str, hint: str, answer: Optional[str]) -> None:
        if answer is not None:
            self.provided += 1
            inline, block = _provider_value(answer)
            self.lines.append(f"- **{label}:** {inline}")
            self.lines.extend(block)
            return
        self.todo += 1
        line = f"- **{label}:** **{TODO}**"
        if hint:
            line += f" — {hint}"
        self.lines.append(line)

    def table(self, header: Sequence[str], rows: Sequence[Sequence[Any]]) -> None:
        if self.lines and self.lines[-1] != "":
            self.lines.append("")
        self.lines.append("| " + " | ".join(header) + " |")
        self.lines.append("|" + "|".join("---" for _ in header) + "|")
        for row in rows:
            self.lines.append("| " + " | ".join(_esc(c) for c in row) + " |")
        self.lines.append("")

    def close(self) -> str:
        while self.lines and self.lines[-1] == "":
            self.lines.pop()
        self.lines.extend(["", "---", "", DISCLAIMER])
        return "\n".join(self.lines).rstrip() + "\n"


def _intro(w: _Writer, title: str, target: str, *, legend: bool = True,
           provider: bool = False) -> None:
    w.lines.extend([f"# {title}", ""])
    w.para(
        f"Generated by AIsbom from a scan of `{_esc(target)}`. "
        f"Template version {TEMPLATE_VERSION}."
    )
    if legend:
        w.para(
            f"Values tagged with a source in italics were read by the scan. Fields "
            f"marked **{TODO}** need information a file scan cannot read; "
            f"AIsbom leaves them blank rather than guess. Values tagged "
            f"_{MAPPING}_ are AIsbom's reading of a declared value; check them."
        )
    if provider:
        w.para(
            f"Values tagged _({SOURCE_PROVIDER})_ come from the provider's "
            f"answers file and are written as given; AIsbom did not read them "
            f"from the files."
        )


# ---------------------------------------------------------------------------
# EU AI Act — Annex XI
# ---------------------------------------------------------------------------

# Every per-format threat property the scanner writes (see `properties.py`),
# with the label the summary gives it.
_THREAT_PROPERTIES = (
    ("aisbom:pickle:opcode", "dangerous imports"),
    ("aisbom:keras:threat", "Keras threats"),
    ("aisbom:gguf:chat_template_threat", "chat template threats"),
    ("aisbom:onnx:threat", "ONNX threats"),
)

_ELEVATED_RISKS = ("CRITICAL", "HIGH")


def _findings(component: Dict[str, Any]) -> str:
    notes: List[str] = []
    for prop, label in _THREAT_PROPERTIES:
        values = _prop_values(component, prop)
        if values:
            notes.append(f"{label}: " + ", ".join(values))
    if _prop_values(component, "aisbom:unreadable"):
        notes.append("not readable by any parser; not inspected")
    if _prop_values(component, "aisbom:pickle:scan_incomplete"):
        notes.append("pickle scan incomplete")
    if notes:
        return "; ".join(notes)
    # A threat property this module does not know yet must not read as a
    # clean bill of health beside an elevated rating.
    if any(r.upper().startswith(_ELEVATED_RISKS) for r in _prop_values(component, "aisbom:risk")):
        return f"see the AIsbom risk rating and {SBOM_FILE}"
    return "none"


def _annex_xi(facts: _Facts, target: str, answers: Dict[str, str]) -> _Writer:
    w = _Writer(answers=answers)
    _intro(w, "Technical documentation — EU AI Act Annex XI (skeleton)", target,
           provider=bool(answers))
    w.para(
        "Article 53(1)(a) of Regulation (EU) 2024/1689 asks providers of "
        "general-purpose AI models to draw up technical documentation containing "
        "at least the information in Annex XI, and to keep it up to date. "
        "Section 1 applies to every such provider; Section 2 only to models "
        "with systemic risk."
    )

    w.heading(2, "Section 1 — Information for all providers of general-purpose AI models")
    w.para("**Point 1 — General description of the model.**")

    w.heading(3, "Point 1(a) — Intended tasks and the AI systems the model can be integrated into")
    w.fact("annex_xi.1a.task_declared", "Task declared in the model card", facts.tasks,
           "confirm it matches the tasks you intend the model to perform")
    w.ask("annex_xi.1a.intended_tasks", "Intended tasks", "what the model is intended to do")
    w.ask("annex_xi.1a.integration_systems",
          "Type and nature of AI systems it can be integrated into")

    w.heading(3, "Point 1(b) — Acceptable use policies")
    w.ask("annex_xi.1b.acceptable_use", "Applicable acceptable use policies")

    w.heading(3, "Point 1(c) — Date of release and methods of distribution")
    w.ask("annex_xi.1c.release_date", "Date of release")
    w.fact("annex_xi.1c.hf_first_published", "First published on Hugging Face",
           facts.first_published,
           "when the repository appeared on Hugging Face, which is not necessarily "
           "the release date")
    w.fact("annex_xi.1c.hf_repository",
           "Hugging Face repository the scanned files come from", facts.repos)
    w.ask("annex_xi.1c.distribution_methods", "Methods of distribution")

    w.heading(3, "Point 1(d) — Architecture and number of parameters")
    w.fact("annex_xi.1d.architecture_family", "Architecture family", facts.families)
    w.fact("annex_xi.1d.model_architecture", "Model architecture", facts.architectures)
    w.fact("annex_xi.1d.parameter_count", "Number of parameters", facts.parameter_counts,
           "pre-filled only from a complete set of safetensors weights; other "
           "formats and partial sets are left to the provider")

    w.heading(3, "Point 1(e) — Modality and format of inputs and outputs")
    w.fact("annex_xi.1e.input_modality", "Input modality and format",
           facts.input_modalities, "add the input format (for example the tokenizer)")
    w.fact("annex_xi.1e.output_modality", "Output modality and format",
           facts.output_modalities)

    w.heading(3, "Point 1(f) — Licence")
    w.fact("annex_xi.1f.licence", "Licence", facts.licenses)

    w.para("**Point 2 — Detailed description of the elements in point 1 and of the development process.**")

    w.heading(3, "Point 2(a) — Technical means needed for integration")
    w.fact("annex_xi.2a.library", "Library declared in the model card", facts.libraries)
    w.fact("annex_xi.2a.file_formats", "Model file formats in this release", facts.formats)
    w.ask("annex_xi.2a.integration_instructions",
          "Instructions of use, infrastructure and tools needed to integrate the model")

    w.heading(3, "Point 2(b) — Design specifications and training process")
    w.ask("annex_xi.2b.training_methods", "Training methodologies and techniques")
    w.ask("annex_xi.2b.design_choices", "Key design choices, with rationale and assumptions")
    w.ask("annex_xi.2b.optimisation_target",
          "What the model is designed to optimise for, and the relevance of its parameters")

    w.heading(3, "Point 2(c) — Data used for training, testing and validation")
    w.fact("annex_xi.2c.declared_datasets", "Training datasets declared in the model card",
           facts.datasets, "confirm each one, and list any the card omits")
    w.ask("annex_xi.2c.data_provenance",
          "Type and provenance of the data, and curation methodologies")
    w.ask("annex_xi.2c.data_points", "Number of data points, scope and main characteristics")
    w.ask("annex_xi.2c.data_selection", "How the data was obtained and selected")
    w.ask("annex_xi.2c.bias_measures",
          "Measures to detect unsuitable data sources and identifiable biases")

    w.heading(3, "Point 2(d) — Computational resources used to train the model")
    w.ask("annex_xi.2d.compute", "Computational resources",
          "for example the number of floating point operations")
    w.fact("annex_xi.2d.hardware_declared", "Training hardware declared in the model card",
           facts.hardware)
    w.ask("annex_xi.2d.training_time", "Training time and other relevant training details")

    w.heading(3, "Point 2(e) — Energy consumption")
    w.ask("annex_xi.2e.energy", "Known or estimated energy consumption",
          "may be estimated from the computational resources in point 2(d)")
    w.fact("annex_xi.2e.co2_declared", "CO2 emissions declared in the model card",
           facts.co2, "emissions are not energy consumption; the energy field above "
           "still needs the provider's figure")

    w.heading(2, "Section 2 — Additional information for models with systemic risk")
    w.para(
        "Complete this section only for a general-purpose AI model with systemic "
        "risk (Article 51); otherwise mark it not applicable."
    )
    w.heading(3, "Item 1 — Evaluation strategies and results")
    w.ask("annex_xi.s2_1.evaluation", "Evaluation strategies, criteria, metrics and results")
    w.fact("annex_xi.s2_1.evaluation_declared",
           "Evaluation results declared in the model card", facts.evaluations,
           "self-reported in the card; the full list is in sbom.json")
    w.heading(3, "Item 2 — Adversarial testing and model adaptations")
    w.ask("annex_xi.s2_2.adversarial_testing",
          "Adversarial testing measures (for example red teaming), alignment and fine-tuning")
    w.heading(3, "Item 3 — System architecture")
    w.ask("annex_xi.s2_3.system_architecture",
          "How the software components build on or feed into each other",
          "where applicable")

    w.heading(2, "Appendix A — Scanned model files")
    note = (
        "AIsbom's mapping: the Act does not name hashes, but a hash pins exactly "
        "which file this documentation describes."
    )
    if any(_sha256(m) is None for m in facts.models):
        note += (
            " A remote scan reads files without downloading them whole, so it "
            "computes no hash; scan a local copy to record one."
        )
    w.para(note)
    if facts.models:
        w.table(
            ["File", "Format", "SHA-256", "AIsbom risk", "Security findings"],
            [
                [
                    m.get("name") or "<unnamed>",
                    ", ".join(_prop_values(m, "aisbom:format")) or "unknown",
                    _sha256(m) or "not computed",
                    ", ".join(_prop_values(m, "aisbom:risk")) or "unknown",
                    _findings(m),
                ]
                for m in facts.models
            ],
        )
    else:
        w.para("The scan found no model files.")

    w.heading(2, "Appendix B — Software dependencies")
    w.para(
        "Article 53(1)(b) and Annex XII expect integrators to receive the "
        "versions of software relevant to using the model. These are the "
        "dependencies the scan found."
    )
    if facts.dependencies:
        w.table(
            ["Package", "Version", "Licence"],
            [
                [d.get("name") or "<unnamed>", d.get("version") or "unpinned",
                 ", ".join(_licenses(d)) or "unknown"]
                for d in facts.dependencies
            ],
        )
    else:
        w.para("The scan found no requirements.txt dependencies.")
    return w


# ---------------------------------------------------------------------------
# EU AI Act — Article 53(1)(d) public summary of training content
# ---------------------------------------------------------------------------

_YES_NO = "Yes / No"
_MODALITY = "Text / Image / Audio / Video / Other"


def _art53(facts: _Facts, target: str, answers: Dict[str, str]) -> _Writer:
    w = _Writer(answers=answers)
    _intro(w, "Public summary of training content — EU AI Act Article 53(1)(d) (draft)",
           target, provider=bool(answers))
    w.para(
        "Follows the sections of the European Commission's *Template for the "
        "Public Summary of Training Content for General-Purpose AI models* "
        f"(published 24 July 2025, {_COMMISSION_TEMPLATE}). The Commission's "
        "template is the form providers use; this draft follows its numbering "
        "so answers can be transferred section by section."
    )
    w._heading = "Summary version"
    w.ask("art53.summary.version", "Version of the summary",
          "with links to previous versions where applicable")
    w.ask("art53.summary.last_update", "Last update")

    w.heading(2, "1 General information")
    w.heading(3, "1.1 Provider identification")
    w.ask("art53.1_1.provider", "Provider name and contact details")
    w.ask("art53.1_1.authorised_representative",
          "Authorised representative name and contact details",
          "only if the provider is established outside the Union (Article 54)")

    w.heading(3, "1.2 Model identification")
    w.fact("art53.1_2.versioned_names", "Versioned model name(s)", facts.versioned_names,
           "replace with the versioned name you place on the market if it differs")
    w.fact("art53.1_2.model_card_link", "Model card link",
           [(f"https://huggingface.co/{repo}", src) for repo, src in facts.repos])
    w.fact("art53.1_2.model_dependencies", "Model dependencies", facts.base_models,
           "if the model modifies or fine-tunes another general-purpose AI model, "
           "name it and link its summary")
    w.ask("art53.1_2.market_placement_date",
          "Date of placement of the model on the Union market")

    w.heading(3, "1.3 Modalities, overall training data size and other characteristics")
    w.ask("art53.1_3.modalities", "Modalities present in the training data", _MODALITY)
    w.ask("art53.1_3.size_per_modality", "Training data size per modality",
          "the template's size ranges, or another unit")
    w.ask("art53.1_3.content_types", "Types of content per modality")
    w.ask("art53.1_3.latest_acquisition_date", "Latest date of data acquisition or collection",
          "MM/YYYY, and whether training continues on new data")
    w.fact("art53.1_3.languages_declared", "Languages declared in the model card",
           facts.languages, "the languages the card lists, which are not necessarily "
           "the languages of the training data")
    w.ask("art53.1_3.linguistic_characteristics",
          "Linguistic characteristics of the overall training data")
    w.ask("art53.1_3.other_characteristics",
          "Other relevant characteristics of the overall training data")

    w.heading(2, "2 List of data sources")
    w.heading(3, "2.1 Publicly available datasets")
    w.ask("art53.2_1.used", "Have you used publicly available datasets to train the model?",
          _YES_NO)
    w.fact("art53.2_1.declared_datasets", "Datasets declared in the model card", facts.datasets,
           "confirm each was used, add an access link, and check whether it is "
           "'large' (over 3% of the public-dataset data for a modality)")
    w.ask("art53.2_1.large_datasets", "List of large publicly available datasets",
          "name and access link for each")
    w.ask("art53.2_1.other_datasets", "General description of other publicly available datasets")

    w.heading(3, "2.2 Private non-publicly available datasets obtained from third parties")
    w.heading(4, "2.2.1 Datasets commercially licensed by rightsholders or their representatives")
    w.ask("art53.2_2_1.licensed", "Transactional commercial licensing agreements concluded?",
          _YES_NO)
    w.ask("art53.2_2_1.modalities", "Modalities covered", _MODALITY)
    w.heading(4, "2.2.2 Private datasets obtained from other third parties")
    w.ask("art53.2_2_2.obtained", "Private datasets obtained from other third parties?", _YES_NO)
    w.ask("art53.2_2_2.modalities", "Modalities covered", _MODALITY)
    w.ask("art53.2_2_2.known_datasets", "List of those datasets, if publicly known")
    w.ask("art53.2_2_2.other_description", "General description of those not publicly known")

    w.heading(3, "2.3 Data crawled and scraped from online sources")
    w.ask("art53.2_3.crawlers_used", "Were crawlers used by the provider or on its behalf?",
          _YES_NO)
    w.ask("art53.2_3.crawler_names", "Crawler name(s) or identifier(s)")
    w.ask("art53.2_3.crawler_purposes", "Purposes of the crawler(s)")
    w.ask("art53.2_3.crawler_behaviour", "General description of crawler behaviour",
          "for example robots.txt, paywalls, captchas")
    w.ask("art53.2_3.collection_period", "Period of data collection", "from MM/YYYY to MM/YYYY")
    w.ask("art53.2_3.content_description",
          "Description of the type of content and online sources crawled")
    w.ask("art53.2_3.modalities", "Modalities covered", _MODALITY)
    w.ask("art53.2_3.top_domains", "Most relevant domain names crawled",
          "top 10% by content size; SMEs top 5% or 1,000, whichever is lower")

    w.heading(3, "2.4 User data")
    w.ask("art53.2_4.model_interactions_used",
          "Was data from user interactions with the model used to train it?", _YES_NO)
    w.ask("art53.2_4.other_services_used",
          "Was data from user interactions with your other services or products used?", _YES_NO)
    w.ask("art53.2_4.services_description",
          "Description of the services or products the user data came from")
    w.ask("art53.2_4.modalities", "Modalities covered", _MODALITY)

    w.heading(3, "2.5 Synthetic data")
    w.ask("art53.2_5.synthetic_used",
          "Was synthetic AI-generated data created by you or on your behalf to train the model?",
          _YES_NO)
    w.ask("art53.2_5.modalities", "Modalities of the synthetic data", _MODALITY)
    w.ask("art53.2_5.gpai_models_used",
          "General-purpose AI model(s) on the market used to generate it")
    w.ask("art53.2_5.other_models_used", "Other AI models used to generate it, including your own")

    w.heading(3, "2.6 Other sources of data")
    w.ask("art53.2_6.other_sources_used",
          "Were data sources other than those in sections 2.1 to 2.5 used?", _YES_NO)
    w.ask("art53.2_6.description", "Narrative description of those sources and data")

    w.heading(2, "3 Data processing aspects")
    w.heading(3, "3.1 Respect of reservation of rights from the text and data mining exception or limitation")
    w.ask("art53.3_1.code_of_practice_signatory",
          "Signatory to the Code of Practice for general-purpose AI models?", _YES_NO)
    w.ask("art53.3_1.rights_reservation_measures",
          "Measures taken to respect reservations of rights before and during data collection")

    w.heading(3, "3.2 Removal of illegal content")
    w.ask("art53.3_2.illegal_content_measures", "General description of measures taken")

    w.heading(3, "3.3 Other information (optional)")
    w.ask("art53.3_3.other_information", "Other relevant information about data processing",
          "optional")
    return w


def _eu_readme(target: str, annex: _Writer, art53: _Writer, *, provider: bool) -> str:
    w = _Writer()
    _intro(w, "EU AI Act documentation pack", target, provider=provider)
    w.table(
        ["File", "What it is"],
        [
            [ANNEX_XI_FILE, "Annex XI technical documentation skeleton (Article 53(1)(a))"],
            [ART53_FILE, "Public summary of training content, in the Commission template's sections (Article 53(1)(d))"],
            [SBOM_FILE, "The CycloneDX 1.7 SBOM every pre-filled value was read from"],
        ],
    )
    filled = annex.filled + art53.filled
    todo = annex.todo + art53.todo
    if provider:
        provided = annex.provided + art53.provided
        w.para(
            f"{filled} field(s) pre-filled from the scan, {provided} provider-supplied "
            f"from the answers file, {todo} left as TODO for the provider."
        )
    else:
        w.para(f"{filled} field(s) pre-filled from the scan, {todo} left as TODO for the provider.")
    both = annex.both + art53.both
    if both:
        w.heading(2, "Fields with both a scan-read and a provider-supplied value")
        w.para(
            "The documents show both values, the scan's first. Check whether they "
            "agree, and correct the answers file or the model card if not."
        )
        w.lines.extend(f"- `{fid}`" for fid in both)
    _filling_todos(w, "the answers a scan cannot read")
    w.para(
        "A file scan can read what the model files and their Hugging Face model "
        "card declare: identifiers, task, architecture, licence, declared "
        "datasets, file formats, hashes and security findings. It cannot read "
        "the provider's identity, release plans, training process, compute, "
        "energy use, data collection or copyright measures."
    )
    w.heading(2, "Sources")
    w.lines.extend([
        f"- Regulation (EU) 2024/1689: {_EUR_LEX_AI_ACT}",
        f"- Commission template for the public summary of training content: {_COMMISSION_TEMPLATE}",
        f"- AIsbom guide to Article 53: {_GUIDE_ART53}",
    ])
    return w.close()


def build_eu_ai_act_pack(
    doc: Dict[str, Any], *, target: str, answers: Optional["Answers"] = None,
) -> Dict[str, str]:
    """Return ``{filename: content}`` for the EU AI Act pack (SBOM excluded)."""
    facts = _collect(doc)
    fields = dict(answers.fields) if answers else {}
    annex = _annex_xi(facts, target, fields)
    art53 = _art53(facts, target, fields)
    readme = _eu_readme(target, annex, art53, provider=bool(fields))
    return {
        ANNEX_XI_FILE: annex.close(),
        ART53_FILE: art53.close(),
        README_FILE: readme,
    }


# ---------------------------------------------------------------------------
# FDA §524B
# ---------------------------------------------------------------------------

# Columns are only ever appended, so a spreadsheet built on an earlier pack
# keeps reading the columns it knows.
_SUPPORT_COLUMNS = [
    "bom_ref", "name", "type", "version", "sha256", "license",
    "support_level", "end_of_support_date", "support_source",
    "supplier", "supplier_source",
    "end_of_support_lookup", "end_of_support_lookup_source",
]


def supplier_for(component: Dict[str, Any]) -> Tuple[str, str]:
    """``(supplier, source)`` under AIsbom's supplier rule, or ``(TODO, why)``.

    * A model: the Hugging Face repository owner, only when the card names no
      base model or every base model sits in the owner's own namespace. A
      fine-tune or re-upload of another organisation's model stays TODO, since
      the uploader is then not plainly the supplier. Known gap: a re-upload
      whose card declares no base model still gets the uploader.
    * A package: the author its PyPI release declares.
    """
    if component.get("type") == _ML_COMPONENT_TYPE:
        owner = _card_prop(component, "aisbom:hf:author")
        if not owner:
            return TODO, ""
        foreign = [b for b in _card_props(component, "aisbom:hf:base_model")
                   if b.split("/", 1)[0] != owner or "/" not in b]
        if foreign:
            return TODO, f"not filled: derived from {', '.join(foreign)}"
        return owner, SOURCE_SUPPLIER_HF
    authors = _prop_values(component, "aisbom:pypi:author")
    if authors:
        return authors[0], SOURCE_SUPPLIER_PYPI
    return TODO, ""


@dataclass
class _SupportCounts:
    supplied: int = 0
    suppliers: int = 0
    looked_up: int = 0


def _support_csv(doc: Dict[str, Any], answers: Optional["Answers"],
                 eol_answers: Optional[Mapping[str, Any]] = None,
                 ) -> Tuple[str, _SupportCounts]:
    """The support table, and how many components each source filled.

    A provider answer always keeps the data cell. An endoflife.date date fills
    ``end_of_support_date`` only when the provider gave none, and is always
    recorded in the ``end_of_support_lookup`` columns, so a value the lookup
    found is never lost and the date column stays one parseable date.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_SUPPORT_COLUMNS, lineterminator="\n")
    writer.writeheader()
    entries = answers.components if answers else []
    eol_answers = eol_answers or {}
    counts = _SupportCounts()
    for c in _components(doc):
        supplier, supplier_source = supplier_for(c)
        row = {
            "bom_ref": c.get("bom-ref") or "",
            "name": c.get("name") or "",
            "type": c.get("type") or "",
            "version": c.get("version") or "",
            "sha256": _sha256(c) or "",
            "license": ";".join(_licenses(c)),
            "support_level": TODO,
            "end_of_support_date": TODO,
            "support_source": "",
            "supplier": supplier,
            "supplier_source": supplier_source,
            "end_of_support_lookup": "",
            "end_of_support_lookup_source": "",
        }
        if supplier != TODO:
            counts.suppliers += 1
        # Keyed on the dependency's bom-ref, so only components the caller
        # looked up as exact pins can match (see `eol_targets`).
        lookup = None
        if c.get("type") != _ML_COMPONENT_TYPE and c.get("bom-ref"):
            lookup = eol_answers.get(c["bom-ref"])
        if lookup is not None:
            counts.looked_up += 1
            row["end_of_support_date"] = lookup.date
            row["end_of_support_lookup"] = lookup.date
            row["end_of_support_lookup_source"] = lookup.source
        matching = [e for e in entries if e.matches(c)]
        for column in COMPONENT_VALUE_KEYS:
            # First matching entry in file order that answers the column wins.
            value = next((e.values[column] for e in matching if column in e.values), None)
            if value is not None:
                row[column] = value
                row["support_source"] = SOURCE_PROVIDER
        if row["support_source"]:
            counts.supplied += 1
        writer.writerow(row)
    return buf.getvalue(), counts


def eol_targets(dependencies: Sequence[Dict[str, Any]]) -> List[Tuple[str, str, str]]:
    """``(bom_ref, name, version)`` for every exact pin among a scan's dependencies.

    Read from the scanner's dependency list, not the SBOM: the SBOM records
    `numpy>=2.2.0` as version 2.2.0 and drops whether it was pinned, and a
    lower bound would be matched to a release cycle the install may have left.
    """
    from .modelcard import dependency_bom_ref

    return [
        (dependency_bom_ref(index, dep), str(dep["name"]), str(dep["version"]))
        for index, dep in enumerate(dependencies)
        if dep.get("pinned") and dep.get("name") and dep.get("version")
    ]


def build_fda_pack(
    doc: Dict[str, Any],
    *,
    target: str,
    vex_statements: Sequence[Any],
    vex_files: Sequence[str],
    answers: Optional["Answers"] = None,
    eol_answers: Optional[Mapping[str, Any]] = None,
    eol_note: Optional[str] = None,
) -> Dict[str, str]:
    """Return ``{filename: content}`` for the FDA pack (SBOM and VEX excluded,
    since the CLI writes those with the same code `scan --vex` uses).

    ``eol_answers`` maps a dependency's ``bom-ref`` to an endoflife.date
    answer (``.date``, ``.source``); ``eol_note`` says why the lookup did not
    run, or what failed, for the README. These are the one pre-fill not read
    from ``sbom.json``: the lookup runs when the pack is built.
    """
    comps = _components(doc)
    support_csv, counts = _support_csv(doc, answers, eol_answers)
    supplied = counts.supplied
    statuses = [getattr(s, "status", None) for s in vex_statements]
    affected = statuses.count("affected")

    w = _Writer()
    _intro(w, "FDA §524B documentation pack", target, legend=False)
    w.para(
        "A premarket submission for a cyber device must include an SBOM "
        "(FD&C Act §524B(b)(3)). FDA's premarket cybersecurity guidance "
        "(2026-02-03, nonbinding) recommends a machine-readable SBOM with the "
        "NTIA minimum elements, the support status of each component, and an "
        "assessment of each known vulnerability. This pack holds the parts a "
        "scan of the model files can produce."
    )
    w.table(
        ["File", "What it is"],
        [
            [SBOM_FILE, f"CycloneDX 1.7 SBOM, {len(comps)} component(s)"],
            *[[name, "VEX for the SBOM's components"] for name in vex_files],
            [SUPPORT_FILE, "One row per component: supplier, support level and "
                           "end-of-support date, pre-filled where a source exists"],
        ],
    )
    w.heading(2, "Supplier and support data")
    lookup_line = (
        f"- **End-of-support dates:** {counts.looked_up} of {len(comps)} component(s) "
        f"carry the date endoflife.date publishes for the release cycle of their "
        f"pinned version (`end_of_support_lookup`, with the product and cycle in "
        f"`end_of_support_lookup_source`). It fills `end_of_support_date` only "
        f"where the answers file gave none. Packages endoflife.date does not "
        f"track, and model files, stay {TODO}. These dates were looked up when "
        f"this pack was built and are not in `{SBOM_FILE}`."
    )
    if eol_note:
        lookup_line += f" Lookup: {eol_note}."
    w.lines.extend([
        f"- **Supplier** (an NTIA minimum element): {counts.suppliers} of "
        f"{len(comps)} component(s) carry one under {MAPPING} (see "
        f"`supplier_source`): a model's Hugging Face repository owner when its "
        f"card names no base model from another namespace, a package's PyPI "
        f"author. Check each one: a repository that re-uploads another "
        f"organisation's model without naming it as the base model shows the "
        f"uploader. The rest are marked {TODO}.",
        lookup_line,
    ])
    w.heading(2, "Vulnerability assessment")
    w.para(
        "FDA's guidance asks for a risk assessment of each known vulnerability "
        "in the device's components; a VEX is one machine-readable way to "
        f"record it. The VEX files carry {len(statuses)} statement(s), "
        f"{affected} affected. Model-file findings are keyed on AIsbom finding "
        "classes; CVE statements cover exact `==` pins in requirements.txt, "
        "looked up in OSV unless the run was offline or used --no-osv."
    )
    w.heading(2, "What this pack cannot evidence")
    if supplied:
        support_line = (
            f"- **Support level, and end-of-support dates endoflife.date does not "
            f"cover:** {supplied} of {len(comps)} component(s) in `{SUPPORT_FILE}` "
            f"take them from the provider's answers file (`support_source` is "
            f"{SOURCE_PROVIDER}); the rest are marked {TODO}."
        )
    else:
        support_line = (
            f"- **Support level, and end-of-support dates endoflife.date does not "
            f"cover:** `{SUPPORT_FILE}` marks them {TODO}."
        )
    w.lines.extend([
        support_line,
        "- **A supplier the scan cannot attribute:** local model files with no "
        "Hugging Face match, fine-tunes of another organisation's model, and "
        "packages whose PyPI release names no author.",
        "- **Software outside the scanned target**, such as firmware, the "
        "operating system or application code.",
        "- **Vulnerabilities without a CVE feed entry**, and CVEs in unpinned "
        "dependencies.",
    ])
    _filling_todos(w, "each component's support level and end-of-support date")
    w.heading(2, "Sources")
    w.lines.append(f"- AIsbom guide to FDA §524B: {_GUIDE_FDA}")
    return {
        SUPPORT_FILE: support_csv,
        README_FILE: w.close(),
    }


# ---------------------------------------------------------------------------
# Provider answers file (--answers)
# ---------------------------------------------------------------------------

ANSWERS_FORMAT_VERSION = 1

COMPONENT_MATCH_KEYS = ("name", "version", "purl", "sha256", "bom_ref")
COMPONENT_VALUE_KEYS = ("support_level", "end_of_support_date")
_TOP_LEVEL_KEYS = ("version", "fields", "components")


class AnswersError(ValueError):
    """The answers file cannot be used. ``problems`` lists every reason."""

    def __init__(self, problems: Sequence[str]):
        self.problems = list(problems)
        super().__init__("\n".join(self.problems))


@dataclass
class ComponentAnswer:
    """Support data for every SBOM component matching all of ``match``."""

    index: int
    match: Dict[str, str]
    values: Dict[str, str]

    def matches(self, component: Dict[str, Any]) -> bool:
        for key, wanted in self.match.items():
            if key == "sha256":
                have = (_sha256(component) or "").lower()
                wanted = wanted.lower()
            else:
                have = str(component.get("bom-ref" if key == "bom_ref" else key) or "").strip()
            if have != wanted:
                return False
        return True

    def describe(self) -> str:
        return ", ".join(f"{k}={v}" for k, v in self.match.items())


@dataclass
class Answers:
    fields: Dict[str, str] = field(default_factory=dict)
    components: List[ComponentAnswer] = field(default_factory=list)


def _field_registry() -> List[_Field]:
    """Every answerable field, in document order, derived from the builders
    themselves so the ids, the docs and the template cannot drift apart."""
    facts = _collect({})
    out: List[_Field] = []
    for name, writer in ((ANNEX_XI_FILE, _annex_xi(facts, "", {})),
                         (ART53_FILE, _art53(facts, "", {}))):
        for f in writer.fields:
            f.doc = name
            out.append(f)
    return out


def field_ids() -> List[str]:
    """The stable id of every field an answers file can fill, in order."""
    return [f.fid for f in _field_registry()]


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate keys instead of keeping the last."""


def _construct_unique_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode,
                              deep: bool = False) -> Dict[Any, Any]:
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in seen
        except TypeError:  # unhashable key; construct_mapping reports it
            continue
        if duplicate:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark)
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


def _scalar(value: Any) -> Optional[str]:
    if isinstance(value, bool):  # before int: bool is an int subclass
        return "Yes" if value else "No"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, datetime.date):  # also covers datetime
        return value.isoformat()
    if isinstance(value, str):
        text = value.replace("\r\n", "\n").strip()
        return text or None
    raise TypeError(type(value).__name__)


def _normalise(value: Any) -> Optional[str]:
    """An answer as text, or None when it is left empty."""
    if value is None:
        return None
    if isinstance(value, list):
        parts = [p for p in (_scalar(v) for v in value) if p]
        return "; ".join(parts) or None
    return _scalar(value)


def _value_problem(where: str, value: Any) -> Optional[str]:
    try:
        _normalise(value)
    except TypeError:
        return (f"{where}: expected text, a number, a date, yes/no or a list of "
                f"those, got {type(value).__name__}")
    return None


def load_answers(text: str) -> Answers:
    """Parse and validate an answers file. Raises AnswersError listing every
    problem; nothing in the file is silently ignored."""
    try:
        data = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        raise AnswersError([f"not valid YAML: {exc}"]) from None
    if data is None:
        return Answers()
    if not isinstance(data, dict):
        raise AnswersError([
            "the file must be a YAML mapping with 'fields' and/or 'components' keys"
        ])

    problems: List[str] = []
    for key in data:
        if key not in _TOP_LEVEL_KEYS:
            problems.append(
                f"unknown top-level key '{key}' (expected: {', '.join(_TOP_LEVEL_KEYS)})")
    version = data.get("version", ANSWERS_FORMAT_VERSION)
    if version != ANSWERS_FORMAT_VERSION:
        problems.append(
            f"unsupported version {version!r}; this AIsbom reads version "
            f"{ANSWERS_FORMAT_VERSION}")

    answers = Answers()
    known = field_ids()
    raw_fields = data.get("fields")
    if raw_fields is not None and not isinstance(raw_fields, dict):
        problems.append("fields: must be a mapping of field id to answer")
        raw_fields = None
    for fid, value in (raw_fields or {}).items():
        fid = str(fid)
        if fid not in known:
            guess = difflib.get_close_matches(fid, known, n=1)
            hint = f"; did you mean '{guess[0]}'?" if guess else ""
            problems.append(f"fields: unknown field id '{fid}' (field ids: {DOCS_URL}){hint}")
            continue
        problem = _value_problem(f"fields.{fid}", value)
        if problem:
            problems.append(problem)
            continue
        text_value = _normalise(value)
        if text_value is not None:
            answers.fields[fid] = text_value

    raw_components = data.get("components")
    if raw_components is not None and not isinstance(raw_components, list):
        problems.append("components: must be a list of entries")
        raw_components = None
    for i, entry in enumerate(raw_components or []):
        where = f"components[{i}]"
        if not isinstance(entry, dict):
            problems.append(f"{where}: must be a mapping with match keys and values")
            continue
        match: Dict[str, str] = {}
        values: Dict[str, str] = {}
        bad = False
        for key, value in entry.items():
            key = str(key)
            if key not in COMPONENT_MATCH_KEYS + COMPONENT_VALUE_KEYS:
                problems.append(
                    f"{where}: unknown key '{key}' (match keys: "
                    f"{', '.join(COMPONENT_MATCH_KEYS)}; values: "
                    f"{', '.join(COMPONENT_VALUE_KEYS)})")
                bad = True
                continue
            problem = _value_problem(f"{where}.{key}", value)
            if problem:
                problems.append(problem)
                bad = True
                continue
            text_value = _normalise(value)
            if text_value is None:
                continue
            (match if key in COMPONENT_MATCH_KEYS else values)[key] = text_value
        if not match and not bad:
            problems.append(
                f"{where}: needs at least one match key ({', '.join(COMPONENT_MATCH_KEYS)})")
            continue
        if not bad:
            answers.components.append(ComponentAnswer(index=i, match=match, values=values))

    if problems:
        raise AnswersError(problems)
    return answers


def unmatched_component_answers(doc: Dict[str, Any], answers: Answers) -> List[str]:
    """Component entries that match nothing in this SBOM, described by their
    match keys. A warning, not an error: hashes and versions change between
    releases, and the file is meant to outlive any one of them."""
    comps = _components(doc)
    return [e.describe() for e in answers.components if not any(e.matches(c) for c in comps)]


def verdict_words_in(answers: Answers) -> List[Tuple[str, str]]:
    """(location, word) for every verdict word in the provider's own text."""
    texts = list(answers.fields.items())
    for e in answers.components:
        texts.extend((f"components[{e.index}].{k}", v) for k, v in e.values.items())
    hits = []
    for where, text in texts:
        for word in VERDICT_WORDS:
            if re.search(rf"\b{re.escape(word)}\b", text, flags=re.IGNORECASE):
                hits.append((where, word))
    return hits


def _yaml_str(value: Any) -> str:
    # A JSON string is a valid YAML double-quoted scalar, and quoting every
    # value keeps names like "a: b # c" intact.
    return json.dumps(str(value), ensure_ascii=False)


def answers_template(doc: Dict[str, Any]) -> str:
    """A starter answers file: every field id with its label as a comment,
    and one support entry per component this scan found."""
    lines = [
        "# AIsbom comply answers file",
        f"# Generated by AIsbom, template version {TEMPLATE_VERSION}.",
        "#",
        "# Fill in what you can answer and leave the rest empty. Each answer is",
        "# written into the pack as given and tagged (provider-supplied). A value",
        "# the scan read is kept beside your answer, never replaced.",
        "#",
        "# How to write answers:",
        "#   text                 annex_xi.1b.acceptable_use: See https://acme.example/aup",
        "#   date                 annex_xi.1c.release_date: 2025-07-01",
        "#   yes / no question    art53.2_1.used: yes",
        "#   several values       art53.1_3.modalities: [Text, Image]",
        "#   several lines        annex_xi.2b.training_methods: |",
        "#                          First paragraph.",
        "#",
        "#                          Second paragraph, indented the same.",
        "# Quote text that contains a colon followed by a space, or starts with",
        "# a special character such as # [ { * & ! | > ' \" % @",
        "#",
        f"# Field ids and examples: {DOCS_URL}",
        "#",
        "#   aisbom comply <target> --framework <eu-ai-act|fda> --answers <this file>",
        "",
        f"version: {ANSWERS_FORMAT_VERSION}",
        "",
        "fields:",
    ]
    doc_name = heading = None
    for f in _field_registry():
        if f.doc != doc_name:
            doc_name, heading = f.doc, None
            lines.extend(["", f"  # ===== {f.doc} ====="])
        if f.heading != heading:
            heading = f.heading
            lines.extend(["", f"  # {f.heading}"])
        comment = f.label
        if f.hint:
            comment += f" ({f.hint})"
        if f.scan:
            comment += " [the scan pre-fills this when it can read it]"
        lines.extend([f"  # {comment}", f"  {f.fid}:"])

    lines.extend([
        "",
        f"# ===== {SUPPORT_FILE} (--framework fda) =====",
        "# An entry fills a component's support level and end-of-support date when",
        f"# every match key it gives agrees ({', '.join(COMPONENT_MATCH_KEYS)}).",
        "# Drop `version` to keep an answer across upgrades. Components no entry",
        "# matches stay TODO.",
    ])
    entries = []
    seen = set()
    for c in _components(doc):
        name = c.get("name")
        if not name:
            continue
        key = (str(name), str(c.get("version") or ""))
        if key in seen:
            continue
        seen.add(key)
        entry = [f"  - name: {_yaml_str(name)}"]
        if c.get("version"):
            entry.append(f"    version: {_yaml_str(c['version'])}")
        sha = _sha256(c)
        if sha:
            entry.append(f"    # sha256: {sha}")
        entry.extend(["    support_level:", "    end_of_support_date:"])
        entries.extend(entry)
    if entries:
        lines.append("components:")
        lines.extend(entries)
    else:
        lines.append("components: []")
    return "\n".join(lines) + "\n"
