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
value in it is worse than one with a visible gap, so nothing is inferred —
not even values that look derivable, such as a parameter count from tensor
shapes, which a sharded or quantised release would get wrong.

The builders read the serialized CycloneDX document rather than the scanner's
raw results. That is the file the pack bundles as ``sbom.json``, so every
pre-filled value can be traced back to a field a reader can inspect.

Wording follows the aisbom.io compliance guides: the documents describe what
the files contain and never pass a verdict on the provider. The test suite
fails on the same verdict words the platform bans.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# Bump on every change to the wording or field mapping of a generated
# document, so a pack in someone's submission folder can be traced to the
# exact template that produced it.
TEMPLATE_VERSION = "2026-11-08"

TODO = "TODO (provider)"

SOURCE_HF = "Hugging Face model card"
SOURCE_HEADER = "model file header"
SOURCE_SCAN = "AIsbom scan"

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


def _collect(doc: Dict[str, Any]) -> _Facts:
    comps = _components(doc)
    models = [c for c in comps if c.get("type") == _ML_COMPONENT_TYPE]
    deps = [c for c in comps if c.get("type") != _ML_COMPONENT_TYPE]

    repos, names, tasks, families, archs = [], [], [], [], []
    datasets, licenses, libraries, formats = [], [], [], []
    for m in models:
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
class _Writer:
    lines: List[str] = field(default_factory=list)
    filled: int = 0
    todo: int = 0

    def heading(self, level: int, text: str) -> None:
        if self.lines and self.lines[-1] != "":
            self.lines.append("")
        self.lines.extend([f"{'#' * level} {text}", ""])

    def para(self, text: str) -> None:
        if self.lines and self.lines[-1] != "":
            self.lines.append("")
        self.lines.extend([text, ""])

    def fact(self, label: str, values: Sequence[Tuple[str, str]], hint: str = "") -> None:
        """A field pre-filled from the scan, or a TODO when the scan had nothing."""
        if not values:
            self.ask(label, hint)
            return
        self.filled += 1
        rendered = ", ".join(f"`{_esc(v)}` _({src})_" for v, src in values)
        line = f"- **{label}:** {rendered}"
        if hint:
            line += f" — {hint}"
        self.lines.append(line)

    def ask(self, label: str, hint: str = "") -> None:
        """A field only the provider can answer."""
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


def _intro(w: _Writer, title: str, target: str, *, legend: bool = True) -> None:
    w.lines.extend([f"# {title}", ""])
    w.para(
        f"Generated by AIsbom from a scan of `{_esc(target)}`. "
        f"Template version {TEMPLATE_VERSION}."
    )
    if legend:
        w.para(
        f"Values tagged with a source in italics were read by the scan. Fields "
        f"marked **{TODO}** need information a file scan cannot read; "
        f"AIsbom leaves them blank rather than guess."
    )


# ---------------------------------------------------------------------------
# EU AI Act — Annex XI
# ---------------------------------------------------------------------------

def _findings(component: Dict[str, Any]) -> str:
    notes: List[str] = []
    opcodes = _prop_values(component, "aisbom:pickle:opcode")
    if opcodes:
        notes.append("dangerous imports: " + ", ".join(opcodes))
    if _prop_values(component, "aisbom:unreadable"):
        notes.append("not readable by any parser; not inspected")
    if _prop_values(component, "aisbom:pickle:scan_incomplete"):
        notes.append("pickle scan incomplete")
    return "; ".join(notes) or "none"


def _annex_xi(facts: _Facts, target: str) -> _Writer:
    w = _Writer()
    _intro(w, "Technical documentation — EU AI Act Annex XI (skeleton)", target)
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
    w.fact("Task declared in the model card", facts.tasks,
           "confirm it matches the tasks you intend the model to perform")
    w.ask("Intended tasks", "what the model is intended to do")
    w.ask("Type and nature of AI systems it can be integrated into")

    w.heading(3, "Point 1(b) — Acceptable use policies")
    w.ask("Applicable acceptable use policies")

    w.heading(3, "Point 1(c) — Date of release and methods of distribution")
    w.ask("Date of release")
    w.fact("Hugging Face repository the scanned files come from", facts.repos)
    w.ask("Methods of distribution")

    w.heading(3, "Point 1(d) — Architecture and number of parameters")
    w.fact("Architecture family", facts.families)
    w.fact("Model architecture", facts.architectures)
    w.ask("Number of parameters", "AIsbom does not derive this from tensor shapes")

    w.heading(3, "Point 1(e) — Modality and format of inputs and outputs")
    w.ask("Input modality and format")
    w.ask("Output modality and format")

    w.heading(3, "Point 1(f) — Licence")
    w.fact("Licence", facts.licenses)

    w.para("**Point 2 — Detailed description of the elements in point 1 and of the development process.**")

    w.heading(3, "Point 2(a) — Technical means needed for integration")
    w.fact("Library declared in the model card", facts.libraries)
    w.fact("Model file formats in this release", facts.formats)
    w.ask("Instructions of use, infrastructure and tools needed to integrate the model")

    w.heading(3, "Point 2(b) — Design specifications and training process")
    w.ask("Training methodologies and techniques")
    w.ask("Key design choices, with rationale and assumptions")
    w.ask("What the model is designed to optimise for, and the relevance of its parameters")

    w.heading(3, "Point 2(c) — Data used for training, testing and validation")
    w.fact("Training datasets declared in the model card", facts.datasets,
           "confirm each one, and list any the card omits")
    w.ask("Type and provenance of the data, and curation methodologies")
    w.ask("Number of data points, scope and main characteristics")
    w.ask("How the data was obtained and selected")
    w.ask("Measures to detect unsuitable data sources and identifiable biases")

    w.heading(3, "Point 2(d) — Computational resources used to train the model")
    w.ask("Computational resources", "for example the number of floating point operations")
    w.ask("Training time and other relevant training details")

    w.heading(3, "Point 2(e) — Energy consumption")
    w.ask("Known or estimated energy consumption",
          "may be estimated from the computational resources in point 2(d)")

    w.heading(2, "Section 2 — Additional information for models with systemic risk")
    w.para(
        "Complete this section only for a general-purpose AI model with systemic "
        "risk (Article 51); otherwise mark it not applicable."
    )
    w.heading(3, "Item 1 — Evaluation strategies and results")
    w.ask("Evaluation strategies, criteria, metrics and results")
    w.heading(3, "Item 2 — Adversarial testing and model adaptations")
    w.ask("Adversarial testing measures (for example red teaming), alignment and fine-tuning")
    w.heading(3, "Item 3 — System architecture")
    w.ask("How the software components build on or feed into each other",
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


def _art53(facts: _Facts, target: str) -> _Writer:
    w = _Writer()
    _intro(w, "Public summary of training content — EU AI Act Article 53(1)(d) (draft)", target)
    w.para(
        "Follows the sections of the European Commission's *Template for the "
        "Public Summary of Training Content for General-Purpose AI models* "
        f"(published 24 July 2025, {_COMMISSION_TEMPLATE}). The Commission's "
        "template is the form providers use; this draft follows its numbering "
        "so answers can be transferred section by section."
    )
    w.ask("Version of the summary", "with links to previous versions where applicable")
    w.ask("Last update")

    w.heading(2, "1 General information")
    w.heading(3, "1.1 Provider identification")
    w.ask("Provider name and contact details")
    w.ask("Authorised representative name and contact details",
          "only if the provider is established outside the Union (Article 54)")

    w.heading(3, "1.2 Model identification")
    w.fact("Versioned model name(s)", facts.versioned_names,
           "replace with the versioned name you place on the market if it differs")
    w.fact("Model card link",
           [(f"https://huggingface.co/{repo}", src) for repo, src in facts.repos])
    w.ask("Model dependencies",
          "if the model modifies or fine-tunes another general-purpose AI model, "
          "name it and link its summary")
    w.ask("Date of placement of the model on the Union market")

    w.heading(3, "1.3 Modalities, overall training data size and other characteristics")
    w.ask("Modalities present in the training data", _MODALITY)
    w.ask("Training data size per modality", "the template's size ranges, or another unit")
    w.ask("Types of content per modality")
    w.ask("Latest date of data acquisition or collection", "MM/YYYY, and whether training continues on new data")
    w.ask("Linguistic characteristics of the overall training data")
    w.ask("Other relevant characteristics of the overall training data")

    w.heading(2, "2 List of data sources")
    w.heading(3, "2.1 Publicly available datasets")
    w.ask("Have you used publicly available datasets to train the model?", _YES_NO)
    w.fact("Datasets declared in the model card", facts.datasets,
           "confirm each was used, add an access link, and check whether it is "
           "'large' (over 3% of the public-dataset data for a modality)")
    w.ask("List of large publicly available datasets", "name and access link for each")
    w.ask("General description of other publicly available datasets")

    w.heading(3, "2.2 Private non-publicly available datasets obtained from third parties")
    w.heading(4, "2.2.1 Datasets commercially licensed by rightsholders or their representatives")
    w.ask("Transactional commercial licensing agreements concluded?", _YES_NO)
    w.ask("Modalities covered", _MODALITY)
    w.heading(4, "2.2.2 Private datasets obtained from other third parties")
    w.ask("Private datasets obtained from other third parties?", _YES_NO)
    w.ask("Modalities covered", _MODALITY)
    w.ask("List of those datasets, if publicly known")
    w.ask("General description of those not publicly known")

    w.heading(3, "2.3 Data crawled and scraped from online sources")
    w.ask("Were crawlers used by the provider or on its behalf?", _YES_NO)
    w.ask("Crawler name(s) or identifier(s)")
    w.ask("Purposes of the crawler(s)")
    w.ask("General description of crawler behaviour", "for example robots.txt, paywalls, captchas")
    w.ask("Period of data collection", "from MM/YYYY to MM/YYYY")
    w.ask("Description of the type of content and online sources crawled")
    w.ask("Modalities covered", _MODALITY)
    w.ask("Most relevant domain names crawled",
          "top 10% by content size; SMEs top 5% or 1,000, whichever is lower")

    w.heading(3, "2.4 User data")
    w.ask("Was data from user interactions with the model used to train it?", _YES_NO)
    w.ask("Was data from user interactions with your other services or products used?", _YES_NO)
    w.ask("Description of the services or products the user data came from")
    w.ask("Modalities covered", _MODALITY)

    w.heading(3, "2.5 Synthetic data")
    w.ask("Was synthetic AI-generated data created by you or on your behalf to train the model?", _YES_NO)
    w.ask("Modalities of the synthetic data", _MODALITY)
    w.ask("General-purpose AI model(s) on the market used to generate it")
    w.ask("Other AI models used to generate it, including your own")

    w.heading(3, "2.6 Other sources of data")
    w.ask("Were data sources other than those in sections 2.1 to 2.5 used?", _YES_NO)
    w.ask("Narrative description of those sources and data")

    w.heading(2, "3 Data processing aspects")
    w.heading(3, "3.1 Respect of reservation of rights from the text and data mining exception or limitation")
    w.ask("Signatory to the Code of Practice for general-purpose AI models?", _YES_NO)
    w.ask("Measures taken to respect reservations of rights before and during data collection")

    w.heading(3, "3.2 Removal of illegal content")
    w.ask("General description of measures taken")

    w.heading(3, "3.3 Other information (optional)")
    w.ask("Other relevant information about data processing", "optional")
    return w


def _eu_readme(target: str, annex: _Writer, art53: _Writer) -> str:
    w = _Writer()
    _intro(w, "EU AI Act documentation pack", target)
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
    w.para(f"{filled} field(s) pre-filled from the scan, {todo} left as TODO for the provider.")
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


def build_eu_ai_act_pack(doc: Dict[str, Any], *, target: str) -> Dict[str, str]:
    """Return ``{filename: content}`` for the EU AI Act pack (SBOM excluded)."""
    facts = _collect(doc)
    annex = _annex_xi(facts, target)
    art53 = _art53(facts, target)
    readme = _eu_readme(target, annex, art53)
    return {
        ANNEX_XI_FILE: annex.close(),
        ART53_FILE: art53.close(),
        README_FILE: readme,
    }


# ---------------------------------------------------------------------------
# FDA §524B
# ---------------------------------------------------------------------------

_SUPPORT_COLUMNS = [
    "bom_ref", "name", "type", "version", "sha256", "license",
    "support_level", "end_of_support_date",
]


def _support_csv(doc: Dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_SUPPORT_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for c in _components(doc):
        writer.writerow({
            "bom_ref": c.get("bom-ref") or "",
            "name": c.get("name") or "",
            "type": c.get("type") or "",
            "version": c.get("version") or "",
            "sha256": _sha256(c) or "",
            "license": ";".join(_licenses(c)),
            "support_level": TODO,
            "end_of_support_date": TODO,
        })
    return buf.getvalue()


def build_fda_pack(
    doc: Dict[str, Any],
    *,
    target: str,
    vex_statements: Sequence[Any],
    vex_files: Sequence[str],
) -> Dict[str, str]:
    """Return ``{filename: content}`` for the FDA pack (SBOM and VEX excluded,
    since the CLI writes those with the same code `scan --vex` uses)."""
    comps = _components(doc)
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
            [SUPPORT_FILE, "One row per component, with support level and end-of-support date to fill in"],
        ],
    )
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
    w.lines.extend([
        f"- **Support level and end-of-support date** for each component: "
        f"`{SUPPORT_FILE}` marks both {TODO}.",
        "- **Supplier name** (an NTIA minimum element): the scan does not record "
        "a supplier for model files.",
        "- **Software outside the scanned target**, such as firmware, the "
        "operating system or application code.",
        "- **Vulnerabilities without a CVE feed entry**, and CVEs in unpinned "
        "dependencies.",
    ])
    w.heading(2, "Sources")
    w.lines.append(f"- AIsbom guide to FDA §524B: {_GUIDE_FDA}")
    return {
        SUPPORT_FILE: _support_csv(doc),
        README_FILE: w.close(),
    }
