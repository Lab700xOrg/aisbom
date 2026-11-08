# `aisbom comply` field mapping

Every field `aisbom comply` writes, and where its value comes from. A field
with no scan source is always written as `TODO (provider)`. A field with a
scan source falls back to `TODO (provider)` when the scan found nothing for
it. Template version: `2026-11-08` (`aisbom/comply.py`, `TEMPLATE_VERSION`).

Sources, as tagged in the generated documents:

- **Hugging Face model card**: the `modelCard` block of a model component in
  `sbom.json`. It is present for `hf://` scans and for local files whose hash
  matched a file in a Hugging Face repo.
- **model file header**: the same `modelCard` fields when no repo was matched.
  Today only a GGUF header supplies one (its architecture).
- **AIsbom scan**: properties the scanner wrote from the file itself, such as
  `aisbom:format`, or a licence it read from file metadata.

Wording follows the [aisbom.io compliance guides](https://aisbom.io/compliance/).
Lines marked *AIsbom's mapping* are interpretations, not quotations of the
text.

## EU AI Act: Annex XI technical documentation

Regulation (EU) 2024/1689, Article 53(1)(a) and Annex XI.

| Annex XI | Field | Value from |
|---|---|---|
| 1(a) | Task declared in the model card | `modelParameters.task` |
| 1(a) | Intended tasks | TODO |
| 1(a) | Type and nature of AI systems it can be integrated into | TODO |
| 1(b) | Applicable acceptable use policies | TODO |
| 1(c) | Date of release | TODO |
| 1(c) | Hugging Face repository the scanned files come from | `aisbom:hf:repo_id` |
| 1(c) | Methods of distribution | TODO |
| 1(d) | Architecture family | `modelParameters.architectureFamily` |
| 1(d) | Model architecture | `modelParameters.modelArchitecture` |
| 1(d) | Number of parameters | TODO (never derived from tensor shapes) |
| 1(e) | Input / output modality and format | TODO |
| 1(f) | Licence | component `licenses[]`, then `aisbom:hf:license` |
| 2(a) | Library declared in the model card | `aisbom:hf:library_name` |
| 2(a) | Model file formats in this release (*AIsbom's mapping*) | `aisbom:format` |
| 2(a) | Instructions of use, infrastructure and tools | TODO |
| 2(b) | Training methodologies, design choices, optimisation target | TODO |
| 2(c) | Training datasets declared in the model card | `modelParameters.datasets[].name` |
| 2(c) | Provenance and curation, data points, selection, bias measures | TODO |
| 2(d) | Computational resources, training time | TODO |
| 2(e) | Known or estimated energy consumption | TODO |
| Section 2, items 1–3 | Evaluation, adversarial testing, system architecture (systemic-risk models only) | TODO |
| Appendix A (*AIsbom's mapping*) | Scanned files: format, SHA-256, AIsbom risk, security findings | component `hashes`, `aisbom:format`, `aisbom:risk`, `aisbom:pickle:opcode`, `aisbom:unreadable` |
| Appendix B | Software dependencies: package, version, licence (Article 53(1)(b), Annex XII) | `library` components |

## EU AI Act: public summary of training content

Article 53(1)(d), following the sections of the Commission's *Template for the
Public Summary of Training Content for General-Purpose AI models* (24 July
2025). Every field the template asks for is present, in its order.

| Template section | Pre-filled field | Value from |
|---|---|---|
| 1.2 | Versioned model name(s) | `aisbom:hf:repo_id` `@` `aisbom:hf:revision` |
| 1.2 | Model card link | `https://huggingface.co/` + `aisbom:hf:repo_id` |
| 2.1 | Datasets declared in the model card, for the provider to confirm | `modelParameters.datasets[].name` |

Everything else, including the version and date of the summary, all of 1.1,
model dependencies and market placement date (1.2), all of 1.3, every Yes/No
question, and sections 2.2 to 3.3, is TODO.

## FDA §524B

FD&C Act §524B(b)(3) and FDA's premarket cybersecurity guidance (2026-02-03,
nonbinding). The guidance does not name VEX; the pack offers VEX as one
machine-readable way to record the per-vulnerability assessment it asks for.

| File | Content |
|---|---|
| `sbom.json` | The CycloneDX 1.7 SBOM `aisbom scan` writes for the same target |
| `sbom.openvex.json`, `sbom.vex.cdx.json` | The VEX `aisbom scan --vex` writes: AIsbom finding classes for model files, plus OSV CVE statements for exact `==` pins unless `--no-osv` or `--offline` |
| `component-support.csv` | One row per component: `bom_ref`, `name`, `type`, `version`, `sha256`, `license` from the SBOM; `support_level` and `end_of_support_date` always TODO |
| `README.md` | Contents, VEX statement counts, and what the pack cannot evidence: support and end-of-support data, supplier name, software outside the target, vulnerabilities with no CVE entry |

## Guards

- `tests/test_comply.py` fails if any generated file contains verdict
  language such as "compliant", "certified" or "guarantee", the same list the
  aisbom.io guides are held to.
- Every generated Markdown file states its template version and ends with the
  same "not legal advice" disclaimer.
- A scan in which any target could not be read writes no pack and exits `1`.
