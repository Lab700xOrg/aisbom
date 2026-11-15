# `aisbom comply` field mapping

Every field `aisbom comply` writes, and where its value comes from. A field
with no scan source is always written as `TODO (provider)`. A field with a
scan source falls back to `TODO (provider)` when the scan found nothing for
it, unless the provider's [answers file](#answers-file---answers) fills it.
Template version: `2026-11-15.2` (`aisbom/comply.py`, `TEMPLATE_VERSION`).

Sources, as tagged in the generated documents:

- **Hugging Face model card**: the `modelCard` block of a model component in
  `sbom.json`. It is present for `hf://` scans and for local files whose hash
  matched a file in a Hugging Face repo.
- **Hugging Face repository metadata**: repository facts the Hugging Face API
  returns beside the card (`aisbom:hf:created_at`).
- **Hugging Face safetensors metadata**: the parameter total Hugging Face
  computes across every safetensors file in the repository
  (`aisbom:hf:parameters_total`).
- **model file header**: the same `modelCard` fields when no repo was matched.
  Today only a GGUF header supplies one (its architecture).
- **AIsbom scan**: properties the scanner wrote from the file itself, such as
  `aisbom:format`, or a licence it read from file metadata.
- **AIsbom scan of safetensors headers**: a parameter count summed from the
  tensor shapes of a complete set of safetensors files
  (`aisbom:safetensors:parameters`, see [Number of parameters](#number-of-parameters)).
- **endoflife.date**: end-of-support dates looked up when an FDA pack is
  built (see [FDA §524B](#fda-524b)). The only source not stored in `sbom.json`.

Wording follows the [aisbom.io compliance guides](https://aisbom.io/compliance/).
Lines marked *AIsbom's mapping* are interpretations, not quotations of the
text. Rows labelled "declared in the model card" carry what the card states,
which is not necessarily the answer to the field beside it; that field stays
TODO for the provider.

## EU AI Act: Annex XI technical documentation

Regulation (EU) 2024/1689, Article 53(1)(a) and Annex XI.

| Annex XI | Field | Value from |
|---|---|---|
| 1(a) | Task declared in the model card | `modelParameters.task` |
| 1(a) | Intended tasks | TODO |
| 1(a) | Type and nature of AI systems it can be integrated into | TODO |
| 1(b) | Applicable acceptable use policies | TODO |
| 1(c) | Date of release | TODO |
| 1(c) | First published on Hugging Face (not necessarily the release date) | `aisbom:hf:created_at`, omitted for the `2022-03-02T23:29:04.000Z` stamp every repository older than Hugging Face's 2022 migration carries |
| 1(c) | Hugging Face repository the scanned files come from | `aisbom:hf:repo_id` |
| 1(c) | Methods of distribution | TODO |
| 1(d) | Architecture family | `modelParameters.architectureFamily` |
| 1(d) | Model architecture | `modelParameters.modelArchitecture` |
| 1(d) | Number of parameters | `aisbom:hf:parameters_total`, and/or the sum of `aisbom:safetensors:parameters` over a complete set ([rule](#number-of-parameters)) |
| 1(e) | Input / output modality and format (*AIsbom's mapping*) | `modelParameters.task` through the [task table](#modality-from-the-task) |
| 1(f) | Licence | component `licenses[]`, then `aisbom:hf:license` |
| 2(a) | Library declared in the model card | `aisbom:hf:library_name` |
| 2(a) | Model file formats in this release (*AIsbom's mapping*) | `aisbom:format` |
| 2(a) | Instructions of use, infrastructure and tools | TODO |
| 2(b) | Training methodologies, design choices, optimisation target | TODO |
| 2(c) | Training datasets declared in the model card | `modelParameters.datasets[].name` |
| 2(c) | Provenance and curation, data points, selection, bias measures | TODO |
| 2(d) | Computational resources, training time | TODO |
| 2(d) | Training hardware declared in the model card | `aisbom:hf:co2_eq_emissions:hardware_used` |
| 2(e) | Known or estimated energy consumption | TODO |
| 2(e) | CO2 emissions declared in the model card (emissions are not energy) | `aisbom:hf:co2_eq_emissions` (grams) with its `source`, `training_type` and `geographical_location` |
| Section 2, item 1 | Evaluation results declared in the model card | `quantitativeAnalysis.performanceMetrics` (the card's `model-index`, at most 50 per model; `aisbom:hf:model_index_truncated` records the declared count when cut) |
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
| 1.2 | Model dependencies | `aisbom:hf:base_model` (the card's `base_model`) |
| 1.3 | Languages declared in the model card (not necessarily the training data's) | `aisbom:hf:language` |
| 2.1 | Datasets declared in the model card, for the provider to confirm | `modelParameters.datasets[].name` |

Everything else, including the version and date of the summary, all of 1.1,
market placement date (1.2), the rest of 1.3 (including the training data's
linguistic characteristics), every Yes/No question, and sections 2.2 to 3.3,
is TODO.

### Number of parameters

Two sources, shown side by side when both exist:

- **Hugging Face safetensors metadata**: the total Hugging Face computes
  server-side across every safetensors file in the repository. Independent of
  how much of the repository the scan read.
- **AIsbom scan of safetensors headers**: each safetensors file's header lists
  every tensor's shape; `aisbom:safetensors:parameters` is the sum of their
  products, recorded only when every entry has a well-formed shape. A count is
  used only for a complete set: a single unsharded `.safetensors` file, or
  every shard `<stem>-0000k-of-0000N.safetensors` for k = 1..N **in the same
  directory**, each with a readable count. The scanner decides this, since it
  sees directories, and writes `aisbom:safetensors:set_parameters` and
  `set_shards` on each shard of a complete set; `comply` never re-derives it
  from component names. A missing, duplicated or unreadable shard, or shards
  split across directories, leaves the set out.

Other weight formats (GGUF, pickle, ONNX) are never counted.

### Modality from the task

*AIsbom's mapping* from the Hugging Face task to Annex XI 1(e). A task not
listed leaves both fields TODO. The input format (for example the tokenizer)
is always the provider's to add.

| Task | Input | Output |
|---|---|---|
| `fill-mask`, `text-generation`, `text2text-generation`, `question-answering`, `summarization`, `translation` | text | text |
| `text-classification`, `zero-shot-classification` | text | text (class labels) |
| `token-classification` | text | text (per-token labels) |
| `sentence-similarity` | text | similarity scores |
| `feature-extraction` | text | numeric vectors (embeddings) |
| `table-question-answering` | tables and text | text |
| `image-classification` | image | text (class labels) |
| `object-detection` | image | bounding boxes with class labels |
| `image-segmentation` | image | segmentation masks |
| `image-to-text` | image | text |
| `image-to-image` | image | image |
| `text-to-image` | text | image |
| `zero-shot-image-classification` | image and text | text (class labels) |
| `visual-question-answering` | image and text | text |
| `automatic-speech-recognition` | audio | text |
| `audio-classification` | audio | text (class labels) |
| `text-to-speech`, `text-to-audio` | text | audio |

## FDA §524B

FD&C Act §524B(b)(3) and FDA's premarket cybersecurity guidance (2026-02-03,
nonbinding). The guidance does not name VEX; the pack offers VEX as one
machine-readable way to record the per-vulnerability assessment it asks for.

| File | Content |
|---|---|
| `sbom.json` | The CycloneDX 1.7 SBOM `aisbom scan` writes for the same target |
| `sbom.openvex.json`, `sbom.vex.cdx.json` | The VEX `aisbom scan --vex` writes: AIsbom finding classes for model files, plus OSV CVE statements for exact `==` pins unless `--no-osv` or `--offline` |
| `component-support.csv` | One row per component, columns in this order: `bom_ref`, `name`, `type`, `version`, `sha256`, `license` from the SBOM; `support_level` and `end_of_support_date` from the answers file's `components` entries, otherwise (for the date) the endoflife.date lookup, otherwise TODO; `support_source` is `provider-supplied` when the answers file filled either; `supplier` and `supplier_source` under the [supplier rule](#supplier); `end_of_support_lookup` and `end_of_support_lookup_source`, what endoflife.date returned, kept even when the answers file overrides the date |
| `README.md` | Contents, VEX statement counts, how many components carry a supplier and an endoflife.date date (and why a lookup did not run), and what the pack cannot evidence: support level and dates nothing covered, suppliers the scan cannot attribute, software outside the target, vulnerabilities with no CVE entry |

### Supplier

*AIsbom's mapping*, written to `supplier` with its rule in `supplier_source`:

- **Model:** the Hugging Face repository owner (`aisbom:hf:author`), only
  when the card names no base model, or every `base_model` sits in the
  owner's own namespace. A fine-tune or re-upload of another organisation's
  model stays TODO, and `supplier_source` says what it derives from. Known
  gap: a re-upload whose card names no base model shows the uploader.
- **Package:** the author its PyPI release declares (`aisbom:pypi:author`):
  `author`, else `maintainer`, else the display name in `author_email` or
  `maintainer_email`. An email address alone is not used.
- Local model files with no Hugging Face match are TODO.

### End of support

For every exact `==` pin in requirements.txt, `comply --framework fda` asks
[endoflife.date](https://endoflife.date) (`GET /api/v1/products/<name>`,
package names only) for the product of the same name. A product is used only
when it lists the package's own PyPI purl (`pkg:pypi/<name>`). The pinned
version is matched to the release cycle that equals it or prefixes it at a
dot (`1.26.4` → `1.26`, never `1.2`), and that cycle's end-of-life date is
written. Untracked packages, versions outside every cycle, cycles with no
announced date, unpinned requirements (a `>=` lower bound is not what is
installed), and model files stay TODO. The lookup is skipped under
`--offline` / `AISBOM_OFFLINE=1` and `--no-eol-lookup`, and a failure never
stops the pack; the README says when it did not run.

## Answers file (`--answers`)

Most TODO fields are facts no scan can read. The provider writes them once in
a YAML file and passes it on every run:

```bash
aisbom comply ./model --framework eu-ai-act --write-answers-template comply.yaml
# fill in comply.yaml, then:
aisbom comply ./model --framework eu-ai-act --answers comply.yaml
```

`--write-answers-template` writes a starter file next to the pack, with every
field id, its label and hint as comments, and one `components` entry per
component the scan found. Its header shows how to write each kind of answer.
It never overwrites an existing file. Every pack's `README.md` and the CLI's
closing message point to this workflow.

Quote an answer that contains a colon followed by a space, or that starts
with a special character such as `#`, `[`, `{`, `*`, `&`, `!`, `|`, `>`, `'`,
`"`, `%` or `@`; otherwise YAML reads it as something other than text. The
answers file is read locally and never sent anywhere.

```yaml
version: 1
fields:
  annex_xi.1c.release_date: 2025-07-01
  art53.1_1.provider: Acme AI, ops@acme.example
  art53.2_1.used: yes
  annex_xi.2b.training_methods: |
    Pre-training on public web text.

    Supervised fine-tuning on licensed dialogue data.
components:
  - name: torch
    support_level: Supported by Acme for the device's service life
    end_of_support_date: 2030-12-31
```

How answers are applied:

- An answer fills its field as written, tagged _(provider-supplied)_. Dates
  are written as ISO dates, `yes`/`no` as Yes/No, and a list as its items
  joined with `; `. An empty value leaves the field TODO.
- A value the scan read is never replaced. When the scan and the answers file
  both give a value, the document shows both, scan first, and the pack's
  `README.md` lists those field ids so the provider can check them.
- The `README.md` counts scan-read, provider-supplied and TODO fields
  separately.
- A `components` entry fills `support_level` and `end_of_support_date` for
  every SBOM component that agrees with all of its match keys: `name`,
  `version`, `purl`, `sha256`, `bom_ref`. Leave out `version` to keep an
  answer across upgrades. When several entries match one component, the first
  in the file that answers a column wins. An entry that matches nothing is
  reported as a warning, not an error, because hashes and versions change
  between releases.
- The file is checked before the scan starts. Invalid YAML, a duplicate key,
  an unknown top-level key or field id, a value that is not text, a number,
  a date, yes/no or a list of those, or a component entry with no match key
  stops the run with exit `1` and lists every problem.
- Provider text is written as given. If it contains a verdict word from the
  guard list below, the CLI prints a warning naming the field, and still
  writes it.

### Field ids

Every field in both EU AI Act documents has a stable id. "Scan can pre-fill"
marks fields where a provider answer may appear beside a scan-read value.

`annex-xi-technical-documentation.md`

| Field id | Section | Field | Scan can pre-fill |
|---|---|---|---|
| `annex_xi.1a.task_declared` | Point 1(a) | Task declared in the model card | yes |
| `annex_xi.1a.intended_tasks` | Point 1(a) | Intended tasks |  |
| `annex_xi.1a.integration_systems` | Point 1(a) | Type and nature of AI systems it can be integrated into |  |
| `annex_xi.1b.acceptable_use` | Point 1(b) | Applicable acceptable use policies |  |
| `annex_xi.1c.release_date` | Point 1(c) | Date of release |  |
| `annex_xi.1c.hf_first_published` | Point 1(c) | First published on Hugging Face | yes |
| `annex_xi.1c.hf_repository` | Point 1(c) | Hugging Face repository the scanned files come from | yes |
| `annex_xi.1c.distribution_methods` | Point 1(c) | Methods of distribution |  |
| `annex_xi.1d.architecture_family` | Point 1(d) | Architecture family | yes |
| `annex_xi.1d.model_architecture` | Point 1(d) | Model architecture | yes |
| `annex_xi.1d.parameter_count` | Point 1(d) | Number of parameters | yes |
| `annex_xi.1e.input_modality` | Point 1(e) | Input modality and format | yes |
| `annex_xi.1e.output_modality` | Point 1(e) | Output modality and format | yes |
| `annex_xi.1f.licence` | Point 1(f) | Licence | yes |
| `annex_xi.2a.library` | Point 2(a) | Library declared in the model card | yes |
| `annex_xi.2a.file_formats` | Point 2(a) | Model file formats in this release | yes |
| `annex_xi.2a.integration_instructions` | Point 2(a) | Instructions of use, infrastructure and tools needed to integrate the model |  |
| `annex_xi.2b.training_methods` | Point 2(b) | Training methodologies and techniques |  |
| `annex_xi.2b.design_choices` | Point 2(b) | Key design choices, with rationale and assumptions |  |
| `annex_xi.2b.optimisation_target` | Point 2(b) | What the model is designed to optimise for, and the relevance of its parameters |  |
| `annex_xi.2c.declared_datasets` | Point 2(c) | Training datasets declared in the model card | yes |
| `annex_xi.2c.data_provenance` | Point 2(c) | Type and provenance of the data, and curation methodologies |  |
| `annex_xi.2c.data_points` | Point 2(c) | Number of data points, scope and main characteristics |  |
| `annex_xi.2c.data_selection` | Point 2(c) | How the data was obtained and selected |  |
| `annex_xi.2c.bias_measures` | Point 2(c) | Measures to detect unsuitable data sources and identifiable biases |  |
| `annex_xi.2d.compute` | Point 2(d) | Computational resources |  |
| `annex_xi.2d.hardware_declared` | Point 2(d) | Training hardware declared in the model card | yes |
| `annex_xi.2d.training_time` | Point 2(d) | Training time and other relevant training details |  |
| `annex_xi.2e.energy` | Point 2(e) | Known or estimated energy consumption |  |
| `annex_xi.2e.co2_declared` | Point 2(e) | CO2 emissions declared in the model card | yes |
| `annex_xi.s2_1.evaluation` | Section 2, item 1 | Evaluation strategies, criteria, metrics and results |  |
| `annex_xi.s2_1.evaluation_declared` | Section 2, item 1 | Evaluation results declared in the model card | yes |
| `annex_xi.s2_2.adversarial_testing` | Section 2, item 2 | Adversarial testing measures (for example red teaming), alignment and fine-tuning |  |
| `annex_xi.s2_3.system_architecture` | Section 2, item 3 | How the software components build on or feed into each other |  |

`art53-training-content-summary.md`

| Field id | Section | Field | Scan can pre-fill |
|---|---|---|---|
| `art53.summary.version` | Header | Version of the summary |  |
| `art53.summary.last_update` | Header | Last update |  |
| `art53.1_1.provider` | 1.1 | Provider name and contact details |  |
| `art53.1_1.authorised_representative` | 1.1 | Authorised representative name and contact details |  |
| `art53.1_2.versioned_names` | 1.2 | Versioned model name(s) | yes |
| `art53.1_2.model_card_link` | 1.2 | Model card link | yes |
| `art53.1_2.model_dependencies` | 1.2 | Model dependencies | yes |
| `art53.1_2.market_placement_date` | 1.2 | Date of placement of the model on the Union market |  |
| `art53.1_3.modalities` | 1.3 | Modalities present in the training data |  |
| `art53.1_3.size_per_modality` | 1.3 | Training data size per modality |  |
| `art53.1_3.content_types` | 1.3 | Types of content per modality |  |
| `art53.1_3.latest_acquisition_date` | 1.3 | Latest date of data acquisition or collection |  |
| `art53.1_3.languages_declared` | 1.3 | Languages declared in the model card | yes |
| `art53.1_3.linguistic_characteristics` | 1.3 | Linguistic characteristics of the overall training data |  |
| `art53.1_3.other_characteristics` | 1.3 | Other relevant characteristics of the overall training data |  |
| `art53.2_1.used` | 2.1 | Have you used publicly available datasets to train the model? |  |
| `art53.2_1.declared_datasets` | 2.1 | Datasets declared in the model card | yes |
| `art53.2_1.large_datasets` | 2.1 | List of large publicly available datasets |  |
| `art53.2_1.other_datasets` | 2.1 | General description of other publicly available datasets |  |
| `art53.2_2_1.licensed` | 2.2.1 | Transactional commercial licensing agreements concluded? |  |
| `art53.2_2_1.modalities` | 2.2.1 | Modalities covered |  |
| `art53.2_2_2.obtained` | 2.2.2 | Private datasets obtained from other third parties? |  |
| `art53.2_2_2.modalities` | 2.2.2 | Modalities covered |  |
| `art53.2_2_2.known_datasets` | 2.2.2 | List of those datasets, if publicly known |  |
| `art53.2_2_2.other_description` | 2.2.2 | General description of those not publicly known |  |
| `art53.2_3.crawlers_used` | 2.3 | Were crawlers used by the provider or on its behalf? |  |
| `art53.2_3.crawler_names` | 2.3 | Crawler name(s) or identifier(s) |  |
| `art53.2_3.crawler_purposes` | 2.3 | Purposes of the crawler(s) |  |
| `art53.2_3.crawler_behaviour` | 2.3 | General description of crawler behaviour |  |
| `art53.2_3.collection_period` | 2.3 | Period of data collection |  |
| `art53.2_3.content_description` | 2.3 | Description of the type of content and online sources crawled |  |
| `art53.2_3.modalities` | 2.3 | Modalities covered |  |
| `art53.2_3.top_domains` | 2.3 | Most relevant domain names crawled |  |
| `art53.2_4.model_interactions_used` | 2.4 | Was data from user interactions with the model used to train it? |  |
| `art53.2_4.other_services_used` | 2.4 | Was data from user interactions with your other services or products used? |  |
| `art53.2_4.services_description` | 2.4 | Description of the services or products the user data came from |  |
| `art53.2_4.modalities` | 2.4 | Modalities covered |  |
| `art53.2_5.synthetic_used` | 2.5 | Was synthetic AI-generated data created by you or on your behalf to train the model? |  |
| `art53.2_5.modalities` | 2.5 | Modalities of the synthetic data |  |
| `art53.2_5.gpai_models_used` | 2.5 | General-purpose AI model(s) on the market used to generate it |  |
| `art53.2_5.other_models_used` | 2.5 | Other AI models used to generate it, including your own |  |
| `art53.2_6.other_sources_used` | 2.6 | Were data sources other than those in sections 2.1 to 2.5 used? |  |
| `art53.2_6.description` | 2.6 | Narrative description of those sources and data |  |
| `art53.3_1.code_of_practice_signatory` | 3.1 | Signatory to the Code of Practice for general-purpose AI models? |  |
| `art53.3_1.rights_reservation_measures` | 3.1 | Measures taken to respect reservations of rights before and during data collection |  |
| `art53.3_2.illegal_content_measures` | 3.2 | General description of measures taken |  |
| `art53.3_3.other_information` | 3.3 | Other relevant information about data processing |  |

## Guards

- `tests/test_comply.py` fails if any generated file contains verdict
  language such as "compliant", "certified" or "guarantee", the same list the
  aisbom.io guides are held to (`VERDICT_WORDS` in `aisbom/comply.py`). The
  guard covers AIsbom's own wording; provider answers get a warning instead.
- Every generated Markdown file states its template version and ends with the
  same "not legal advice" disclaimer.
- A scan in which any target could not be read writes no pack and exits `1`.
