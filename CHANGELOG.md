# Changelog

## Unreleased

### New formats scanned

- **Keras models (`.keras`, `.h5`, `.hdf5`) are now scanned.** A `Lambda` layer stores an arbitrary Python callable in the model config as a base64-encoded marshalled code object, and `load_model` runs it — so the config is an execution vector in the same way a pickle stream is. `Lambda` layers and embedded code objects are flagged CRITICAL. The payload is identified from its header bytes and **never unmarshalled**, and a truncated or corrupted container is still scanned rather than skipped. Both containers Keras writes are handled: the `.keras` zip and legacy HDF5. No HDF5 library is added to the install.
- **ONNX models (`.onnx`) are now scanned.** The protobuf is walked directly — no ONNX runtime is imported and the graph is never executed. Alongside producer, opset, IR version and operator inventory, two signals are surfaced: operators from a non-standard domain (which need a custom native op library at load time), and external-data paths that point outside the model directory, which turn `load_model` into an arbitrary-file read. Subgraphs carried by `If`, `Loop` and `Scan` are walked too.
- **GGUF chat templates are now checked.** The embedded Jinja `chat_template` is extracted into the SBOM component and analysed statically for sandbox-escape constructs. The template is **never rendered** — rendering it is the vulnerability.

### Pickle detection

- **Concatenated pickle streams are all scanned.** A legacy `torch.save` file hides its object behind several header pickles, so stopping at the first `STOP` meant never reaching the payload. There is a work limit on the walk, and a file that reaches it now reports `MEDIUM (Pickle Scan Incomplete)` rather than passing as clean — an unfinished scan is never reported as a clean one.
- **Non-standard containers are flagged.** Packing a model with 7z (or rar, xz…) instead of the ZIP PyTorch expects previously meant the archive was never opened. It is now reported as `CRITICAL (Non-Standard Container: …)`. The container is named, not unpacked — unpacking would put a native 7z dependency into every install and every standalone binary.
- **Broken and truncated pickle streams are scanned rather than skipped.** The pickle VM executes sequentially, so a payload at the front of the stream runs before a corrupt tail is ever reached. Damaging a file is no longer a way to hide one.
- **Files are disassembled before their type is decided.** A printable protocol-0 pickle could previously pass as a text config file and be reported safe.
- **A ZIP member that cannot be read is no longer a clean bill** — it reports `MEDIUM (Unreadable Pickle Member)`, because a loader that does not verify integrity the way AIsbom does would still run it.
- **Indirect-execution gadgets are now detected in both scan modes** — `bdb.Bdb.run`, the asyncio gadget chain, and the import-mechanism primitives (`sys.modules`, `importlib`, `imp`, `runpy`, `pkgutil`, `builtins.__import__`). Strict mode now judges a global by its *resolved* module and attribute, so a submodule no longer inherits an allowlisted parent's trust.
- Hugging Face scans (`hf://…`) now list the Keras and ONNX extensions, so a repo containing a backdoored `.keras`, `.h5` or `.onnx` model is no longer resolved to zero artifacts.

### New command

- **`aisbom bypass-scorecard`** scans a corpus of publicly-documented scanner-evasion techniques — each reproduced as an inert, synthesized artifact — and reports what AIsbom catches in each scan mode. Nothing in the corpus is ever executed. `--check` is a release gate that fails if any case scores below its committed floor, and it now runs in CI on every push. Current state: **8 of 11 evasion cases caught**, up from 5 of 11.

## 1.2.1 — 2026-08-08

- SPDX export (`--format spdx`) now reports each model's real filename instead of labelling every artifact `unknown-model`, and its real format (`pickle` / `safetensors` / `gguf`) instead of `unknown`.
- SPDX packages now carry the SHA256 checksum of the scanned file. Remotely-scanned artifacts, whose bytes are never fully read, omit the field rather than asserting a placeholder.
- SPDX identifiers are now derived from file content instead of a process memory address, so scanning unchanged inputs twice produces identical documents and SPDX SBOMs can be diffed meaningfully in CI.
- SPDX documents now report the running CLI version in `creators` (previously hardcoded to `aisbom-cli-0.1.0`).
- Fixed `--format spdx` crashing on a `requirements.txt` that repeats a pin or uses a wildcard version (e.g. `torch>=2.0.*`), and on a scan that finds no models and no requirements. All three produced an invalid document and an unhandled traceback.
- CycloneDX output is byte-for-byte unchanged.

## 1.2.0 — 2026-06-11

- The hosted dashboard at <https://app.aisbom.io> is now generally available (previously private early access). The GitHub Action's optional `token` input posts each scan's SBOM to your inventory dashboard — get a per-repo token at <https://app.aisbom.io/connect>. See the README's "Hosted dashboard (optional)" and "Data flow & privacy" sections for exactly what is sent (and how to keep the Action purely local: just leave `token` unset).
- `action.yml`: the `platform-url` input now shows its default (`https://app.aisbom.io`) instead of resolving it internally; behavior is unchanged.

## 1.1.0 — 2026-06-05

- Scan private and gated Hugging Face models by setting `HF_TOKEN` / `HUGGING_FACE_HUB_TOKEN`; the token is sent only to `huggingface.co` and is never logged or included in telemetry.
- Remote fetch failures (auth, network, not found) now print a clear, status-aware message with no traceback and exit non-zero, instead of silently reporting zero artifacts.
- `cli_error` telemetry now includes an `http_status` bucket and a `token_present` boolean (never the token value).
- Add optional `token` / `platform-url` / `fail-on-platform-error` inputs for posting SBOM to an external dashboard (private early access).
- Action upload now includes the scanned branch/tag (`GITHUB_REF_NAME`) so the dashboard can attribute results to the right ref.
