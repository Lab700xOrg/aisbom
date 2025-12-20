# AIsbom: The Supply Chain for Artificial Intelligence

[![PyPI version](https://img.shields.io/pypi/v/aisbom-cli.svg)](https://pypi.org/project/aisbom-cli/)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Compliance](https://img.shields.io/badge/standard-CycloneDX-green)

**AIsbom** is a specialized security and compliance scanner for Machine Learning artifacts.

Unlike generic SBOM tools that only parse `requirements.txt`, AIsbom performs **Deep Binary Introspection** on model files (`.pt`, `.pkl`, `.safetensors`, `.gguf`) to detect malware risks and legal license violations hidden inside the serialized weights.

![AIsbom Demo](assets/aisbom_demo.gif)

---

## Quick Start

### 1. Installation
Install directly from PyPI. No cloning required.

```bash
pip install aisbom-cli
```
*Note: The package name is `aisbom-cli`, but the command you run is `aisbom`.*

### 2. Run a Local Scan
Point it at any directory containing your ML project. It scans recursively for requirements files AND binary model artifacts.

```bash
aisbom scan ./my-project-folder
```

### 3. The Output
You will see a combined Security & Legal risk assessment in your terminal:

```text
                           🧠 AI Model Artifacts Found                           
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Filename            ┃ Framework   ┃ Security Risk        ┃ Legal Risk                  ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ bert_finetune.pt    │ PyTorch     │ CRITICAL (RCE Found) │ UNKNOWN                     │
│ safe_model.st       │ SafeTensors │ LOW                  │ UNKNOWN                     │
│ restricted_model.st │ SafeTensors │ LOW                  │ LEGAL RISK (cc-by-nc-4.0)   │
│ llama-3-quant.gguf  │ GGUF        │ LOW                  │ LEGAL RISK (cc-by-nc-sa)    │
└─────────────────────┴─────────────┴──────────────────────┴─────────────────────────────┘
```

A compliant `sbom.json` (CycloneDX v1.6) including SHA256 hashes and license data will be generated in your current directory.

---

## Advanced Usage

### Remote Scanning (Hugging Face)
Scan models directly on Hugging Face **without downloading** terabytes of weights. We use HTTP Range requests to inspect headers over the wire.

```bash
aisbom scan hf://google-bert/bert-base-uncased
```
*   **Speed:** Scans in seconds, not minutes.
*   **Storage:** Zero disk usage.
*   **Security:** Verify "SafeTensors" compliance before you even `git clone`.

### Strict Mode (Allowlisting)
For high-security environments, switch from "Blocklisting" (looking for malware) to "Allowlisting" (blocking everything unknown).

```bash
aisbom scan . --strict
```
*   Only permits standard ML modules (`torch`, `numpy`, `collections`, etc.).
*   Flags *any* unknown global import as `CRITICAL`.

### Markdown Reporting (CI/CD)
Generate a GitHub-flavored Markdown report suitable for Pull Request comments.

```bash
aisbom scan . --format markdown --output report.md
```

---

## CI/CD Integration

Add AIsbom to your GitHub Actions pipeline.
**Behavior:** The scanner returns `exit code 1` if Critical risks are found, automatically blocking the build/merge.

```yaml
name: AI Security Scan
on: [pull_request]

jobs:
  aisbom-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Scan AI Models
        uses: Lab700xOrg/aisbom@v0
        with:
          directory: '.'
```

---

## Visualize the Report
Don't like reading JSON? You can visualize your security posture using our **offline** viewer.

1.  Run the scan to generate `sbom.json`.
2.  Go to [aisbom.io/viewer.html](https://aisbom.io/viewer.html).
3.  Drag and drop your JSON file.
4.  Get an instant dashboard of risks, license issues, and compliance stats.

*Note: The viewer is client-side only. Your SBOM data never leaves your browser.*

---

## Why AIsbom?

AI models are not just text files; they are executable programs and IP assets.

*   **The Security Risk:** PyTorch (`.pt`) files are Zip archives containing Pickle bytecode. A malicious model can execute arbitrary code (RCE) instantly when loaded.
*   **The Legal Risk:** A developer might download a "Non-Commercial" model (CC-BY-NC) and deploy it to production. Since the license is hidden inside the binary header, standard tools miss it.
*   **The Solution:** **We look inside.** We decompile bytecode and parse internal metadata headers without loading the heavy weights into RAM.

---

## How to Verify (The "Trust Factor")

Security tools require trust. **We do not distribute malicious binaries.**

However, AIsbom includes a built-in generator so you can create safe "mock artifacts" to verify the scanner works.

**1. Install:**
```bash
pip install aisbom-cli
```

**2. Generate Test Artifacts:**
Run this command to create a mock "Pickle Bomb" and a "Restricted License" model in your current folder.
```bash
aisbom generate-test-artifacts
```
*Result: Files named `mock_malware.pt`, `mock_restricted.safetensors`, and `mock_restricted.gguf` are created.*

**3. Scan them:**
```bash
aisbom scan .
```
*Result: You will see `mock_malware.pt` flagged as **CRITICAL** and (`mock_restricted.safetensors`, `mock_restricted.gguf`) as **LEGAL RISK**.*

---

## Security Logic Details
AIsbom uses a static analysis engine to disassemble Python Pickle opcodes. It looks for specific `GLOBAL` and `STACK_GLOBAL` instructions that reference dangerous modules:
*   `os` / `posix` (System calls)
*   `subprocess` (Shell execution)
*   `builtins.eval` / `exec` (Dynamic code execution)
*   `socket` (Network reverse shells)