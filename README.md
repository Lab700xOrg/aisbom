# AIsbom: The Supply Chain for Artificial Intelligence
[![PyPI version](https://badge.fury.io/py/aisbom-cli.svg)](https://badge.fury.io/py/aisbom-cli)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Compliance](https://img.shields.io/badge/standard-CycloneDX-green)

**AIsbom** is a specialized security and compliance scanner for Machine Learning artifacts. 

Unlike generic SBOM tools that only parse `requirements.txt`, AIsbom performs **Deep Binary Introspection** on model files (`.pt`, `.pkl`, `.safetensors`) to detect malware risks and legal license violations hidden inside the serialized weights.

---

## ⚡ Quick Start

### 1. Installation
Install directly from PyPI. No cloning required.

```bash
pip install aisbom-cli
```

_Note: The package name is aisbom-cli, but the command you run is aisbom._

### 2. Run a Scan
Point it at any directory containing your ML project. It will find requirements files AND binary model artifacts.

```bash
aisbom scan ./my-project-folder
```

### 3. Output
You will see a combined Security & Legal risk assessment in your terminal:

🧠 AI Model Artifacts Found                           

| Filename | Framework | Security Risk | Legal Risk |
| :--- | :--- | :--- | :--- |
| `bert_finetune.pt` | PyTorch | 🔴 **CRITICAL** (RCE Detected: posix.system) | UNKNOWN |
| `safe_model.safetensors` | SafeTensors | 🟢 **LOW** (Binary Safe) | UNKNOWN |
| `restricted_model.safetensors` | SafeTensors | 🟢 **LOW** | LEGAL RISK (cc-by-nc-4.0)  |

A compliant `sbom.json` (CycloneDX v1.6) including SHA256 hashes and license data will be generated in your current directory.

---

### 4. Visualize the Report (New!)
Don't like reading JSON? You can visualize your security posture using our **offline** viewer.

1.  Run the scan.
2.  Go to [aisbom.io/viewer.html](https://aisbom.io/viewer.html).
3.  Drag and drop your `sbom.json`.
4.  Get an instant dashboard of risks, license issues, and compliance stats.

*Note: The viewer is client-side only. Your SBOM data never leaves your browser.*

---

## 🚀 Why AIsbom?
AI models are not just text files; they are executable programs and IP assets.
*   **The Security Risk:** PyTorch (`.pt`) files are Zip archives containing Pickle bytecode. A malicious model can execute arbitrary code (RCE) instantly when loaded.
*   **The Legal Risk:** A developer might download a "Non-Commercial" model (CC-BY-NC) and deploy it to production. Since the license is hidden inside the binary header, standard tools miss it.
*   **Pickle** files can execute arbitrary code (RCE) instantly upon loading.
*   **The Solution:** Legacy scanners look at requirements.txt manifest files but ignore binary model weights. **We look inside.** We decompile the bytecode headers without loading the heavy weights into RAM.

## ✨ Key Features
*   **🧠 Deep Introspection:** Peeks inside PyTorch Zip structures and Safetensors headers without loading weights into RAM.
*   **💣 Pickle Bomb Detector:** Disassembles bytecode to detect `os.system`, `subprocess`, and `eval` calls before they run.
*   **⚖️ License Radar:** Extracts metadata from .safetensors to flag restrictive licenses (e.g., CC-BY-NC, AGPL) that threaten commercial use.
*   **🛡️ Compliance Ready:** Generates standard [CycloneDX v1.6](https://cyclonedx.org/) JSON for enterprise integration (Dependency-Track, ServiceNow).
*   **⚡ Blazing Fast:** Scans GB-sized models in milliseconds by reading headers only and using streaming hash calculation.

---

## 🧪 How to Verify (The "Trust Factor")

Security tools require trust. To maintain a safe repository, we do not distribute malicious binaries. However, AIsbom includes a built-in generator so you can create safe "test dummies" to verify the scanner works.

**1. Install:**
```bash
pip install aisbom-cli
```
**2. Generate Test Artifacts:**
Run this command to create a fake "Pickle Bomb" and a "Restricted License" model in your current folder.
```bash
# Generate a mock Pickle Bomb (Security Risk) and a mock Non-Commercial Model (Legal Risk)
aisbom generate-test-artifacts
```
__Result: Files named mock_malware.pt and mock_restricted.safetensors are created.__

**3. Scan it:**
```bash
# You can use your globally installed aisbom, or poetry run aisbom
aisbom scan .
```
_You will see the scanner flag mock_malware.pt as **CRITICAL** and mock_restricted.safetensors as a **LEGAL RISK**._

---

## 🔒 Security Logic
AIsbom uses a static analysis engine to disassemble Python Pickle opcodes. It looks for specific `GLOBAL` and `STACK_GLOBAL` instructions that reference dangerous modules:

* os / posix (System calls)
* subprocess (Shell execution)
* builtins.eval / exec (Dynamic code execution)
* socket (Network reverse shells)

---

## 🤖 GitHub Actions Integration
Add AIsbom to your CI/CD pipeline to block unsafe models before they merge.

```Yaml
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