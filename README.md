# AIsbom: The Supply Chain for Artificial Intelligence
[![PyPI version](https://badge.fury.io/py/aisbom-cli.svg)](https://badge.fury.io/py/aisbom-cli)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Compliance](https://img.shields.io/badge/standard-CycloneDX-green)

**AIsbom** is a specialized security scanner for Machine Learning artifacts. Unlike generic SBOM tools that only parse `requirements.txt`, AIsbom performs **Deep Binary Introspection** on model files (`.pt`, `.pkl`, `.safetensors`) to detect risks hidden inside the serialized weights.

---

## ⚡ Quick Start

### 1. Installation
Install directly from PyPI. No cloning required.

```bash
pip install aisbom-cli
```

__Note: The package name is aisbom-cli, but the command you run is aisbom.__


### 2. Run a Scan
Point it at any directory containing your ML project. It will find requirements files AND binary model artifacts.

```bash
aisbom scan ./my-project-folder
```

### 3. Output
You will see a risk assessment table in your terminal:

🧠 AI Model Artifacts Found                           

| Filename | Framework | Risk Level |
| :--- | :--- | :--- |
| `bert_finetune.pt` | PyTorch | 🔴 **CRITICAL** (RCE Detected: posix.system) |
| `safe_model.safetensors` | SafeTensors | 🟢 **LOW** (Binary Safe) |

A compliant `sbom.json` will be generated in the current directory.

---

## 🚀 Why AIsbom?
AI models are not just text files; they are executable programs.
*   **PyTorch (`.pt`)** files are Zip archives containing Pickle bytecode.
*   **Pickle** files can execute arbitrary code (RCE) instantly upon loading.
*   Legacy scanners look at requirements.txt manifest files but ignore binary model weights. **We look inside.** We decompile the bytecode headers without loading the heavy weights into RAM.

## ✨ Key Features
*   **🧠 Deep Introspection:** Peeks inside PyTorch Zip structures without loading weights into RAM.
*   **💣 Pickle Bomb Detector:** Disassembles bytecode to detect `os.system`, `subprocess`, and `eval` calls before they run.
*   **🛡️ Compliance Ready:** Generates standard [CycloneDX v1.6](https://cyclonedx.org/) JSON for enterprise integration (Dependency-Track, ServiceNow).
*   **⚡ Blazing Fast:** Scans GB-sized models in milliseconds by reading headers only.

---

## 🧪 How to Verify (The "Trust Factor")

Security tools require trust. To maintain a safe repository, we do not distribute malicious binaries. However, you can verify our detection engine works by generating a test "Pickle Bomb" yourself.

**Prerequisites:** You will need to clone the repository to access the generator scripts.

**1. Clone the repo:**
```bash
git clone https://github.com/Lab700xOrg/aisbom.git
cd aisbom
```
**2. Generate the "Malware":**
We provide a transparent Python script that uses standard libraries to create a file simulating a system call.
```bash
python demo_data/generate_malware.py
```
__Result: A file named malicious_model.pt is created.__

**3. Scan it:**
```bash
# You can use your globally installed aisbom, or poetry run aisbom
aisbom scan demo_data
```
__You will see the scanner flag malicious_model.pt as CRITICAL.__

---

## 🔒 Security Logic
AIsbom uses a static analysis engine to disassemble Python Pickle opcodes. It looks for specific `GLOBAL` and `STACK_GLOBAL` instructions that reference dangerous modules:

* os / posix (System calls)
* subprocess (Shell execution)
* builtins.eval / exec (Dynamic code execution)
* socket (Network reverse shells)

---