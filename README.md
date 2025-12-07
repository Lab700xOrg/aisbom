# AIsbom: The Supply Chain for Artificial Intelligence

![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Compliance](https://img.shields.io/badge/standard-CycloneDX-green)

**AIsbom** is a specialized security scanner for Machine Learning artifacts. Unlike generic SBOM tools that only parse `requirements.txt`, AIsbom performs **Deep Binary Introspection** on model files (`.pt`, `.pkl`, `.safetensors`) to detect risks hidden inside the serialized weights.

---

## 🚀 The Problem
AI models are not just text files; they are executable programs.
*   **PyTorch (`.pt`)** files are Zip archives containing Pickle bytecode.
*   **Pickle** files can execute arbitrary code (RCE) instantly upon loading.
*   Legacy scanners see a binary blob and ignore it. **We look inside.**

## ✨ Features
*   **🧠 Deep Introspection:** Peeks inside PyTorch Zip structures without loading weights into RAM.
*   **💣 Pickle Bomb Detector:** Disassembles bytecode to detect `os.system`, `subprocess`, and `eval` calls before they run.
*   **🛡️ Compliance Ready:** Generates standard [CycloneDX v1.6](https://cyclonedx.org/) JSON for enterprise integration (Dependency-Track, ServiceNow).
*   **⚡ Blazing Fast:** Scans GB-sized models in milliseconds by reading headers only.

---

## 📦 Installation

```bash
git clone https://github.com/your-org/aisbom.git
cd aisbom
pip install -e .
```

--- 

## 🛠️ Usage

1. Scan a directory
Pass any directory containing your ML project. AIsbom will find requirements files AND model artifacts.

```bash
aisbom scan ./my-ml-project
```

2. Output
You will see a risk assessment table in your terminal:

🧠 AI Model Artifacts Found                           
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Filename           ┃ Framework ┃ Risk Level                            ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ bert_finetune.pt   │ PyTorch   │ CRITICAL (RCE Detected: posix.system) │
│ safe_model.safetensors │ SafeTensors | LOW (Binary Safe)               │
└────────────────────┴───────────┴───────────────────────────────────────┘
A compliant sbom.json will be generated in the current directory.

---

## 🔒 Security Logic
AIsbom uses a static analysis engine to disassemble Python Pickle opcodes. It looks for specific GLOBAL and STACK_GLOBAL instructions that reference dangerous modules:

* os / posix (System calls)
* subprocess (Shell execution)
* builtins.eval / exec (Dynamic code execution)
* socket (Network reverse shells)