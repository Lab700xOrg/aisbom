# Sandboxed Execution (Defense in Depth)

AIsbom provides a "Defense in Depth" strategy for handling untrusted AI models. While our Static Analysis (Linter) helps you identify potentially dangerous code, **Runtime Sandboxing** is the only way to safely execute or load suspicious artifacts (e.g., for conversion or debugging).

## The Strategy

1.  **Linter (Static):** Use `aisbom scan --lint` to inspect the file structure without loading it.
2.  **Sandbox (Runtime):** If you MUST load the model, do it inside an isolated ephemeral environment.

## 📦 Runtime Sandbox (Recommended)

We recommend using **[amazing-sandbox](https://github.com/amazing-open-source/amazing-sandbox)**, wrapped via `uvx` for ephemeral execution. This ensures that even if a model contains RCE (Remote Code Execution), it cannot persist or access your host filesystem.

### Usage with `uvx`

You can use `uv` (the fast Python package manager) to spin up a temporary sandbox environment.

```bash
# 1. Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Run your model loader inside the sandbox
uvx --from amazing-sandbox asb run -- python load_model.py
```

### Example: Safely Loading a Suspicious Model

Create a loader script that attempts to load the model using `weights_only=True` but falls back to safe unpickling.

```python
# load_model.py
import torch
import sys

model_path = "suspicious_model.pt"

try:
    print(f"Loading {model_path} in SANDBOX...")
    # Attempt load. If it contains malware, it executes here.
    # But because we are in 'asb', network and filesystem are restricted.
    model = torch.load(model_path, weights_only=False) 
    print("Model loaded successfully (but be careful!)")
except Exception as e:
    print(f"Load failed: {e}")
```

Then execute it:

```bash
uvx --from amazing-sandbox asb run -- python load_model.py
```

## Why Sandbox?

The AIsbom Linter warns you about `REDUCE` opcodes and custom class imports. However, some legacy models *require* these unsafe features. Sandboxing allows you to support these legacy workflows without exposing your infrastructure to full compromise.

> [!WARNING]
> Sandboxing reduces risk but does not eliminate it. Sophisticated malware might attempt to break out of the container or abuse allowed resources (e.g., GPU drivers).
