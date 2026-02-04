# Sandboxed Execution (Defense in Depth)

AIsbom provides a "Defense in Depth" strategy for handling untrusted AI models. While our Static Analysis (Linter) helps you identify potentially dangerous code, **Runtime Sandboxing** is the only way to safely execute or load suspicious artifacts (e.g., for conversion or debugging).

## The Strategy

1.  **Linter (Static):** Use `aisbom scan --lint` to inspect the file structure without loading it.
2.  **Sandbox (Runtime):** If you MUST load the model, do it inside an isolated ephemeral environment.

## Runtime Sandbox (Recommended)

We recommend using **[amazing-sandbox](https://github.com/ashishb/amazing-sandbox)**, wrapped via `uvx` for ephemeral execution. This ensures that even if a model contains RCE (Remote Code Execution), it cannot persist or access your host filesystem.

### Usage with Wrapper Script

We provide a helper script to simplify the `uvx` command:

```bash
# Run any command inside the sandbox
./scripts/asb-wrapper.sh <command>
```

### Example: Safely Loading a Suspicious Model

We include `scripts/safe_loader.py` as a template. It loads a model with `weights_only=False` (unsafe on host, but contained in sandbox) to verify if it works or to extract data.

**How to use:**

```bash
# usage: ./scripts/asb-wrapper.sh python scripts/safe_loader.py <model_path>
./scripts/asb-wrapper.sh python scripts/safe_loader.py my_legacy_model.pt
```

If the model is malicious, the malware executes **inside** the ephemeral container, protecting your laptop.

## Why Sandbox?

The AIsbom Linter warns you about `REDUCE` opcodes and custom class imports. However, some legacy models *require* these unsafe features. Sandboxing allows you to support these legacy workflows without exposing your infrastructure to full compromise.

> [!WARNING]
> Sandboxing reduces risk but does not eliminate it. Sophisticated malware might attempt to break out of the container or abuse allowed resources (e.g., GPU drivers).
