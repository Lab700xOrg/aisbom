# 🔒 Air-Gapped / Offline Auditing Guide

This guide details the secure protocol for using **AIsbom** in air-gapped, offline, or high-compliance environments (e.g., Industrial OT, Defense, Critical Infrastructure).

> **Security Note:** This method uses a **Standalone Binary**. It requires zero external dependencies (no Python, no pip, no internet access on the target machine), eliminating the risk of "Supply Chain Injection" attacks during installation.

---

## 1. The "Sneaker-Net" Protocol

To audit an air-gapped machine ("Zone B") without connecting it to the internet, follow this strictly unidirectional workflow:

1.  **Zone A (Online):** Download the binary and verify its cryptographic signature (Secure Workstation).
2.  **Transfer:** Copy the verified binary to a secure transfer medium (e.g., Encrypted USB, Diode).
3.  **Zone B (Air-Gapped):** Execute the scan on the sensitive target.
4.  **Egress:** (Optional) Bring the text-based `sbom.json` report back to Zone A for analysis.

---

## 2. Step-by-Step Instructions

### Step 1: Download & Verify (Zone A)

On your internet-connected workstation, navigate to the [Latest Release](https://github.com/Lab700xOrg/aisbom/releases/latest) and download the binary matching your **Target** architecture.

| Target OS | File Name |
| :--- | :--- |
| **Linux (x86_64)** | `aisbom-linux-amd64` |
| **macOS (Intel)** | `aisbom-macos-amd64` |
| **macOS (Apple Silicon)** | `aisbom-macos-arm64` |

**Critical: Verify the Chain of Custody**
Before transferring, verify the SHA256 checksum matches the one published in the Release Notes.

```bash
# MacOS / Linux
shasum -a 256 aisbom-linux-amd64

# Output must match the published hash EXACTLY.
# Example: 92ed9666a9ae62aeae74e78f689e048ba294f05d3164f97f74806b2546249a1e
```

### Step 2: Execution (Zone B)

Mount your transfer medium on the air-gapped target. No installation is required; the binary runs in place.

#### Linux
```bash
# 1. Make executable (if permissions were lost during transfer)
chmod +x ./aisbom-linux-amd64

# 2. Run Scan
./aisbom-linux-amd64 scan /path/to/model_directory
```

#### macOS (Gatekeeper Fix)
> **Admonition:** macOS marks downloaded binaries with a "Quarantine" attribute. On an offline machine, you cannot "Right Click -> Open" to bypass this. You **must** strip the attribute manually.

```bash
# 1. Make executable
chmod +x ./aisbom-macos-arm64

# 2. Fix "Unidentified Developer" / Gatekeeper block
xattr -d com.apple.quarantine ./aisbom-macos-arm64

# 3. Run Scan
./aisbom-macos-arm64 scan .
```

### Step 3: Analyzing Results

The tool produces two outputs:

1.  **Risk Table (Standard Out):** Immediate, human-readable feedback on the terminal.
    *   🔴 **Critical:** Pickle bombs, malicious opcodes.
    *   🟡 **Warning:** High-risk imports.
2.  **SBOM Report (`sbom.json`):** A CycloneDX JSON file generated in the working directory.
    *   This file is **static plain text**. It is safe to egress back to "Zone A" for ingestion into your central vulnerability dashboard.

---

## 3. Why this matters

By using the standalone binary, you avoid:
1.  **PyPI Typosquatting:** You never run `pip install`.
2.  **Dependency Confusion:** No internal/external repo confusion.
3.  **Runtime Modification:** The binary is immutable.

This ensures that the security tool itself does not introduce new attack vectors into your critical environment.
