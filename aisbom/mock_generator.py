import os
import pickle
import zipfile
import io
import json
import struct
from pathlib import Path

# --- SIMULATION LOGIC ---
class MockExploitPayload(object):
    """
    A harmless class used to simulate an RCE (Remote Code Execution) attack signature.
    It uses os.system but prints a warning message instead of doing damage.
    """
    def __reduce__(self):
        # The payload command
        return (os.system, ("echo ' [TEST] AIsbom RCE simulation executed successfully. '",))

def create_mock_malware_file(target_dir: Path):
    """Generates a PyTorch file containing a Mock Pickle Bomb."""
    # We use protocol 2 or higher to ensure STACK_GLOBAL opcodes are generated
    payload_bytes = pickle.dumps(MockExploitPayload(), protocol=2)
    
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('archive/data.pkl', payload_bytes)
        z.writestr('archive/version', '3')
        
    output_path = target_dir / "mock_malware.pt" 
    with open(output_path, "wb") as f:
        f.write(zip_buffer.getvalue())
    
    return output_path

# --- LICENSE RISK LOGIC ---
def create_mock_restricted_file(target_dir: Path):
    """Generates a Safetensors file with Non-Commercial metadata."""
    header = {
        "weight_tensor": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
        "__metadata__": {
            "format": "pt",
            "license": "cc-by-nc-4.0 (Non-Commercial)",
            "author": "Research Lab X"
        }
    }
    
    header_json = json.dumps(header).encode('utf-8')
    header_len = struct.pack('<Q', len(header_json))
    dummy_data = b'\x00\x00\x00\x00'
    
    output_path = target_dir / "mock_restricted.safetensors" 
    with open(output_path, "wb") as f:
        f.write(header_len)
        f.write(header_json)
        f.write(dummy_data)
        
    return output_path

def create_mock_gguf(target_dir: Path):
    """Generates a minimal valid GGUF header with a restrictive license."""
    output_path = target_dir / "mock_restricted.gguf"
    
    with open(output_path, "wb") as f:
        # 1. Magic "GGUF"
        f.write(b'GGUF')
        
        # 2. Version (3) - Little Endian uint32
        f.write(struct.pack('<I', 3))
        
        # 3. Tensor Count (0) - uint64
        f.write(struct.pack('<Q', 0))
        
        # 4. KV Pair Count (1) - uint64 (We will write 1 pair: general.license)
        f.write(struct.pack('<Q', 1))
        
        # --- KV PAIR 1 ---
        # Key: "general.license"
        key = "general.license"
        f.write(struct.pack('<Q', len(key))) # Key Length
        f.write(key.encode('utf-8'))         # Key String
        
        # Type: String (8) - uint32
        f.write(struct.pack('<I', 8))
        
        # Value: "cc-by-nc-sa-4.0" (Restrictive)
        val = "cc-by-nc-sa-4.0"
        f.write(struct.pack('<Q', len(val))) # Value Length
        f.write(val.encode('utf-8'))         # Value String
        
    return output_path

# --- DIFF DEMO LOGIC ---
import uuid
import random

def _generate_component(name, version, risk="LOW", license="MIT", is_model=False):
    # Simulate scanner logic: simple check for restricted keywords
    restricted = ["cc-by-nc", "agpl", "commons clause"]
    
    is_restricted = any(r in license.lower() for r in restricted)
    legal_status = f"LEGAL RISK ({license})" if is_restricted else "UNKNOWN"
    
    desc = f"Risk: {risk} | Framework: PyTorch | Legal: {legal_status} | License: {license}"
    
    comp = {
        "bom-ref": str(uuid.uuid4()),
        "name": name,
        "version": version,
        "type": "machine-learning-model" if is_model else "library",
        "description": desc
    }
    
    if is_model:
        comp["hashes"] = [{"alg": "SHA-256", "content": "".join(random.choices("0123456789abcdef", k=64))}]
    
    return comp

def create_demo_diff_sboms(target_dir: Path):
    """Generates a pair of SBOMs (Baseline vs Drifted) for testing the diff command."""
    demo_dir = target_dir / "demo_data"
    demo_dir.mkdir(exist_ok=True)

    # Base SBOM Components
    params = [
        ("stable-lib", "1.0.0", "LOW", "MIT", False),
        ("stable-model.pt", "v1", "LOW", "MIT", True),
        ("drift-risk.pt", "v1", "LOW", "MIT", True),      # Will become CRITICAL
        ("drift-license.pt", "v1", "LOW", "MIT", True),   # Will become CC-BY-NC (Legal Risk)
        ("drift-ver-lib", "1.0.0", "LOW", "MIT", False),    # Will bump version
        ("drift-hash.pt", "v1", "LOW", "MIT", True),        # Will change hash
        ("removed-lib", "0.9.0", "LOW", "MIT", False),      # Will be removed
    ]
    
    old_comps = [_generate_component(*p) for p in params]
    
    # New SBOM Components
    new_comps = []
    for c in old_comps:
        name = c["name"]
        if "removed" in name:
            continue
            
        new_c = c.copy()
        
        # Apply Drifts
        if name == "drift-risk.pt":
            new_c["description"] = c["description"].replace("Risk: LOW", "Risk: CRITICAL")
        elif name == "drift-license.pt":
            new_c["description"] = c["description"].replace("Risk: LOW", "Risk: LOW") # No risk change
            # Manually update description to reflect new license and NEW status
            # Since _generate_component isn't called here, we hack the string
            # Old: ... Legal: UNKNOWN | License: MIT
            # New: ... Legal: LEGAL RISK (CC-BY-NC) | License: CC-BY-NC
            new_c["description"] = new_c["description"].replace("License: MIT", "License: CC-BY-NC-4.0")
            new_c["description"] = new_c["description"].replace("Legal: UNKNOWN", "Legal: LEGAL RISK (CC-BY-NC-4.0)")
        elif name == "drift-ver-lib":
            new_c["version"] = "1.0.1"
        elif name == "drift-hash.pt":
            new_c["hashes"] = [{"alg": "SHA-256", "content": "deadbeef" + "0" * 56}]
            
        new_comps.append(new_c)

    # Add new items
    new_comps.append(_generate_component("added-new-lib", "2.0.0", "LOW", "Apache-2.0", False))
    new_comps.append(_generate_component("added-critical.pt", "v1", "CRITICAL", "Unknown", True))

    path_old = demo_dir / "sbom_baseline.json"
    path_new = demo_dir / "sbom_drifted.json"

    with open(path_old, "w") as f:
        json.dump({"components": old_comps}, f, indent=2)
        
    with open(path_new, "w") as f:
        json.dump({"components": new_comps}, f, indent=2)
        
    return path_old, path_new