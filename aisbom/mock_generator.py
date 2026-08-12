import os
import pickle
import zipfile
import io
import json
import struct
from pathlib import Path

# --- BYPASS-CORPUS PRIMITIVES ---
# The evasion corpus (aisbom/corpus.py) needs pickles that reference globals we
# must never actually import (pip.main, bdb.Bdb, asyncio internals). Pickling a
# real object cannot produce those, so the streams are assembled opcode by
# opcode here. Every one names the same inert echo below — there is no payload
# in this repo, only a recognizable signature for the disassembler to find.
HARMLESS_COMMAND = "echo [TEST] AIsbom bypass-corpus simulation - no payload executed"


def _short_binunicode(text: str) -> bytes:
    """SHORT_BINUNICODE (protocol 4) frame for a short string."""
    raw = text.encode("utf-8")
    if len(raw) > 255:
        raise ValueError("string too long for SHORT_BINUNICODE")
    return b"\x8c" + bytes([len(raw)]) + raw


def harmless_reduce_pickle(module: str, name: str, command: str = HARMLESS_COMMAND) -> bytes:
    """
    A protocol-0 pickle equivalent to `module.name(command)`.

    Uses the GLOBAL opcode ('c' module '\\n' name '\\n'), which is what the
    blocklist path in safety.py matches on.
    """
    return (
        b"c" + module.encode("utf-8") + b"\n" + name.encode("utf-8") + b"\n"
        + b"("                                   # MARK
        + b"S" + repr(command).encode("utf-8") + b"\n"   # STRING
        + b"t"                                   # TUPLE
        + b"R"                                   # REDUCE
        + b"."                                   # STOP
    )


def harmless_stack_global_pickle(module: str, name: str, command: str = HARMLESS_COMMAND) -> bytes:
    """
    A protocol-4 pickle equivalent to `module.name(command)`.

    Uses STACK_GLOBAL, which resolves the module and name from the stack rather
    than from an inline argument — the opcode path that scanners relying on
    GLOBAL-only string matching miss.
    """
    return (
        b"\x80\x04"                              # PROTO 4
        + _short_binunicode(module)
        + _short_binunicode(name)
        + b"\x93"                                # STACK_GLOBAL
        + _short_binunicode(command)
        + b"\x85"                                # TUPLE1
        + b"R"                                   # REDUCE
        + b"."                                   # STOP
    )


def truncate_pickle(payload: bytes, junk: bytes = b"\x99\x99\x99") -> bytes:
    """
    Drop the STOP opcode and append an invalid opcode.

    Reproduces the nullifAI shape: the pickle VM executes the opcodes at the
    front of the stream before it ever reaches the corruption, so a scanner
    that bails on a malformed stream never sees the payload that still runs.
    """
    return payload.rstrip(b".") + junk


def pytorch_zip_bytes(
    payload: bytes,
    inner_name: str = "archive/data.pkl",
    compression: int = zipfile.ZIP_DEFLATED,
) -> bytes:
    """Wrap a pickle stream in the ZIP layout torch.save() produces."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as z:
        z.writestr(inner_name, payload)
        z.writestr("archive/version", "3")
    return buffer.getvalue()


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

# --- 2. BROKEN MIGRATION LOGIC (LINT FAILURE) ---
class MockCustomLayer(object):
    """
    A harmless custom class. It is NOT malware.
    However, it will cause torch.load(weights_only=True) to fail
    because it is not in the default PyTorch allowlist.
    """
    def __init__(self):
        self.config = {"layer_type": "ProprietaryAttention"}

def create_mock_broken_file(target_dir: Path):
    """Generates a PyTorch file that is SAFE but fails Strict Mode."""
    # Pickle a custom class
    payload_bytes = pickle.dumps(MockCustomLayer(), protocol=2)

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('archive/data.pkl', payload_bytes)
        z.writestr('archive/version', '3')

    output_path = target_dir / "mock_broken.pt"
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

# --- KERAS ARTIFACTS ---
# A `.keras` file is a zip holding the model config as JSON, so a realistic
# fixture needs nothing but the standard library. The legacy `.h5` container is
# HDF5 and cannot be written without h5py, which is a dev-only dependency — so
# HDF5 fixtures are built in the test suite instead of here, and the shipped
# package stays free of that dependency.

def _marshalled_code_b64() -> str:
    """Base64 of a marshalled code object, as a Keras Lambda layer stores one.

    This is the *signature* a scanner must recognize, not a payload: the code
    object returned here computes ``x + 1``. It is never unmarshalled or called.
    """
    import base64
    import marshal

    harmless = lambda x: x + 1  # noqa: E731
    return base64.b64encode(marshal.dumps(harmless.__code__)).decode("ascii")


def create_mock_keras_zip(output_path, with_lambda: bool = False) -> Path:
    """Write a `.keras` archive, optionally carrying a Lambda layer.

    Takes an explicit output path (rather than a target directory like the
    older generators) because each Keras case wants its own filename.
    """
    output_path = Path(output_path)
    layers = [
        {
            "module": "keras.layers",
            "class_name": "Dense",
            "config": {"name": "dense_0", "units": 64, "activation": "relu"},
            "registered_name": None,
        }
    ]
    if with_lambda:
        layers.insert(0, {
            "module": "keras.layers",
            "class_name": "Lambda",
            "config": {
                "name": "lambda_exec",
                "function": {
                    "class_name": "__lambda__",
                    "config": {"code": _marshalled_code_b64(), "defaults": None, "closure": None},
                },
            },
            "registered_name": None,
        })

    config = {
        "module": "keras",
        "class_name": "Sequential",
        "config": {"name": "sequential", "layers": layers},
        "registered_name": None,
    }
    metadata = {"keras_version": "3.5.0", "date_saved": "2026-01-01@00:00:00"}

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("metadata.json", json.dumps(metadata, indent=2))
        z.writestr("config.json", json.dumps(config, indent=2))

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