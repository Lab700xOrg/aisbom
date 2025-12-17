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