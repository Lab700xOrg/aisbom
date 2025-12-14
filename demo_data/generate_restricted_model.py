import struct
import json
import os

# 1. Define the Header with RESTRICTED License
header = {
    "weight_tensor": {
        "dtype": "F32",
        "shape": [1],
        "data_offsets": [0, 4]
    },
    "__metadata__": {
        "format": "pt",
        "license": "cc-by-nc-4.0 (Non-Commercial)", # <--- The Trigger
        "author": "Research Lab X"
    }
}

# 2. Serialize Header
header_json = json.dumps(header).encode('utf-8')
header_len = len(header_json)

# 3. Create dummy data (4 bytes for float32)
dummy_data = b'\x00\x00\x00\x00'

# 4. Write File: [8 bytes length][json header][data]
# Get the directory where this script is located
script_dir = os.path.dirname(os.path.abspath(__file__))
output_file = os.path.join(script_dir, "restricted_model.safetensors")
with open(output_file, "wb") as f:
    # Write header length as unsigned long long (8 bytes)
    f.write(struct.pack('<Q', header_len))
    # Write JSON header
    f.write(header_json)
    # Write data
    f.write(dummy_data)

print(f"✅ Generated {output_file} with Non-Commercial license metadata.")