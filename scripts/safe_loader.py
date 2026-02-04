import torch
import sys
import os

def load_safely(model_path):
    print(f"🔒 [Sandbox] Attempting to load: {model_path}")
    
    if not os.path.exists(model_path):
        print(f"❌ Error: File not found: {model_path}")
        sys.exit(1)

    try:
        # We purposely use weights_only=False here because we are technically "safe" inside the sandbox.
        # This allows us to load legacy models that would otherwise fail.
        # IF there is malware, it executes here, but the container *should* contain it.
        model = torch.load(model_path, weights_only=False)
        print(f"✅ Success! Model loaded. Type: {type(model)}")
        return model
    except Exception as e:
        print(f"❌ Load Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python safe_loader.py <path_to_model.pt>")
        sys.exit(1)
    
    load_safely(sys.argv[1])
