import os
import json
import zipfile
import struct
from typing import List, Dict, Any
from pathlib import Path
from .safety import scan_pickle_stream
from pip_requirements_parser import RequirementsFile

# Constants for file types make the code cleaner and easier to extend
PYTORCH_EXTENSIONS = {'.pt', '.pth', '.bin'}
SAFETENSORS_EXTENSION = '.safetensors'
REQUIREMENTS_FILENAME = 'requirements.txt'

class DeepScanner:
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.artifacts = []
        self.dependencies = []
        self.errors = []

    def scan(self):
        """Orchestrates the scan of the directory."""
        # Use rglob for a more concise way to recursively find files
        for full_path in self.root_path.rglob("*"):
            if full_path.is_file():
                ext = full_path.suffix.lower()

                # 1. Scan AI Artifacts
                if ext in PYTORCH_EXTENSIONS:
                    self.artifacts.append(self._inspect_pytorch(full_path))
                elif ext == SAFETENSORS_EXTENSION:
                    self.artifacts.append(self._inspect_safetensors(full_path))
                
                # 2. Scan Dependency Manifests
                elif full_path.name == REQUIREMENTS_FILENAME:
                    self._parse_requirements(full_path)

        return {"artifacts": self.artifacts, "dependencies": self.dependencies, "errors": self.errors}

    def _inspect_pytorch(self, path: Path) -> Dict[str, Any]:
        """Peeks inside a PyTorch file structure and SCANS for malware."""
        meta = {
            "name": path.name,
            "type": "machine-learning-model",
            "framework": "PyTorch",
            "risk_level": "UNKNOWN", 
            "details": {}
        }
        try:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path, 'r') as z:
                    files = z.namelist()
                    
                    # 1. Find the data file (usually archive/data.pkl or just data.pkl)
                    pickle_files = [f for f in files if f.endswith('.pkl')]
                    
                    threats = []
                    if pickle_files:
                        # 2. Extract and Scan the pickle bytes
                        # We only scan the first few MBs or the main file to be fast
                        main_pkl = pickle_files[0]
                        with z.open(main_pkl) as f:
                            # Read first 10MB max to prevent zip bombs
                            content = f.read(10 * 1024 * 1024) 
                            threats = scan_pickle_stream(content)

                    # 3. Assess Risk
                    if threats:
                        meta["risk_level"] = f"CRITICAL (RCE Detected: {', '.join(threats)})"
                    elif pickle_files:
                        meta["risk_level"] = "MEDIUM (Pickle Present)"
                    else:
                        meta["risk_level"] = "LOW (No bytecode found)"
                        
                    meta["details"] = {"internal_files": len(files), "threats": threats}
            else:
                meta["risk_level"] = "CRITICAL (Legacy Binary)"
        except Exception as e:
            meta["error"] = str(e)
        return meta

    def _inspect_safetensors(self, path: Path) -> Dict[str, Any]:
        """Reads the JSON header from a .safetensors file."""
        meta = {
            "name": path.name,
            "type": "machine-learning-model", 
            "framework": "SafeTensors",
            "risk_level": "LOW", # Safe by design
            "details": {}
        }
        try:
            with open(path, 'rb') as f:
                # First 8 bytes = header length
                length_bytes = f.read(8)
                if len(length_bytes) == 8:
                    header_len = struct.unpack('<Q', length_bytes)[0]
                    header_json = json.loads(f.read(header_len))
                    meta["details"] = {
                        "tensors": len(header_json.keys()),
                        "metadata": header_json.get("__metadata__", {})
                    }
        except Exception as e:
            meta["error"] = str(e)
        return meta

    def _parse_requirements(self, path: Path):
        """Parses requirements.txt into individual components."""
        try:
            req_file = RequirementsFile.from_file(path)
            for req in req_file.requirements:
                if req.name:
                    # Robust version extraction
                    version = "unknown"
                    specs = list(req.specifier) if req.specifier else []
                    if specs:
                        # Grab the first version number found, e.g. "==1.2.0" -> "1.2.0"
                        version = specs[0].version
                    
                    self.dependencies.append({
                        "name": req.name,
                        "version": version,
                        "type": "library"
                    })
        except Exception as e:
            self.errors.append({"file": str(path), "error": str(e)})