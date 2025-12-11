import os
import json
import zipfile
import struct
import hashlib
from typing import List, Dict, Any
from pathlib import Path
from pip_requirements_parser import RequirementsFile
from aisbom.safety import scan_pickle_stream

# Constants
PYTORCH_EXTENSIONS = {'.pt', '.pth', '.bin'}
SAFETENSORS_EXTENSION = '.safetensors'
REQUIREMENTS_FILENAME = 'requirements.txt'

# Simple blocklist for license keywords that imply legal risk in commercial software
RESTRICTED_LICENSES = ["non-commercial", "cc-by-nc", "agpl", "commons clause"]

class DeepScanner:
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.artifacts = []
        self.dependencies = []
        self.errors = []

    def scan(self):
        """Orchestrates the scan of the directory."""
        for full_path in self.root_path.rglob("*"):
            if full_path.is_file():
                ext = full_path.suffix.lower()

                if ext in PYTORCH_EXTENSIONS:
                    self.artifacts.append(self._inspect_pytorch(full_path))
                elif ext == SAFETENSORS_EXTENSION:
                    self.artifacts.append(self._inspect_safetensors(full_path))
                elif full_path.name == REQUIREMENTS_FILENAME:
                    self._parse_requirements(full_path)

        return {"artifacts": self.artifacts, "dependencies": self.dependencies, "errors": self.errors}

    def _calculate_hash(self, path: Path) -> str:
        sha256_hash = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for byte_block in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return "hash_error"

    def _assess_legal_risk(self, license_name: str) -> str:
        """Checks if a license string contains restricted keywords."""
        if not license_name or license_name == "Unknown":
            return "UNKNOWN"
        
        normalized = license_name.lower()
        for restricted in RESTRICTED_LICENSES:
            if restricted in normalized:
                return f"LEGAL RISK ({license_name})"
        return "PASS"

    def _inspect_pytorch(self, path: Path) -> Dict[str, Any]:
        """Peeks inside PyTorch."""
        meta = {
            "name": path.name,
            "type": "machine-learning-model",
            "framework": "PyTorch",
            "risk_level": "UNKNOWN",
            "license": "Unknown", # PyTorch files rarely store metadata natively
            "legal_status": "UNKNOWN",
            "hash": self._calculate_hash(path),
            "details": {}
        }
        try:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path, 'r') as z:
                    files = z.namelist()
                    pickle_files = [f for f in files if f.endswith('.pkl')]
                    
                    threats = []
                    if pickle_files:
                        main_pkl = pickle_files[0]
                        with z.open(main_pkl) as f:
                            content = f.read(10 * 1024 * 1024) 
                            threats = scan_pickle_stream(content)

                    if threats:
                        meta["risk_level"] = f"CRITICAL (RCE Detected: {', '.join(threats)})"
                    elif pickle_files:
                        meta["risk_level"] = "MEDIUM (Pickle Present)"
                    else:
                        meta["risk_level"] = "LOW"
                        
                    meta["details"] = {"internal_files": len(files), "threats": threats}
            else:
                 meta["risk_level"] = "CRITICAL (Legacy Binary)"
        except Exception as e:
            meta["error"] = str(e)
        return meta

    def _inspect_safetensors(self, path: Path) -> Dict[str, Any]:
        """Reads Safetensors header for Metadata/License."""
        meta = {
            "name": path.name,
            "type": "machine-learning-model", 
            "framework": "SafeTensors",
            "risk_level": "LOW", 
            "license": "Unknown",
            "legal_status": "UNKNOWN",
            "hash": self._calculate_hash(path),
            "details": {}
        }
        try:
            with open(path, 'rb') as f:
                length_bytes = f.read(8)
                if len(length_bytes) == 8:
                    header_len = struct.unpack('<Q', length_bytes)[0]
                    header_json = json.loads(f.read(header_len))
                    
                    # EXTRACT METADATA
                    metadata = header_json.get("__metadata__", {})
                    
                    # Try to find license key (HuggingFace standard)
                    license_info = metadata.get("license", "Unknown")
                    meta["license"] = license_info
                    meta["legal_status"] = self._assess_legal_risk(license_info)

                    meta["details"] = {
                        "tensors": len(header_json.keys()),
                        "metadata": metadata
                    }
        except Exception as e:
            meta["error"] = str(e)
        return meta

    def _parse_requirements(self, path: Path):
        try:
            req_file = RequirementsFile.from_file(path)
            for req in req_file.requirements:
                if req.name:
                    version = "unknown"
                    specs = list(req.specifier) if req.specifier else []
                    if specs:
                        version = specs[0].version
                    self.dependencies.append({
                        "name": req.name,
                        "version": version,
                        "type": "library"
                    })
        except Exception as e:
            self.errors.append({"file": str(path), "error": str(e)})