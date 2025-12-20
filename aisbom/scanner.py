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
GGUF_EXTENSION = '.gguf'
REQUIREMENTS_FILENAME = 'requirements.txt'

# Simple blocklist for license keywords that imply legal risk in commercial software
RESTRICTED_LICENSES = ["non-commercial", "cc-by-nc", "agpl", "commons clause"]

from aisbom.remote import RemoteStream, resolve_huggingface_repo

class DeepScanner:
    def __init__(self, root_path: str, strict_mode: bool = False):
        self.root_path = root_path
        self.strict_mode = strict_mode
        self.artifacts = []
        self.dependencies = []
        self.errors = []
        self.is_remote = isinstance(root_path, str) and (
            root_path.startswith("http://")
            or root_path.startswith("https://")
            or root_path.startswith("hf://")
        )

    def scan(self):
        """Orchestrates the scan of the directory."""
        if self.is_remote:
            targets = self._resolve_remote_targets(self.root_path)
            for url in targets:
                ext = Path(url).suffix.lower()
                if ext in PYTORCH_EXTENSIONS:
                    with RemoteStream(url) as stream:
                        self.artifacts.append(self._inspect_pytorch(stream, Path(url).name, is_remote=True))
                elif ext == SAFETENSORS_EXTENSION:
                    with RemoteStream(url) as stream:
                        self.artifacts.append(self._inspect_safetensors(stream, Path(url).name, is_remote=True))
                elif ext == GGUF_EXTENSION:
                    with RemoteStream(url) as stream:
                        self.artifacts.append(self._inspect_gguf(stream, Path(url).name, is_remote=True))
        else:
            root = Path(self.root_path)
            for full_path in root.rglob("*"):
                if full_path.is_file():
                    ext = full_path.suffix.lower()

                    if ext in PYTORCH_EXTENSIONS:
                        self.artifacts.append(self._inspect_pytorch(full_path))
                    elif ext == SAFETENSORS_EXTENSION:
                        self.artifacts.append(self._inspect_safetensors(full_path))
                    elif ext == GGUF_EXTENSION:
                        self.artifacts.append(self._inspect_gguf(full_path))
                    elif full_path.name == REQUIREMENTS_FILENAME:
                        self._parse_requirements(full_path)

        return {"artifacts": self.artifacts, "dependencies": self.dependencies, "errors": self.errors}

    def _resolve_remote_targets(self, target: str):
        if target.startswith("hf://"):
            return resolve_huggingface_repo(target)
        if target.startswith("http://") or target.startswith("https://"):
            return [target]
        return []

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

    def _inspect_pytorch(self, source, name: str | None = None, is_remote: bool = False) -> Dict[str, Any]:
        """Peeks inside PyTorch."""
        local_path = None
        if isinstance(source, (str, Path)):
            local_path = Path(source)
            name = name or local_path.name
            is_remote = False
        name = name or getattr(source, "name", "unknown")

        meta = {
            "name": name,
            "type": "machine-learning-model",
            "framework": "PyTorch",
            "risk_level": "UNKNOWN",
            "license": "Unknown", # PyTorch files rarely store metadata natively
            "legal_status": "UNKNOWN",
            "hash": "remote_unhashed" if is_remote else self._calculate_hash(local_path),
            "details": {}
        }
        try:
            # Choose stream
            if local_path:
                stream = open(local_path, "rb")
            else:
                stream = source

            if zipfile.is_zipfile(stream):
                stream.seek(0)
                with zipfile.ZipFile(stream, 'r') as z:
                    files = z.namelist()
                    pickle_files = [f for f in files if f.endswith('.pkl')]
                    
                    threats = []
                    if pickle_files:
                        main_pkl = pickle_files[0]
                        with z.open(main_pkl) as f:
                            content = f.read(10 * 1024 * 1024) 
                            threats = scan_pickle_stream(content, strict_mode=self.strict_mode)

                    if threats:
                        meta["risk_level"] = f"CRITICAL (RCE Detected: {', '.join(threats)})"
                    elif pickle_files:
                        meta["risk_level"] = "MEDIUM (Pickle Present)"
                    else:
                        meta["risk_level"] = "LOW"
                        
                    meta["details"] = {"internal_files": len(files), "threats": threats}
            else:
                 meta["risk_level"] = "CRITICAL (Legacy Binary)"
            if local_path and not stream.closed:
                stream.close()
        except Exception as e:
            meta["error"] = str(e)
        return meta

    def _inspect_safetensors(self, source, name: str | None = None, is_remote: bool = False) -> Dict[str, Any]:
        """Reads Safetensors header for Metadata/License."""
        local_path = None
        if isinstance(source, (str, Path)):
            local_path = Path(source)
            name = name or local_path.name
            is_remote = False
        name = name or getattr(source, "name", "unknown")
        meta = {
            "name": name,
            "type": "machine-learning-model", 
            "framework": "SafeTensors",
            "risk_level": "LOW", 
            "license": "Unknown",
            "legal_status": "UNKNOWN",
            "hash": "remote_unhashed" if is_remote else self._calculate_hash(local_path),
            "details": {}
        }
        try:
            f = open(local_path, "rb") if local_path else source
            f.seek(0)
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
            if local_path:
                f.close()
        except Exception as e:
            meta["error"] = str(e)
        return meta

    def _inspect_gguf(self, source, name: str | None = None, is_remote: bool = False) -> Dict[str, Any]:
        """
        Parses GGUF header to extract metadata/licenses.
        GGUF format: Magic (4b) | Version (4b) | TensorCount (8b) | KVCount (8b) | KV Pairs...
        """
        local_path = None
        if isinstance(source, (str, Path)):
            local_path = Path(source)
            name = name or local_path.name
            is_remote = False
        name = name or getattr(source, "name", "unknown")
        meta = {
            "name": name,
            "type": "machine-learning-model",
            "framework": "GGUF",
            "risk_level": "LOW", # GGUF is binary-safe (no pickle)
            "license": "Unknown",
            "legal_status": "UNKNOWN",
            "hash": "remote_unhashed" if is_remote else self._calculate_hash(local_path),
            "details": {}
        }

        try:
            f = open(local_path, "rb") if local_path else source
            f.seek(0)
            # 1. Check Magic "GGUF"
            magic = f.read(4)
            if magic != b'GGUF':
                meta['risk_level'] = "UNKNOWN (Invalid Header)"
                return meta

            # 2. Read Header Info
            # Version (I), Tensor Count (Q), KV Count (Q)
            # I = uint32 (4 bytes), Q = uint64 (8 bytes)
            ver_bytes = f.read(4)
            version = struct.unpack('<I', ver_bytes)[0]
            
            f.read(8) # Skip Tensor Count
            
            kv_count_bytes = f.read(8)
            kv_count = struct.unpack('<Q', kv_count_bytes)[0]
            
            extracted_meta = {}
            
            # 3. Parse Key-Value Pairs
            # We interpret just enough to find the license
            for _ in range(kv_count):
                # Read Key (String: Length (Q) + Bytes)
                key_len_b = f.read(8)
                if not key_len_b: break
                key_len = struct.unpack('<Q', key_len_b)[0]
                key = f.read(key_len).decode('utf-8', errors='ignore')
                
                # Read Value Type (uint32)
                type_b = f.read(4)
                val_type = struct.unpack('<I', type_b)[0]
                
                # GGUF Value Types: 8=String, others are numbers/bools/arrays
                # We strictly care about Strings (8) for metadata
                value = "N/A"
                if val_type == 8: # String
                    val_len = struct.unpack('<Q', f.read(8))[0]
                    value = f.read(val_len).decode('utf-8', errors='ignore')
                elif val_type in [0, 1, 2, 3, 4, 5, 10, 11, 12]: 
                    # Simple scalar types (1-8 bytes), skip them to get to next key
                    # Mapping sizes roughly: 
                    # 0(uint8):1, 1(int8):1, 2(uint16):2, 3(int16):2, 4(uint32):4, 5(int32):4
                    # 10(uint64):8, 11(int64):8, 12(float64):8
                    skip_map = {0:1, 1:1, 2:2, 3:2, 4:4, 5:4, 6:4, 7:8, 10:8, 11:8, 12:8}
                    skip = skip_map.get(val_type, 0)
                    if skip > 0: f.read(skip)
                    if val_type == 12: value = "float" # Placeholder
                elif val_type == 9: # Array
                    # Arrays are complex to skip without recursion, abort parsing to avoid crash
                    # Most metadata strings are at the top of the file anyway
                    break 
                
                # Capture interesting keys
                if val_type == 8:
                    if "license" in key:
                        extracted_meta[key] = value
                    if "architecture" in key:
                        extracted_meta["arch"] = value

            # 4. Analyze License
            # GGUF usually stores it as "general.license"
            lic = extracted_meta.get("general.license") or extracted_meta.get("license") or "Unknown"
            meta["license"] = lic
            meta["legal_status"] = self._assess_legal_risk(lic)
            meta["details"] = extracted_meta

        except Exception as e:
            meta['details']['error'] = str(e)
        finally:
            if local_path and f:
                f.close()
            
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
