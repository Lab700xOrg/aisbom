import os
import json
import re
import zipfile
import struct
import hashlib
from typing import List, Dict, Any
from pathlib import Path
from pip_requirements_parser import RequirementsFile
from aisbom.safety import scan_keras_config, scan_keras_config_bytes, scan_pickle_stream

# Constants
PYTORCH_EXTENSIONS = {'.pt', '.pth', '.bin'}
SAFETENSORS_EXTENSION = '.safetensors'
GGUF_EXTENSION = '.gguf'
KERAS_EXTENSIONS = {'.keras', '.h5', '.hdf5'}
REQUIREMENTS_FILENAME = 'requirements.txt'

# HDF5 files start with this signature; a `.keras` file is a plain zip.
HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"

# Keras stores the model architecture as a JSON string in the root group's
# `model_config` attribute. HDF5 writes attribute values as literal,
# uncompressed bytes, so the JSON can be recovered by locating the attribute
# name and brace-matching the object that follows — no HDF5 library needed,
# which keeps the PyInstaller bundle unchanged. Verified against files written
# by h5py (what Keras itself uses) with configs from 300 bytes to 300KB.
KERAS_H5_CONFIG_ATTR = b"model_config"
KERAS_H5_VERSION_ATTR = b"keras_version"

# Cap on how many bytes of a container are searched for the config. The
# attribute sits in the root group's object header near the start of the file,
# so this is generous; it exists to bound memory on a multi-GB weights file.
KERAS_MAX_SCAN_BYTES = 16 * 1024 * 1024

# Remote scans pay for every byte over HTTP Range requests, so they get a much
# tighter cap — the config is at the head of the file, and pulling 16MB per
# model would break the "scans complete in seconds" property of a remote scan.
KERAS_MAX_REMOTE_SCAN_BYTES = 2 * 1024 * 1024

# Simple blocklist for license keywords that imply legal risk in commercial software
RESTRICTED_LICENSES = ["non-commercial", "cc-by-nc", "agpl", "commons clause"]

from aisbom.remote import RemoteStream, resolve_huggingface_repo

class DeepScanner:
    def __init__(self, root_path: str, strict_mode: bool = False, lint: bool = False):
        self.root_path = root_path
        self.strict_mode = strict_mode
        self.lint = lint
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
            # Resolving the repo is itself a network call; a 401/403/404 here
            # must surface as a structured error (not a swallowed empty list or
            # a raw traceback) so the CLI can render a status-aware hint.
            try:
                targets = self._resolve_remote_targets(self.root_path)
            except Exception as e:
                self._record_fetch_error(self.root_path, e)
                targets = []
            for url in targets:
                ext = Path(url).suffix.lower()
                # Per-target isolation: one gated/missing file in a multi-file
                # repo records its error and continues, so the rest still scan.
                try:
                    if ext in PYTORCH_EXTENSIONS:
                        with RemoteStream(url) as stream:
                            self.artifacts.append(self._inspect_pytorch(stream, Path(url).name, is_remote=True))
                    elif ext == SAFETENSORS_EXTENSION:
                        with RemoteStream(url) as stream:
                            self.artifacts.append(self._inspect_safetensors(stream, Path(url).name, is_remote=True))
                    elif ext == GGUF_EXTENSION:
                        with RemoteStream(url) as stream:
                            self.artifacts.append(self._inspect_gguf(stream, Path(url).name, is_remote=True))
                    elif ext in KERAS_EXTENSIONS:
                        with RemoteStream(url) as stream:
                            self.artifacts.append(self._inspect_keras(stream, Path(url).name, is_remote=True))
                except Exception as e:
                    self._record_fetch_error(url, e)
                    continue
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
                    elif ext in KERAS_EXTENSIONS:
                        self.artifacts.append(self._inspect_keras(full_path))
                    elif full_path.name == REQUIREMENTS_FILENAME:
                        self._parse_requirements(full_path)

        return {"artifacts": self.artifacts, "dependencies": self.dependencies, "errors": self.errors}

    def _resolve_remote_targets(self, target: str):
        if target.startswith("hf://"):
            return resolve_huggingface_repo(target)
        if target.startswith("http://") or target.startswith("https://"):
            return [target]
        return []

    def _record_fetch_error(self, target: str, exc: Exception) -> None:
        """Record a remote fetch failure as a structured, non-fatal error.

        Lands in results['errors'] so the CLI's `errors → exit 1` path fires.
        Tagged `fetch_failure` (vs. a parse error) and carries the live
        exception so the CLI can render a status-aware, traceback-free message
        and emit the enriched cli_error telemetry. The exception object stays
        in-process — errors are never serialized into the SBOM.
        """
        self.errors.append({
            "file": target,
            "error": str(exc),
            "fetch_failure": True,
            "exception": exc,
        })

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
        stream = None
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
                            
                            # LINT CHECK (Migration Linter)
                            if self.lint:
                                from aisbom.linter import MigrationLinter
                                linter = MigrationLinter()
                                lint_errors = linter.lint_pickle(content)
                                if lint_errors:
                                    meta["details"]["lint_report"] = [
                                        {"msg": e.message, "hint": e.hint, "severity": e.severity} 
                                        for e in lint_errors
                                    ]

                    if threats:
                        meta["risk_level"] = f"CRITICAL (RCE Detected: {', '.join(threats)})"
                    elif pickle_files:
                        meta["risk_level"] = "MEDIUM (Pickle Present)"
                    else:
                        meta["risk_level"] = "LOW"
                        
                    meta["details"].update({"internal_files": len(files), "threats": threats})
            else:
                 # Handle text-based .pth config files to avoid false positives
                 try:
                     stream.seek(0)
                     sample = stream.read(1024)
                     if isinstance(sample, bytes):
                         text = sample.decode("utf-8")
                     else:
                         text = str(sample)
                     # Consider it text if mostly printable characters
                     printable = sum(ch.isprintable() for ch in text)
                     if len(text) > 0 and printable / len(text) > 0.9:
                         meta["risk_level"] = "LOW"
                         meta["type"] = "configuration"
                         meta["framework"] = "Python Path Config"
                     else:
                         # Likely raw pickle (Legacy PyTorch 1.5-)
                         if self.lint:
                             stream.seek(0)
                             content = stream.read()
                             print(f"DEBUG: Linting {len(content)} bytes from {name}")
                             try:
                                 from aisbom.linter import MigrationLinter
                                 lint_errors = MigrationLinter().lint_pickle(content)
                                 print(f"DEBUG: Found {len(lint_errors)} errors")
                                 if lint_errors:
                                     meta["details"]["lint_report"] = [
                                        {"msg": e.message, "hint": e.hint, "severity": e.severity} 
                                        for e in lint_errors
                                     ]
                             except Exception as e:
                                 print(f"DEBUG: Linter failed: {e}")
                                 meta["details"]["lint_error"] = str(e)
                         meta["risk_level"] = "CRITICAL (Legacy Binary)"
                 except Exception:
                     if self.lint:
                         stream.seek(0)
                         content = stream.read()
                         try:
                             from aisbom.linter import MigrationLinter
                             lint_errors = MigrationLinter().lint_pickle(content)
                             if lint_errors:
                                 meta["details"]["lint_report"] = [
                                    {"msg": e.message, "hint": e.hint, "severity": e.severity} 
                                    for e in lint_errors
                                 ]
                         except Exception as e:
                             meta["details"]["lint_error"] = str(e)
                     meta["risk_level"] = "CRITICAL (Legacy Binary)"
        except Exception as e:
            meta["error"] = str(e)
        finally:
            if local_path and stream:
                try:
                    stream.close()
                except Exception:
                    pass
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
        f = None
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

                # Structured per-format findings (consumed by the platform's
                # artifact drawer as CycloneDX properties). "__metadata__" is a
                # header key but not a tensor, so exclude it from the count.
                tensor_entries = {
                    k: v for k, v in header_json.items() if k != "__metadata__"
                }
                dtypes = sorted({
                    v.get("dtype")
                    for v in tensor_entries.values()
                    if isinstance(v, dict) and v.get("dtype")
                })
                meta["details"] = {
                    "tensors": len(tensor_entries),
                    "metadata": metadata,
                    "dtypes": dtypes,
                    "header_keys": list(header_json.keys()),
                }
        except Exception as e:
            meta["error"] = str(e)
        finally:
            if local_path and f:
                try:
                    f.close()
                except Exception:
                    pass
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

        f = None
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
            metadata_keys = []   # every KV key we successfully read (for properties)
            quantization = None  # general.file_type / quantization_version (scalar)

            # Little-endian struct formats for the integer scalar types, so we
            # can decode quantization enums rather than blindly skipping them.
            int_fmt = {0: '<B', 1: '<b', 2: '<H', 3: '<h', 4: '<I', 5: '<i', 10: '<Q', 11: '<q'}

            # 3. Parse Key-Value Pairs
            # We interpret just enough to find the license, architecture, and
            # quantization, and to enumerate the metadata keys present.
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
                    # Simple scalar types (1-8 bytes), read them to get to next key
                    # Mapping sizes roughly:
                    # 0(uint8):1, 1(int8):1, 2(uint16):2, 3(int16):2, 4(uint32):4, 5(int32):4
                    # 10(uint64):8, 11(int64):8, 12(float64):8
                    skip_map = {0:1, 1:1, 2:2, 3:2, 4:4, 5:4, 6:4, 7:8, 10:8, 11:8, 12:8}
                    skip = skip_map.get(val_type, 0)
                    raw = f.read(skip) if skip > 0 else b""
                    if val_type == 12: value = "float" # Placeholder
                    # Quantization is stored as an integer enum, usually under
                    # general.file_type (or general.quantization_version).
                    if ("file_type" in key or "quantization" in key) and val_type in int_fmt:
                        try:
                            quantization = struct.unpack(int_fmt[val_type], raw)[0]
                        except struct.error:
                            pass
                elif val_type == 9: # Array
                    # Arrays are complex to skip without recursion, abort parsing to avoid crash
                    # Most metadata strings are at the top of the file anyway
                    metadata_keys.append(key)
                    break

                metadata_keys.append(key)

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
            # Structured per-format findings for CycloneDX properties.
            extracted_meta["architecture"] = extracted_meta.get("arch")
            if quantization is not None:
                extracted_meta["quantization"] = quantization
            extracted_meta["metadata_keys"] = metadata_keys
            meta["details"] = extracted_meta

        except Exception as e:
            meta['details']['error'] = str(e)
        finally:
            if local_path and f:
                try:
                    f.close()
                except Exception:
                    pass
            
        return meta

    @staticmethod
    def _brace_match(blob: bytes, start: int) -> bytes | None:
        """Return the JSON object beginning at ``start``, or None if unbalanced.

        String-aware: a ``{`` or ``}`` inside a JSON string literal is skipped,
        so a config that embeds braces in a layer name (or does so deliberately
        to break a naive matcher) still delimits correctly.
        """
        depth = 0
        in_string = False
        escaped = False
        for i in range(start, len(blob)):
            ch = blob[i]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == 0x5C:  # backslash
                    escaped = True
                elif ch == 0x22:  # closing quote
                    in_string = False
                continue
            if ch == 0x22:
                in_string = True
            elif ch == 0x7B:  # {
                depth += 1
            elif ch == 0x7D:  # }
                depth -= 1
                if depth == 0:
                    return blob[start:i + 1]
        return None

    def _extract_h5_config(self, blob: bytes) -> bytes | None:
        """Recover the `model_config` JSON from raw HDF5 bytes.

        HDF5 stores attribute values uncompressed and contiguous, so the JSON
        is located by finding the attribute name and brace-matching the first
        object that parses after it. Several candidates are tried because other
        attribute data can sit between the name and its value.
        """
        search_from = 0
        while True:
            attr_at = blob.find(KERAS_H5_CONFIG_ATTR, search_from)
            if attr_at == -1:
                return None
            cursor = attr_at
            for _ in range(5):
                brace_at = blob.find(b"{", cursor)
                if brace_at == -1:
                    break
                candidate = self._brace_match(blob, brace_at)
                if candidate is not None:
                    try:
                        if isinstance(json.loads(candidate), dict):
                            return candidate
                    except (ValueError, UnicodeDecodeError):
                        pass
                cursor = brace_at + 1
            search_from = attr_at + len(KERAS_H5_CONFIG_ATTR)

    @staticmethod
    def _extract_h5_keras_version(blob: bytes) -> str | None:
        """Read the `keras_version` attribute value, if it is present."""
        attr_at = blob.find(KERAS_H5_VERSION_ATTR)
        if attr_at == -1:
            return None
        window = blob[attr_at:attr_at + 128]
        match = re.search(rb"\d+\.\d+(?:\.\d+)?", window)
        return match.group(0).decode("ascii") if match else None

    @staticmethod
    def _keras_risk_label(threats: List[str], lambda_layers: List[str]) -> str:
        """Summarize Keras findings for the risk column.

        The full threat list stays in ``details``; this is the one-line version,
        so it names the Lambda layers (the part a user acts on) and counts the
        embedded code objects rather than pasting every JSON path into the
        terminal table. Must contain "CRITICAL" — that substring is what the
        CLI's ``--fail-on-risk`` exit-code check matches on.
        """
        parts = []
        named = list(dict.fromkeys(lambda_layers))  # de-duplicated, order kept
        if named:
            parts.append(f"Lambda layer(s): {', '.join(named)}")
        code_objects = sum(1 for t in threats if t.startswith("KERAS_MARSHALLED_CODE:"))
        if code_objects:
            parts.append(f"{code_objects} embedded code object(s)")
        serialized = sum(1 for t in threats if t.startswith("KERAS_SERIALIZED_LAMBDA:"))
        if serialized and not named:
            parts.append(f"{serialized} serialized callable(s)")
        detail = "; ".join(parts) if parts else "; ".join(threats)
        return f"CRITICAL (Keras Lambda Code Execution — {detail})"

    def _inspect_keras(self, source, name: str | None = None, is_remote: bool = False) -> Dict[str, Any]:
        """Scans a Keras model for Lambda-layer code execution.

        Handles both containers Keras writes: the newer `.keras` zip (config as
        a `config.json` member) and the legacy HDF5 `.h5` (config as the root
        group's `model_config` attribute). Neither path loads the model, and an
        embedded code object is identified from its header bytes without ever
        being unmarshalled.

        A container that cannot be parsed is still scanned: the raw bytes go
        through a signature check, so truncating or corrupting a file is not a
        way to hide a Lambda layer.
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
            "framework": "Keras",
            "risk_level": "LOW",
            "license": "Unknown",  # Keras containers carry no license metadata
            "legal_status": "UNKNOWN",
            "hash": "remote_unhashed" if is_remote else self._calculate_hash(local_path),
            "details": {},
        }

        f = None
        try:
            f = open(local_path, "rb") if local_path else source

            # A remote scan pays per byte, so it reads a smaller window.
            budget = KERAS_MAX_SCAN_BYTES if local_path else KERAS_MAX_REMOTE_SCAN_BYTES

            container = None
            config_bytes = None      # the config JSON, if we could isolate it
            fallback_bytes = b""     # what the signature scan reads if JSON fails
            keras_version = None

            if zipfile.is_zipfile(f):
                container = "keras-zip"
                f.seek(0)
                with zipfile.ZipFile(f, "r") as z:
                    members = z.namelist()
                    meta["details"]["internal_files"] = len(members)
                    if "config.json" in members:
                        with z.open("config.json") as cfg:
                            config_bytes = cfg.read(budget)
                            fallback_bytes = config_bytes
                    if "metadata.json" in members:
                        try:
                            with z.open("metadata.json") as md:
                                keras_version = json.loads(md.read(65536)).get("keras_version")
                        except Exception:
                            pass
            else:
                f.seek(0)
                if f.read(len(HDF5_MAGIC)) == HDF5_MAGIC:
                    container = "hdf5"
                    f.seek(0)
                    blob = f.read(budget)
                    fallback_bytes = blob
                    config_bytes = self._extract_h5_config(blob)
                    keras_version = self._extract_h5_keras_version(blob)

            if container is None:
                meta["risk_level"] = "UNKNOWN (Unrecognized Container)"
                meta["details"]["container"] = None
                meta["details"]["config_found"] = False
                meta["details"]["threats"] = []
                return meta

            parsed = None
            if config_bytes:
                try:
                    parsed = json.loads(config_bytes)
                except (ValueError, UnicodeDecodeError):
                    parsed = None

            if parsed is not None:
                threats = scan_keras_config(parsed)
                config_parsed = True
            else:
                # No usable JSON — fall back to the coarse signature scan
                # rather than declining to report on a file we can't fully read.
                threats = scan_keras_config_bytes(fallback_bytes)
                config_parsed = False

            layer_count = None
            if isinstance(parsed, dict):
                layers = (parsed.get("config") or {}).get("layers")
                if isinstance(layers, list):
                    layer_count = len(layers)
                keras_version = keras_version or parsed.get("keras_version")

            lambda_layers = [
                t.split(": ", 1)[1] for t in threats if t.startswith("KERAS_LAMBDA:")
            ]

            meta["details"].update({
                "container": container,
                "config_found": parsed is not None or bool(threats),
                "config_parsed": config_parsed,
                "threats": threats,
                "lambda_layers": lambda_layers,
                "layer_count": layer_count,
                "keras_version": keras_version,
            })

            if threats:
                meta["risk_level"] = self._keras_risk_label(threats, lambda_layers)
            elif parsed is None:
                meta["risk_level"] = "LOW"
        except Exception as e:
            meta["error"] = str(e)
        finally:
            if local_path and f:
                try:
                    f.close()
                except Exception:
                    pass
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
