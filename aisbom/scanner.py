import os
import json
import re
import zipfile
import zlib
import struct
import hashlib
from typing import List, Dict, Any
from pathlib import Path
from pip_requirements_parser import RequirementsFile
from aisbom import protobuf_reader as pb
from aisbom.safety import (
    onnx_domain_is_custom,
    scan_keras_config,
    scan_keras_config_bytes,
    scan_onnx_model,
    scan_pickle_stream,
)

# Constants
PYTORCH_EXTENSIONS = {'.pt', '.pth', '.bin'}
SAFETENSORS_EXTENSION = '.safetensors'
GGUF_EXTENSION = '.gguf'
KERAS_EXTENSIONS = {'.keras', '.h5', '.hdf5'}
ONNX_EXTENSION = '.onnx'
REQUIREMENTS_FILENAME = 'requirements.txt'

# --- ONNX protobuf field numbers ---
# ONNX has no magic bytes — a .onnx file is a bare serialized ModelProto — so
# these field numbers are the schema. Confirmed against models serialized by the
# onnx library itself rather than read off the .proto by eye.
_ONNX_MODEL_IR_VERSION = 1
_ONNX_MODEL_PRODUCER_NAME = 2
_ONNX_MODEL_PRODUCER_VERSION = 3
_ONNX_MODEL_DOMAIN = 4
_ONNX_MODEL_VERSION = 5
_ONNX_MODEL_GRAPH = 7
_ONNX_MODEL_OPSET_IMPORT = 8

_ONNX_OPSET_DOMAIN = 1
_ONNX_OPSET_VERSION = 2

_ONNX_GRAPH_NODE = 1
_ONNX_GRAPH_NAME = 2
_ONNX_GRAPH_INITIALIZER = 5

_ONNX_NODE_OP_TYPE = 4
_ONNX_NODE_ATTRIBUTE = 5
_ONNX_NODE_DOMAIN = 7

# AttributeProto: `g` holds one nested graph, `graphs` holds several. These are
# how If / Loop / Scan carry the branches they execute. `t` / `tensors` hold
# tensors, which can themselves point at external data (a Constant node).
# Numbers read from the ONNX descriptor, not from memory — `graphs` is 11, and
# 10 is `tensors`, which is exactly the sort of confusion that turns a security
# walk into a parse of the wrong bytes.
_ONNX_ATTRIBUTE_TENSOR = 5
_ONNX_ATTRIBUTE_GRAPH = 6
_ONNX_ATTRIBUTE_TENSORS = 10
_ONNX_ATTRIBUTE_GRAPHS = 11

# Nested graphs may nest further; bound the recursion rather than trusting the
# file's own structure.
ONNX_MAX_GRAPH_DEPTH = 12

# When walking a large file by seeking, only sub-messages under this size are
# read. A tensor pointing at external data carries no inline payload and is
# therefore tiny, and nodes are small by construction — so what gets stepped
# over is inline weight data, which holds nothing this scan looks for.
ONNX_MAX_SUBMESSAGE_BYTES = 4 * 1024 * 1024

_ONNX_TENSOR_NAME = 8
_ONNX_TENSOR_EXTERNAL_DATA = 13
_ONNX_TENSOR_DATA_LOCATION = 14
_ONNX_DATA_LOCATION_EXTERNAL = 1

_ONNX_STRING_ENTRY_KEY = 1
_ONNX_STRING_ENTRY_VALUE = 2

# Bound on how much of a model is read. ONNX stores weights inline, so a real
# model runs to gigabytes while the graph structure sits at the head; reading a
# window keeps memory flat. A truncated read still yields every node it covers.
ONNX_MAX_SCAN_BYTES = 16 * 1024 * 1024

# Remote scans pay per byte over HTTP Range requests, so they read far less.
ONNX_MAX_REMOTE_SCAN_BYTES = 2 * 1024 * 1024

# Caps on how much graph inventory is retained, so a model with a million nodes
# cannot turn one SBOM component into an unbounded document.
ONNX_MAX_OP_TYPES = 200
ONNX_MAX_EXTERNAL_ENTRIES = 100

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
                    elif ext == ONNX_EXTENSION:
                        with RemoteStream(url) as stream:
                            self.artifacts.append(self._inspect_onnx(stream, Path(url).name, is_remote=True))
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
                    elif ext == ONNX_EXTENSION:
                        self.artifacts.append(self._inspect_onnx(full_path))
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

    @staticmethod
    def _recover_zip_members(blob: bytes, limit: int = 32) -> bytes:
        """Rebuild member contents from local headers alone.

        A `.keras` archive whose central directory is truncated or damaged is
        rejected by ``zipfile``, but its local file headers — and the member
        data behind them — are usually intact. Reading those directly means a
        wrecked container is not a way to hide a Lambda layer, whether the
        member was stored or deflated.

        Returns the concatenated recovered members, for signature scanning.
        """
        recovered = []
        offset = 0
        for _ in range(limit):
            offset = blob.find(b"PK\x03\x04", offset)
            if offset == -1:
                break
            header = blob[offset:offset + 30]
            if len(header) < 30:
                break
            try:
                method = struct.unpack("<H", header[8:10])[0]
                compressed_size = struct.unpack("<I", header[18:22])[0]
                name_len = struct.unpack("<H", header[26:28])[0]
                extra_len = struct.unpack("<H", header[28:30])[0]
            except struct.error:
                break

            start = offset + 30 + name_len + extra_len
            # A damaged header can carry a zero size; take what remains.
            end = start + compressed_size if compressed_size else len(blob)
            payload = blob[start:min(end, len(blob))]

            if method == zipfile.ZIP_STORED:
                recovered.append(payload)
            elif method == zipfile.ZIP_DEFLATED:
                try:
                    # -15 selects raw deflate: no wrapper, no checksum, so a
                    # damaged trailer does not prevent reading the front.
                    recovered.append(zlib.decompressobj(-15).decompress(payload))
                except zlib.error:
                    pass
            offset = start + max(compressed_size, 1)

        return b"".join(recovered)

    @staticmethod
    def _hdf5_signature_offset(blob: bytes) -> int | None:
        """Find the HDF5 superblock, which need not sit at offset zero.

        The format permits a *user block* before the superblock, whose size is
        512 bytes or any larger power of two. h5py opens such files normally, so
        requiring the signature at offset 0 would let a Keras model with a user
        block — Lambda layer and all — be dismissed as an unrecognized container.
        """
        offset = 0
        while offset < len(blob):
            if blob[offset:offset + len(HDF5_MAGIC)] == HDF5_MAGIC:
                return offset
            offset = 512 if offset == 0 else offset * 2
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
            truncated = False        # did the read stop at the budget?

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
                            truncated = len(config_bytes) >= budget
                    if "metadata.json" in members:
                        try:
                            with z.open("metadata.json") as md:
                                keras_version = json.loads(md.read(65536)).get("keras_version")
                        except Exception:
                            pass
            else:
                f.seek(0)
                blob = f.read(budget)
                fallback_bytes = blob
                truncated = len(blob) >= budget
                if self._hdf5_signature_offset(blob) is not None:
                    container = "hdf5"
                    config_bytes = self._extract_h5_config(blob)
                    keras_version = self._extract_h5_keras_version(blob)

            if container is None:
                # Not a readable ZIP and no HDF5 signature — but a damaged
                # archive lands here too, and a truncated `.keras` can still
                # carry an intact Lambda signature in its bytes. Refusing to
                # look would make corrupting the container an evasion.
                salvage = scan_keras_config_bytes(fallback_bytes)
                if not salvage and fallback_bytes.startswith(b"PK\x03\x04"):
                    # A damaged archive: its directory is unusable but the
                    # member data behind the local headers usually is not.
                    salvage = scan_keras_config_bytes(
                        self._recover_zip_members(fallback_bytes)
                    )
                meta["details"]["container"] = None
                meta["details"]["config_found"] = bool(salvage)
                meta["details"]["config_parsed"] = False
                meta["details"]["threats"] = salvage
                meta["details"]["lambda_layers"] = [
                    t.split(": ", 1)[1] for t in salvage if t.startswith("KERAS_LAMBDA:")
                ]
                if salvage:
                    meta["risk_level"] = self._keras_risk_label(
                        salvage, meta["details"]["lambda_layers"]
                    )
                else:
                    meta["risk_level"] = "UNKNOWN (Unrecognized Container)"
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
                "truncated": truncated,
            })

            if threats:
                meta["risk_level"] = self._keras_risk_label(threats, lambda_layers)
            elif truncated:
                # The config did not fit the read window, so a Lambda layer
                # after the cut would not have been seen. Padding a config with
                # harmless layers is cheap, and the archive stays small and
                # loadable — so "nothing found" here is not a clean bill.
                meta["risk_level"] = (
                    "MEDIUM (Keras config incomplete: read limit reached)"
                )
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

    @staticmethod
    def _parse_onnx_model(blob: bytes) -> Dict[str, Any]:
        """Walk a serialized ONNX ModelProto into a plain dict.

        Structure only — the security judgement lives in ``scan_onnx_model``.
        The walk is total: a field that is absent, empty or truncated yields
        ``None`` or an empty list rather than raising, because the input is an
        untrusted file that may well be none of the things it claims to be.
        """
        model = pb.parse_message(blob)

        opsets = []
        for entry in pb.get_messages(model, _ONNX_MODEL_OPSET_IMPORT):
            opsets.append({
                "domain": pb.get_str(entry, _ONNX_OPSET_DOMAIN) or "",
                "version": pb.get_int(entry, _ONNX_OPSET_VERSION),
            })

        graph_name = None
        op_types: List[str] = []
        custom_ops: List[Dict[str, Any]] = []
        external_data: List[Dict[str, Any]] = []
        node_count = 0

        # `If`, `Loop` and `Scan` carry whole GraphProtos in their node
        # attributes, and those subgraphs execute. A walk covering only the top
        # level would miss a custom operator or an escaping external-data path
        # hidden one branch down.
        acc: Dict[str, Any] = {
            "op_types": op_types,
            "custom_ops": custom_ops,
            "external_data": external_data,
            "nodes": 0,
            "subgraphs": 0,
        }

        graph_blob = pb.get_bytes(model, _ONNX_MODEL_GRAPH)
        if graph_blob:
            graph = pb.parse_message(graph_blob)
            graph_name = pb.get_str(graph, _ONNX_GRAPH_NAME)
            DeepScanner._walk_onnx_graph_message(graph, acc, 0)
        node_count = acc["nodes"]
        subgraph_count = acc["subgraphs"]

        return {
            "subgraph_count": subgraph_count,
            "ir_version": pb.get_int(model, _ONNX_MODEL_IR_VERSION),
            "producer_name": pb.get_str(model, _ONNX_MODEL_PRODUCER_NAME),
            "producer_version": pb.get_str(model, _ONNX_MODEL_PRODUCER_VERSION),
            "model_domain": pb.get_str(model, _ONNX_MODEL_DOMAIN),
            "model_version": pb.get_int(model, _ONNX_MODEL_VERSION),
            "graph_name": graph_name,
            "opsets": opsets,
            "op_types": op_types,
            "custom_ops": custom_ops,
            "external_data": external_data,
            "node_count": node_count,
        }

    def _parse_onnx_model_streamed(self, f, local_path: Path):
        """Re-walk a large ONNX file, seeking past bulk tensor payloads.

        Only sub-messages below ``ONNX_MAX_SUBMESSAGE_BYTES`` are read. That is
        safe for the questions being asked: a tensor that points at *external*
        data carries no inline payload and is therefore tiny, and nodes are
        small by construction. What gets skipped is inline weight data, which
        holds nothing this scan is looking for.

        Returns ``None`` if the file does not walk cleanly, so the caller keeps
        the buffered result rather than losing findings it already had.
        """
        try:
            size = local_path.stat().st_size

            def read_at(offset: int, count: int) -> bytes:
                f.seek(offset)
                return f.read(count)

            graph_range = None
            header_fields: Dict[int, List[Any]] = {}
            for fn, wt, off, length in pb.iter_stream_fields(read_at, 0, size):
                if fn == _ONNX_MODEL_GRAPH and wt == pb.WIRE_LENGTH_DELIMITED:
                    graph_range = (off, off + length)
                elif length <= ONNX_MAX_SUBMESSAGE_BYTES:
                    header_fields.setdefault(fn, []).append(
                        read_at(off, length) if wt == pb.WIRE_LENGTH_DELIMITED
                        else pb.read_varint(read_at(off, length), 0)[0]
                    )
            if graph_range is None:
                return None

            acc: Dict[str, Any] = {
                "op_types": [],
                "custom_ops": [],
                "external_data": [],
                "nodes": 0,
                "subgraphs": 0,
            }
            graph_name = None

            for fn, wt, off, length in pb.iter_stream_fields(read_at, *graph_range):
                if wt != pb.WIRE_LENGTH_DELIMITED:
                    continue
                if fn == _ONNX_GRAPH_NAME and graph_name is None:
                    graph_name = read_at(off, length).decode("utf-8", "replace")
                elif fn == _ONNX_GRAPH_NODE and length <= ONNX_MAX_SUBMESSAGE_BYTES:
                    acc["nodes"] += 1
                    node = pb.parse_message(read_at(off, length))
                    op_type = pb.get_str(node, _ONNX_NODE_OP_TYPE)
                    domain = pb.get_str(node, _ONNX_NODE_DOMAIN) or ""
                    if (op_type and op_type not in acc["op_types"]
                            and len(acc["op_types"]) < ONNX_MAX_OP_TYPES):
                        acc["op_types"].append(op_type)
                    if onnx_domain_is_custom(domain):
                        acc["custom_ops"].append({"op_type": op_type, "domain": domain})
                    self._collect_onnx_node_payloads(node, acc, 0)
                elif fn == _ONNX_GRAPH_INITIALIZER and length <= ONNX_MAX_SUBMESSAGE_BYTES:
                    # A tensor with external data has no inline payload, so
                    # anything large here is weights and can be stepped over.
                    self._collect_onnx_external(
                        pb.parse_message(read_at(off, length)), acc["external_data"]
                    )

            op_types = acc["op_types"]
            custom_ops = acc["custom_ops"]
            external_data = acc["external_data"]
            counters = {"nodes": acc["nodes"], "subgraphs": acc["subgraphs"]}

            model = pb.parse_message(read_at(0, min(size, 4096)))
            return {
                "ir_version": pb.get_int(model, _ONNX_MODEL_IR_VERSION),
                "producer_name": pb.get_str(model, _ONNX_MODEL_PRODUCER_NAME),
                "producer_version": pb.get_str(model, _ONNX_MODEL_PRODUCER_VERSION),
                "model_domain": pb.get_str(model, _ONNX_MODEL_DOMAIN),
                "model_version": pb.get_int(model, _ONNX_MODEL_VERSION),
                "graph_name": graph_name,
                "opsets": [
                    {
                        "domain": pb.get_str(e, _ONNX_OPSET_DOMAIN) or "",
                        "version": pb.get_int(e, _ONNX_OPSET_VERSION),
                    }
                    for e in pb.get_messages(model, _ONNX_MODEL_OPSET_IMPORT)
                ],
                "op_types": op_types,
                "custom_ops": custom_ops,
                "external_data": external_data,
                "node_count": counters["nodes"],
                "subgraph_count": counters["subgraphs"],
            }
        except Exception:
            return None

    @staticmethod
    def _collect_onnx_external(tensor, external_data: List[Dict[str, Any]]) -> None:
        if pb.get_int(tensor, _ONNX_TENSOR_DATA_LOCATION) != _ONNX_DATA_LOCATION_EXTERNAL:
            return
        if len(external_data) >= ONNX_MAX_EXTERNAL_ENTRIES:
            return
        entry: Dict[str, Any] = {"tensor": pb.get_str(tensor, _ONNX_TENSOR_NAME)}
        for kv in pb.get_messages(tensor, _ONNX_TENSOR_EXTERNAL_DATA):
            key = pb.get_str(kv, _ONNX_STRING_ENTRY_KEY)
            if key:
                entry[key] = pb.get_str(kv, _ONNX_STRING_ENTRY_VALUE)
        external_data.append(entry)

    @classmethod
    def _collect_onnx_node_payloads(cls, node, acc: Dict[str, Any], depth: int) -> None:
        """Inspect a node's attributes: nested graphs, and tensors."""
        for attribute in pb.get_messages(node, _ONNX_NODE_ATTRIBUTE):
            for field in (_ONNX_ATTRIBUTE_GRAPH, _ONNX_ATTRIBUTE_GRAPHS):
                for nested in attribute.get(field, []):
                    if isinstance(nested, bytes):
                        acc["subgraphs"] += 1
                        cls._walk_onnx_graph_message(
                            pb.parse_message(nested), acc, depth + 1
                        )
            for field in (_ONNX_ATTRIBUTE_TENSOR, _ONNX_ATTRIBUTE_TENSORS):
                for blob_bytes in attribute.get(field, []):
                    if isinstance(blob_bytes, bytes):
                        cls._collect_onnx_external(
                            pb.parse_message(blob_bytes), acc["external_data"]
                        )

    @classmethod
    def _walk_onnx_graph_message(cls, graph, acc: Dict[str, Any], depth: int) -> None:
        """Walk a buffered graph message, recursing into nested graphs."""
        if depth > ONNX_MAX_GRAPH_DEPTH:
            return
        for node in pb.get_messages(graph, _ONNX_GRAPH_NODE):
            acc["nodes"] += 1
            op_type = pb.get_str(node, _ONNX_NODE_OP_TYPE)
            domain = pb.get_str(node, _ONNX_NODE_DOMAIN) or ""
            if (op_type and op_type not in acc["op_types"]
                    and len(acc["op_types"]) < ONNX_MAX_OP_TYPES):
                acc["op_types"].append(op_type)
            if onnx_domain_is_custom(domain):
                acc["custom_ops"].append({"op_type": op_type, "domain": domain})
            cls._collect_onnx_node_payloads(node, acc, depth)
        for tensor in pb.get_messages(graph, _ONNX_GRAPH_INITIALIZER):
            cls._collect_onnx_external(tensor, acc["external_data"])

    @staticmethod
    def _onnx_risk_label(threats: List[str]) -> str:
        """Map ONNX findings to a risk label.

        Only an external-data path that leaves the model directory is CRITICAL:
        that one turns loading the model into a read of a file the author chose.
        A custom operator, or external data that stays put, is a MEDIUM — real
        signal, but it needs something else (a registered op library, a swapped
        weights file) before it becomes an attack.

        The substring in the returned label is what the CLI's exit-code check
        reads, so the wording is load-bearing: "CRITICAL" exits 2, "MEDIUM"
        does not. ("HIGH" is deliberately unused — it is not one of the levels
        the exit-code mapping recognises.)
        """
        escapes = [t for t in threats if t.startswith("ONNX_EXTERNAL_DATA_ESCAPE:")]
        if escapes:
            paths = ", ".join(t.split(": ", 1)[1] for t in escapes)
            return f"CRITICAL (ONNX External Data Escapes Model Directory: {paths})"

        custom = sum(1 for t in threats if t.startswith("ONNX_CUSTOM_OP:"))
        external = sum(1 for t in threats if t.startswith("ONNX_EXTERNAL_DATA:"))
        parts = []
        if custom:
            parts.append(f"{custom} custom operator(s)")
        if external:
            parts.append(f"{external} external tensor(s)")
        if parts:
            return f"MEDIUM (ONNX: {'; '.join(parts)})"
        return "LOW"

    def _inspect_onnx(self, source, name: str | None = None, is_remote: bool = False) -> Dict[str, Any]:
        """Statically inspects an ONNX model's protobuf structure.

        No ONNX runtime is loaded and the graph is never executed — the file is
        walked as protobuf to recover its metadata and to surface two signals:
        operators outside the standard domains, and tensors stored outside the
        model file. Only the head of the file is read, so a multi-gigabyte model
        costs the same as a small one.
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
            "framework": "ONNX",
            "risk_level": "LOW",
            "license": "Unknown",  # ONNX has no standard license field
            "legal_status": "UNKNOWN",
            "hash": "remote_unhashed" if is_remote else self._calculate_hash(local_path),
            "details": {},
        }

        f = None
        try:
            f = open(local_path, "rb") if local_path else source
            budget = ONNX_MAX_SCAN_BYTES if local_path else ONNX_MAX_REMOTE_SCAN_BYTES
            f.seek(0)
            blob = f.read(budget)

            parsed = self._parse_onnx_model(blob)

            # ONNX stores weights inline, so a real model is far larger than any
            # window worth buffering — and a single big tensor early in the
            # graph would otherwise hide every external-data entry behind it.
            # For a local file, seeking is free, so the graph is re-walked by
            # stepping over bulk payloads instead of reading them.
            truncated = len(blob) >= budget
            if truncated and local_path is not None:
                streamed = self._parse_onnx_model_streamed(f, local_path)
                if streamed is not None:
                    parsed = streamed
                    truncated = False

            threats = scan_onnx_model(parsed)

            # A .onnx file has no magic number, so "did this parse as ONNX?" is
            # judged by whether the walk recovered anything a ModelProto has.
            looks_like_onnx = any((
                parsed["ir_version"] is not None,
                parsed["producer_name"],
                parsed["graph_name"],
                parsed["opsets"],
                parsed["node_count"],
            ))

            meta["details"] = {
                "ir_version": parsed["ir_version"],
                "producer_name": parsed["producer_name"],
                "producer_version": parsed["producer_version"],
                "graph_name": parsed["graph_name"],
                "opsets": parsed["opsets"],
                "op_types": parsed["op_types"],
                "custom_ops": parsed["custom_ops"],
                "external_data": parsed["external_data"],
                "node_count": parsed["node_count"],
                "subgraph_count": parsed.get("subgraph_count", 0),
                "threats": threats,
                "parsed": looks_like_onnx,
                "truncated": len(blob) >= budget,
            }

            if not looks_like_onnx:
                meta["risk_level"] = "UNKNOWN (Unparsable ONNX)"
            else:
                meta["risk_level"] = self._onnx_risk_label(threats)
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
