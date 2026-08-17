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
from aisbom import pickle_containers as pc
from aisbom import protobuf_reader as pb
from aisbom.safety import (
    PICKLE_SCAN_INCOMPLETE,
    _threat_kind as _jinja_threat_kind,
    jinja_threats_are_critical,
    looks_like_pickle_stream,
    onnx_domain_is_custom,
    scan_jinja_template,
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

# The serialization formats of everyday scientific Python. Every one of them is
# a pickle stream under a wrapper, so each carries the same arbitrary-code
# -execution risk as a `.pt` — and generic SBOM tooling opens none of them.
#
# `.pkl`/`.pickle` are here because the bare pickle was never discovered at all:
# the README documents `aisbom scan model.pkl --strict`, and until now that
# scanned nothing and exited 0.
PICKLE_VARIANT_EXTENSIONS = {'.pkl', '.pickle', '.joblib', '.dill', '.npy', '.npz'}

# Local reads get the same budget as the other formats; a remote read pays one
# HTTP Range request per call and gets the tighter one.
PICKLE_VARIANT_MAX_SCAN_BYTES = 16 * 1024 * 1024
PICKLE_VARIANT_MAX_REMOTE_SCAN_BYTES = 2 * 1024 * 1024

# How many members of an `.npz` are opened. An archive is attacker-controlled,
# so the member count is bounded like every other declared length.
NPZ_MAX_MEMBERS = 512

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
# --- GGUF metadata value types ---
# Every scalar type with its struct format and byte width. Two of these matter
# more than they look: BOOL is one byte (not eight), and FLOAT32 is four. Both
# appear in essentially every real model — `add_bos_token` and the attention
# epsilon — so getting either width wrong desynchronises the whole key-value
# walk and silently loses every field after it.
GGUF_SCALAR_TYPES = {
    0: ('<B', 1),   # UINT8
    1: ('<b', 1),   # INT8
    2: ('<H', 2),   # UINT16
    3: ('<h', 2),   # INT16
    4: ('<I', 4),   # UINT32
    5: ('<i', 4),   # INT32
    6: ('<f', 4),   # FLOAT32
    7: ('<?', 1),   # BOOL
    10: ('<Q', 8),  # UINT64
    11: ('<q', 8),  # INT64
    12: ('<d', 8),  # FLOAT64
}
GGUF_TYPE_STRING = 8
GGUF_TYPE_ARRAY = 9

# The chat template lives here, after the tokenizer arrays.
GGUF_CHAT_TEMPLATE_KEY = "tokenizer.chat_template"

# How much of a GGUF file is read to cover its metadata block. The metadata sits
# at the head, but the token/merge arrays in front of the chat template run to
# megabytes on a large vocabulary, so the window has to clear them.
GGUF_METADATA_WINDOW = 16 * 1024 * 1024

# Remote reads are HTTP Range requests, so a remote scan starts with a small
# window and widens once if the metadata block did not fit. Two requests at
# worst, against one request per field if the stream were walked directly.
GGUF_REMOTE_FIRST_WINDOW = 1 * 1024 * 1024
GGUF_REMOTE_MAX_WINDOW = 16 * 1024 * 1024

# Array contents are never retained — only the element type and count — but a
# declared count still has to be sanity-bounded before it is trusted.
GGUF_MAX_ARRAY_ELEMENTS = 50_000_000
# How much of a bare (non-ZIP) candidate is disassembled. The same bound the
# ZIP path already uses for its pickle member.
PICKLE_MAX_SCAN_BYTES = 10 * 1024 * 1024

# Container formats that are not PyTorch's ZIP. A model wearing a .pt extension
# packed with one of these is the nullifAI shape: the alternative container kept
# scanners from opening the file at all while the model still loaded. Repacking
# a model in 7z is not something a normal toolchain does, so the container
# itself is the signal — the payload inside stays compressed and unread.
NONSTANDARD_CONTAINER_MAGICS = (
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"BZh", "bzip2"),
    (b"\x1f\x8b", "gzip"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x89LZO", "lzo"),
)

# Simple blocklist for license keywords that imply legal risk in commercial software
RESTRICTED_LICENSES = ["non-commercial", "cc-by-nc", "agpl", "commons clause"]

from aisbom.remote import RemoteStream, resolve_huggingface_repo


class _GGUFTruncated(Exception):
    """The GGUF metadata block ran past the end of the buffer we read."""


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
                    elif ext in PICKLE_VARIANT_EXTENSIONS:
                        with RemoteStream(url) as stream:
                            self.artifacts.append(
                                self._inspect_pickle_variant(stream, Path(url).name, is_remote=True)
                            )
                except Exception as e:
                    self._record_fetch_error(url, e)
                    continue
        else:
            root = Path(self.root_path)
            # Path.rglob only ever yields the *contents* of a directory, so
            # before #125 a file target (or a path that did not exist) walked
            # nothing, recorded no error, and reported a clean scan — a
            # malicious .pt named directly on the command line exited 0.
            # Each local target shape is now handled explicitly.
            if root.is_dir():
                for full_path in root.rglob("*"):
                    if full_path.is_file():
                        # A tree legitimately contains non-model files; an
                        # unclaimed file here is normal and stays silent.
                        self._dispatch_local_file(full_path)
            elif root.is_file():
                # A single file is a first-class target: README documents
                # `aisbom scan model.pkl --strict` and `aisbom scan model.pt
                # --lint`. Unlike the walk above, the user named this exact
                # file, so an inspector declining it is a failed instruction
                # rather than an empty result.
                if not self._dispatch_local_file(root):
                    self._record_target_error(
                        str(root),
                        f"Unsupported file type '{root.suffix or root.name}' — no scanner claimed this file",
                    )
            else:
                # Missing, a broken symlink, or not a regular file (fifo,
                # socket, device). is_dir()/is_file() both follow symlinks,
                # so a dangling link lands here and reads as missing.
                self._record_target_error(
                    str(root),
                    "No such file or directory"
                    if not root.exists()
                    else "Not a regular file or directory",
                )

        return {"artifacts": self.artifacts, "dependencies": self.dependencies, "errors": self.errors}

    def _resolve_remote_targets(self, target: str):
        if target.startswith("hf://"):
            return resolve_huggingface_repo(target)
        if target.startswith("http://") or target.startswith("https://"):
            return [target]
        return []

    def _dispatch_local_file(self, full_path: Path) -> bool:
        """Inspect one local file by extension.

        Shared by the directory walk and the single-file target path so the
        two cannot drift apart (#125). Returns True if an inspector claimed
        the file; callers decide whether declining it is noteworthy.
        """
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
        elif ext in PICKLE_VARIANT_EXTENSIONS:
            self.artifacts.append(self._inspect_pickle_variant(full_path))
        elif full_path.name == REQUIREMENTS_FILENAME:
            self._parse_requirements(full_path)
        else:
            return False
        return True

    def _record_target_error(self, target: str, message: str) -> None:
        """Record an unusable scan target as a structured, non-fatal error.

        Lands in results['errors'] so the CLI's `errors → exit 1` path fires.
        Tagged `target_error` to keep it out of both the fetch-failure
        rendering (which expects a live exception) and the "Could not parse"
        list — the target was never readable enough to parse. An empty
        directory is *not* this: that is a legitimate clean scan.
        """
        self.errors.append({
            "file": target,
            "error": message,
            "target_error": True,
        })

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

    @staticmethod
    def _identify_container(head: bytes) -> str | None:
        """Name the archive format ``head`` begins with, if it is not ZIP."""
        for magic, label in NONSTANDARD_CONTAINER_MAGICS:
            if head.startswith(magic):
                return label
        return None

    @staticmethod
    def _looks_like_text(content: bytes) -> bool:
        """True if the first kilobyte decodes as UTF-8 and is mostly printable."""
        try:
            text = content[:1024].decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            return False
        if not text:
            return False
        printable = sum(ch.isprintable() for ch in text)
        return printable / len(text) > 0.9

    def _apply_lint(self, meta: Dict[str, Any], content: bytes) -> None:
        """Run the migration linter over a pickle stream, if linting is on."""
        if not self.lint:
            return
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

    @staticmethod
    def _raw_member_bytes(stream, info) -> bytes | None:
        """Read a zip member from its local header, skipping every check.

        Bypasses the CRC validation and the directory/header name agreement
        that ``ZipFile.open`` enforces. Both are evasions precisely because the
        loaders that matter do not enforce them — PyTorch reads these archives
        with its own reader — so refusing to look at the bytes hides a payload
        that would still run. STORED members are returned as-is; DEFLATED ones
        are inflated as a raw stream, which needs no CRC and no trailer.
        """
        try:
            stream.seek(info.header_offset)
            header = stream.read(30)
            if len(header) < 30 or header[:4] != b"PK\x03\x04":
                return None
            name_len = struct.unpack("<H", header[26:28])[0]
            extra_len = struct.unpack("<H", header[28:30])[0]
            stream.seek(info.header_offset + 30 + name_len + extra_len)

            if info.compress_type == zipfile.ZIP_STORED:
                size = info.compress_size or info.file_size
                return stream.read(min(size or PICKLE_MAX_SCAN_BYTES, PICKLE_MAX_SCAN_BYTES))

            if info.compress_type == zipfile.ZIP_DEFLATED:
                # A tampered header can leave compress_size at zero, so read a
                # bounded window and let the decompressor stop at the stream end.
                raw = stream.read(min(info.compress_size or PICKLE_MAX_SCAN_BYTES,
                                      PICKLE_MAX_SCAN_BYTES))
                # -15 selects a raw deflate stream: no zlib wrapper, no checksum.
                return zlib.decompressobj(-15).decompress(raw, PICKLE_MAX_SCAN_BYTES)
        except Exception:
            return None
        return None

    def _read_zip_member(self, z, member: str, stream):
        """Return ``(bytes, note)`` for a zip member, working around corruption.

        A member that will not open cleanly is not the end of the inquiry: the
        bytes are read straight from the local header instead, so tampering
        with a CRC or with a filename does not buy silence.
        """
        try:
            with z.open(member) as f:
                return f.read(PICKLE_MAX_SCAN_BYTES), None
        except Exception as exc:
            try:
                info = z.getinfo(member)
            except Exception:
                return None, str(exc)
            data = self._raw_member_bytes(stream, info)
            if data:
                return data, f"container integrity check failed, read raw member: {exc}"
            return None, str(exc)

    @staticmethod
    def _split_scan_incomplete(threats):
        """Separate the "did not finish" marker from real findings.

        It is not a threat and must not be reported as one — but it must also
        not vanish, or an unfinished scan would read as a clean one.
        """
        incomplete = PICKLE_SCAN_INCOMPLETE in (threats or [])
        return [t for t in (threats or []) if t != PICKLE_SCAN_INCOMPLETE], incomplete

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
                    content = None
                    if pickle_files:
                        main_pkl = pickle_files[0]
                        content, read_note = self._read_zip_member(z, main_pkl, stream)
                        if read_note:
                            meta["details"]["member_read"] = read_note
                        if content is not None:
                            threats = scan_pickle_stream(content, strict_mode=self.strict_mode)
                            self._apply_lint(meta, content)

                    threats, incomplete = self._split_scan_incomplete(threats)
                    if threats:
                        meta["risk_level"] = f"CRITICAL (RCE Detected: {', '.join(threats)})"
                    elif incomplete:
                        meta["details"]["scan_incomplete"] = True
                        meta["risk_level"] = "MEDIUM (Pickle Scan Incomplete)"
                    elif content is None and pickle_files:
                        # The member is there but could not be read at all. A
                        # loader that does not verify integrity the way we do
                        # would still run it, so this is not a clean bill.
                        meta["risk_level"] = "MEDIUM (Unreadable Pickle Member)"
                    elif pickle_files:
                        meta["risk_level"] = "MEDIUM (Pickle Present)"
                    else:
                        meta["risk_level"] = "LOW"

                    meta["details"].update({"internal_files": len(files), "threats": threats})
            else:
                stream.seek(0)
                content = stream.read(PICKLE_MAX_SCAN_BYTES)
                if not isinstance(content, bytes):
                    content = bytes(content)

                container = self._identify_container(content)
                if container:
                    # Deliberately not unpacked: doing so would put a 7z
                    # implementation and its native dependencies into every
                    # install and every standalone binary. The container choice
                    # is itself the finding, and it is named rather than
                    # reported as a generic unreadable blob.
                    meta["details"]["container_format"] = container
                    meta["details"]["threats"] = []
                    meta["risk_level"] = (
                        f"CRITICAL (Non-Standard Container: {container})"
                    )
                else:
                    # Disassemble *before* deciding what the file is. Judging
                    # by shape first is what let a printable protocol-0 pickle
                    # pass as a text config file and be reported safe.
                    threats = scan_pickle_stream(content, strict_mode=self.strict_mode)
                    threats, incomplete = self._split_scan_incomplete(threats)
                    meta["details"]["threats"] = threats
                    if incomplete:
                        meta["details"]["scan_incomplete"] = True
                    self._apply_lint(meta, content)

                    if threats:
                        meta["risk_level"] = f"CRITICAL (RCE Detected: {', '.join(threats)})"
                    elif incomplete:
                        meta["risk_level"] = "MEDIUM (Pickle Scan Incomplete)"
                    elif looks_like_pickle_stream(content):
                        meta["risk_level"] = "MEDIUM (Pickle Present)"
                    elif self._looks_like_text(content):
                        meta["risk_level"] = "LOW"
                        meta["type"] = "configuration"
                        meta["framework"] = "Python Path Config"
                    else:
                        # Binary, not a parsable pickle, not a known container.
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

    def _npy_member_threats(self, blob: bytes, details: Dict[str, Any]):
        """Scan one `.npy` buffer; return ``(threats, carries_pickle)``.

        The data section is disassembled whatever the declared dtype says. The
        header is an attacker-supplied field, so using it to decide *whether* to
        look would make `descr: '<f8'` a one-line way to hide a pickle.

        Whether the file *carries* one is a separate question, answered from the
        bytes: an array of ordinary numbers is a real, fully-read file with no
        pickle in it, and reporting it as "pickle present" would be noise on
        every checkpoint directory that holds one.
        """
        section, header = pc.npy_data_section(blob)
        if header is not None:
            details["npy_version"] = header["version"]
            details["dtype"] = str(header["descr"]) if header["descr"] is not None else None
            details["object_dtype"] = header["object_dtype"]
            if header["shape"] is not None:
                details["shape"] = str(header["shape"])
        if section is None:
            # Not a `.npy` after all — scan the whole buffer as a pickle rather
            # than declining, since the extension is not what decides here.
            section = blob
        threats = scan_pickle_stream(section, strict_mode=self.strict_mode)
        carries_pickle = bool(
            threats
            or (header or {}).get("object_dtype")
            or looks_like_pickle_stream(section)
        )
        return threats, carries_pickle

    def _inspect_pickle_variant(self, source, name: str | None = None,
                                is_remote: bool = False) -> Dict[str, Any]:
        """Scan the pickle-bearing serialization formats that are not `.pt`.

        joblib (plain, compressed, and the legacy `ZF` container), dill, bare
        `.pkl`, and numpy's `.npy`/`.npz` object arrays all reduce to the same
        question — what does the pickle stream inside import — so they share one
        inspector and the disassembler the rest of the scanner uses.

        What the file *is* comes from its bytes, not its extension. A `.npy`
        holding a bare pickle is reported as a pickle, and a `.joblib` that is
        really a zip is opened as one, because the attacker picks the extension.
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
            "framework": "Pickle",
            "risk_level": "UNKNOWN",
            "license": "Unknown",  # none of these containers carry license metadata
            "legal_status": "UNKNOWN",
            "hash": "remote_unhashed" if is_remote else self._calculate_hash(local_path),
            "details": {},
        }
        details = meta["details"]

        stream = None
        try:
            stream = open(local_path, "rb") if local_path else source
            budget = (PICKLE_VARIANT_MAX_SCAN_BYTES if local_path
                      else PICKLE_VARIANT_MAX_REMOTE_SCAN_BYTES)

            threats: List[str] = []
            carries_pickle = False
            unreadable = None   # a container we could name but not open

            if zipfile.is_zipfile(stream):
                # `.npz` is a zip of `.npy` members. Compressed or stored, and
                # damaged either way, it goes through the same reader the
                # PyTorch path uses, so tampering with a CRC or a member name
                # does not buy silence here either.
                meta["framework"] = "NumPy"
                details["container"] = "npz"
                stream.seek(0)
                with zipfile.ZipFile(stream, "r") as z:
                    members = z.namelist()[:NPZ_MAX_MEMBERS]
                    details["internal_files"] = len(z.namelist())
                    read_notes = []
                    for member in members:
                        blob, note = self._read_zip_member(z, member, stream)
                        if note:
                            read_notes.append(f"{member}: {note}")
                        if blob is None:
                            unreadable = unreadable or "npz member"
                            continue
                        member_threats, member_pickle = self._npy_member_threats(blob, details)
                        threats.extend(member_threats)
                        carries_pickle = carries_pickle or member_pickle
                    if read_notes:
                        details["member_read"] = read_notes
            else:
                stream.seek(0)
                blob = stream.read(budget)
                if not isinstance(blob, bytes):
                    blob = bytes(blob)
                details["truncated"] = len(blob) >= budget

                if blob.startswith(pc.NPY_MAGIC):
                    meta["framework"] = "NumPy"
                    details["container"] = "npy"
                    threats, carries_pickle = self._npy_member_threats(blob, details)
                else:
                    wrapper = pc.describe_container(blob)
                    if wrapper["compression"]:
                        meta["framework"] = "Joblib"
                        details["container"] = wrapper["compression"]
                        details["compression"] = wrapper["compression"]
                        if wrapper["payload"] is None:
                            # Named, not opened. lz4 and zstd are the joblib
                            # codecs with no standard-library decompressor, and
                            # pulling one in would put it into every install and
                            # every standalone binary. Reporting the limit is
                            # the honest answer; claiming a clean scan is not.
                            unreadable = wrapper["compression"]
                        else:
                            carries_pickle = True
                            threats = scan_pickle_stream(
                                wrapper["payload"], strict_mode=self.strict_mode
                            )
                            details["decompressed_bytes"] = len(wrapper["payload"])
                    else:
                        details["container"] = "bare"
                        threats = scan_pickle_stream(blob, strict_mode=self.strict_mode)
                        carries_pickle = looks_like_pickle_stream(blob) or bool(threats)
                        self._apply_lint(meta, blob)

            threats, incomplete = self._split_scan_incomplete(threats)
            # De-duplicate across `.npz` members while keeping the order, so one
            # payload repeated in every array is reported once.
            threats = list(dict.fromkeys(threats))
            details["threats"] = threats
            if any(t.startswith("dill.") or t.startswith("UNSAFE_IMPORT: dill.")
                   for t in threats):
                # dill puts a marshalled code object in the stream and rebuilds
                # it on load. Worth naming: "RCE detected" reads very
                # differently once you know the file is a serialized function.
                details["dill_code_objects"] = True

            if threats:
                meta["risk_level"] = f"CRITICAL (RCE Detected: {', '.join(threats)})"
            elif incomplete:
                details["scan_incomplete"] = True
                meta["risk_level"] = "MEDIUM (Pickle Scan Incomplete)"
            elif unreadable:
                meta["risk_level"] = f"MEDIUM (Unscanned Container: {unreadable})"
            elif carries_pickle:
                meta["risk_level"] = "MEDIUM (Pickle Present)"
            else:
                # A `.npy` of ordinary numbers reaches here: a real file, fully
                # read, carrying no pickle at all.
                meta["risk_level"] = "LOW"
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

    @staticmethod
    def _read_gguf_window(f, is_remote: bool) -> bytes:
        """Read enough of the file to cover its metadata block.

        Local files get one generous read. A remote scan starts small and widens
        once, because the chat template sits behind the tokenizer arrays and a
        window that stops short of them would systematically miss it — while
        always pulling the full window would make every remote GGUF scan
        expensive. Each attempt is a single Range request.
        """
        f.seek(0)
        if not is_remote:
            return f.read(GGUF_METADATA_WINDOW)

        buf = f.read(GGUF_REMOTE_FIRST_WINDOW)
        if len(buf) < GGUF_REMOTE_FIRST_WINDOW:
            return buf  # the whole file already fits

        probe = DeepScanner._parse_gguf_metadata(buf)
        if not probe["truncated"]:
            return buf

        f.seek(0)
        return f.read(GGUF_REMOTE_MAX_WINDOW)

    @staticmethod
    def _parse_gguf_metadata(buf: bytes) -> Dict[str, Any]:
        """Walk a GGUF metadata block into ``{key: value}``.

        Operates on the buffer rather than the stream, and treats running out of
        buffer as an ordinary outcome: ``truncated`` says the block did not fit,
        and the keys read so far are still returned. Array *contents* are never
        retained — a token array holds hundreds of thousands of strings — only
        the element type and count, but the bytes are still stepped over exactly
        so that every key after an array is read from the right offset.

        Every declared length comes from the file, so each one is checked
        against the bytes actually present before being used.
        """
        result: Dict[str, Any] = {
            "values": {},
            "metadata_keys": [],
            "kv_count": 0,
            "pairs_read": 0,
            "truncated": False,
            "version": None,
        }

        # Magic (4) | version (4) | tensor count (8) | kv count (8)
        if len(buf) < 24:
            result["truncated"] = True
            return result

        result["version"] = struct.unpack('<I', buf[4:8])[0]
        kv_count = struct.unpack('<Q', buf[16:24])[0]
        result["kv_count"] = kv_count

        pos = 24

        def read_scalar(offset: int, val_type: int):
            fmt, width = GGUF_SCALAR_TYPES[val_type]
            if offset + width > len(buf):
                raise _GGUFTruncated()
            return struct.unpack(fmt, buf[offset:offset + width])[0], offset + width

        def read_string(offset: int):
            if offset + 8 > len(buf):
                raise _GGUFTruncated()
            length = struct.unpack('<Q', buf[offset:offset + 8])[0]
            offset += 8
            if length > len(buf) - offset:
                raise _GGUFTruncated()
            return buf[offset:offset + length].decode('utf-8', errors='replace'), offset + length

        def skip_value(offset: int, val_type: int, depth: int = 0):
            """Step over one value, returning the offset just past it."""
            if val_type in GGUF_SCALAR_TYPES:
                _value, offset = read_scalar(offset, val_type)
                return offset
            if val_type == GGUF_TYPE_STRING:
                _value, offset = read_string(offset)
                return offset
            if val_type == GGUF_TYPE_ARRAY:
                # Arrays may nest; bound the recursion rather than trusting the
                # file's structure.
                if depth > 8:
                    raise _GGUFTruncated()
                if offset + 12 > len(buf):
                    raise _GGUFTruncated()
                elem_type = struct.unpack('<I', buf[offset:offset + 4])[0]
                count = struct.unpack('<Q', buf[offset + 4:offset + 12])[0]
                offset += 12
                if count > GGUF_MAX_ARRAY_ELEMENTS:
                    raise _GGUFTruncated()
                if elem_type in GGUF_SCALAR_TYPES:
                    # Fixed-width elements step in one jump.
                    width = GGUF_SCALAR_TYPES[elem_type][1]
                    end = offset + width * count
                    if end > len(buf):
                        raise _GGUFTruncated()
                    return end
                for _ in range(count):
                    offset = skip_value(offset, elem_type, depth + 1)
                return offset
            # An unknown type means the framing is lost; there is no safe width
            # to skip, so stop rather than guess and read garbage as keys.
            raise _GGUFTruncated()

        for _ in range(kv_count):
            try:
                key, pos = read_string(pos)
                if pos + 4 > len(buf):
                    raise _GGUFTruncated()
                val_type = struct.unpack('<I', buf[pos:pos + 4])[0]
                pos += 4

                if val_type == GGUF_TYPE_STRING:
                    value, pos = read_string(pos)
                    result["values"][key] = value
                elif val_type in GGUF_SCALAR_TYPES:
                    value, pos = read_scalar(pos, val_type)
                    result["values"][key] = value
                elif val_type == GGUF_TYPE_ARRAY:
                    before = pos
                    pos = skip_value(pos, GGUF_TYPE_ARRAY)
                    elem_type = struct.unpack('<I', buf[before:before + 4])[0]
                    count = struct.unpack('<Q', buf[before + 4:before + 12])[0]
                    result["values"][key] = {
                        "array_type": elem_type,
                        "array_count": count,
                    }
                else:
                    raise _GGUFTruncated()

                result["metadata_keys"].append(key)
                result["pairs_read"] += 1
            except (_GGUFTruncated, struct.error):
                result["truncated"] = True
                return result

        return result

    @staticmethod
    def _gguf_template_risk_label(threats: List[str]) -> str:
        """Summarize chat-template findings for the risk column.

        Full findings stay in ``details``; this stays short because the terminal
        table truncates. "CRITICAL" and "MEDIUM" are the substrings the CLI's
        exit-code mapping reads, so the wording is load-bearing.
        """
        # Findings may carry a leading "[template key] " tag on a model that
        # ships several templates; severity does not depend on which one.
        kinds = [_jinja_threat_kind(t) for t in threats]
        escapes = [k.split(": ", 1)[-1] for k in kinds if k.startswith("JINJA_SANDBOX_ESCAPE:")]
        calls = [k.split(": ", 1)[-1] for k in kinds if k.startswith("JINJA_DANGEROUS_CALL:")]

        if jinja_threats_are_critical(threats):
            named = ", ".join((escapes + calls)[:3]) or "sandbox escape"
            return f"CRITICAL (Chat Template Code Execution: {named})"
        return f"MEDIUM (Chat Template: {len(threats)} anomalous construct(s))"

    def _inspect_gguf(self, source, name: str | None = None, is_remote: bool = False) -> Dict[str, Any]:
        """
        Parses GGUF header to extract metadata/licenses and inspect the
        embedded Jinja chat template.

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

            # 2. Read the metadata block in as few reads as possible.
            # Walking the stream field by field costs one HTTP Range request per
            # field on a remote scan, so the block is buffered and parsed from
            # memory instead.
            buf = self._read_gguf_window(f, is_remote)
            parsed = self._parse_gguf_metadata(buf)
            kv = parsed["values"]
            metadata_keys = parsed["metadata_keys"]

            extracted_meta: Dict[str, Any] = {}

            # 3. License. GGUF usually stores it as "general.license".
            lic = "Unknown"
            for key in ("general.license", "license"):
                candidate = kv.get(key)
                if isinstance(candidate, str) and candidate:
                    lic = candidate
                    extracted_meta[key] = candidate
                    break
            meta["license"] = lic
            meta["legal_status"] = self._assess_legal_risk(lic)

            # 4. Structured per-format findings for CycloneDX properties.
            arch = kv.get("general.architecture")
            if not isinstance(arch, str):
                arch = next(
                    (v for k, v in kv.items() if "architecture" in k and isinstance(v, str)),
                    None,
                )
            extracted_meta["arch"] = arch
            extracted_meta["architecture"] = arch

            quantization = None
            for key, value in kv.items():
                if ("file_type" in key or "quantization" in key) and isinstance(value, int):
                    quantization = value
                    break
            if quantization is not None:
                extracted_meta["quantization"] = quantization

            extracted_meta["metadata_keys"] = metadata_keys
            extracted_meta["kv_count"] = parsed["kv_count"]
            extracted_meta["kv_parsed"] = parsed["pairs_read"]
            if parsed["truncated"]:
                extracted_meta["metadata_truncated"] = True

            # 5. The chat templates. These are Jinja templates that run on every
            # inference request, so they are inspected as strings — never
            # rendered. A model may ship several: llama.cpp stores named variants
            # under `tokenizer.chat_template.default`, `.tool_use` and friends,
            # so an exact-key lookup would miss every one of them.
            templates = {
                key: value
                for key, value in kv.items()
                if isinstance(value, str)
                and value
                and (
                    key == GGUF_CHAT_TEMPLATE_KEY
                    or key.startswith(GGUF_CHAT_TEMPLATE_KEY + ".")
                )
            }

            template_threats: List[str] = []
            template_digests = {}
            for key in sorted(templates):
                body = templates[key]
                template_digests[key] = hashlib.sha256(
                    body.encode("utf-8", errors="replace")
                ).hexdigest()
                for threat in scan_jinja_template(body):
                    # Name the variant when there is more than one, so a finding
                    # points at the template it came from.
                    tagged = threat if len(templates) == 1 else f"[{key}] {threat}"
                    if tagged not in template_threats:
                        template_threats.append(tagged)

            extracted_meta["chat_template_present"] = bool(templates)
            if templates:
                extracted_meta["chat_template_keys"] = sorted(templates)
                extracted_meta["chat_template_length"] = sum(
                    len(v) for v in templates.values()
                )
                extracted_meta["chat_template_sha256"] = template_digests[
                    sorted(templates)[0]
                ]
                extracted_meta["chat_template_digests"] = template_digests
            extracted_meta["chat_template_threats"] = template_threats

            meta["details"] = extracted_meta

            if template_threats:
                meta["risk_level"] = self._gguf_template_risk_label(template_threats)
            elif parsed["truncated"]:
                # The metadata block did not fit the window, so the chat
                # template may simply not have been reached. Reporting LOW here
                # would let a hostile template hide behind a large vocabulary
                # array; "we did not finish looking" is not "nothing is there".
                meta["risk_level"] = (
                    "MEDIUM (GGUF metadata incomplete: "
                    f"{parsed['pairs_read']}/{parsed['kv_count']} keys read)"
                )

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
