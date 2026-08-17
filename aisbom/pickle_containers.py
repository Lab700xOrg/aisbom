"""Locate the pickle stream inside the wrapper formats that carry one.

joblib, dill and numpy's object arrays are the everyday serialization formats of
scientific Python, and every one of them is pickle underneath — the same
arbitrary-code-execution risk as a bare ``.pkl``, wrapped in a container that
generic tooling does not open.

Nothing in this module imports joblib, numpy or dill. The compression is stdlib,
the ``.npy`` header is parsed by hand, and the payload is never unpickled — it is
handed back as bytes for the disassembler to read. That is deliberate twice over:
a scanner that loads the artifact to inspect it has already lost, and pulling a
scientific-Python stack into the package would put it into every install and
every standalone binary for the sake of reading bytes we can read ourselves.

Everything here is bounded. A container is an attacker-controlled input, so a
decompressor is never handed an unbounded output buffer and a declared header
length is never trusted far enough to allocate against it.
"""

from __future__ import annotations

import ast
import bz2
import lzma
import re
import zlib
from typing import Any, Dict, Tuple

# Fallback ceiling on any single decompressed payload: a compression bomb must
# cost the same as a large ordinary file, not more. The decompressors below are
# all incremental and take this as a `max_length`, so the bomb is never expanded
# in the first place.
#
# Callers pass their own budget — the scanner passes the same figure it used to
# read the file, so a remote scan that fetched 2MB does not then expand 16.
DECOMPRESS_MAX_BYTES = 16 * 1024 * 1024

# `.npy` declares its header length in the file. Cap what we will honour: the
# real headers are a few dozen bytes, and a declared length is exactly the field
# an attacker would inflate.
NPY_MAX_HEADER_BYTES = 1 * 1024 * 1024

NPY_MAGIC = b"\x93NUMPY"

# joblib's pre-0.10 container: a two-byte tag, a decimal length, then zlib data.
# Still readable today, and still a way to carry a pickle past a scanner that
# only knows the modern layout.
JOBLIB_ZFILE_MAGIC = b"ZF"

# Compression formats joblib writes that the standard library can open. The
# label is what gets reported, so it is the name a user would recognise.
_GZIP = "gzip"
_BZ2 = "bz2"
_LZMA = "lzma"
_XZ = "xz"
_ZLIB = "zlib"

SUPPORTED_COMPRESSION = (_ZLIB, _GZIP, _BZ2, _LZMA, _XZ)

# Formats joblib also supports whose decompressors are not in the standard
# library. Naming one is not the same as reading it — see `describe_container`.
_MAGIC_UNSUPPORTED = (
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
)

_MAGIC_SUPPORTED = (
    (b"\x1f\x8b", _GZIP),
    (b"BZh", _BZ2),
    (b"\xfd7zXZ\x00", _XZ),
    (b"\x5d\x00\x00", _LZMA),
)


def _looks_like_zlib(head: bytes) -> bool:
    """True for a zlib stream header (RFC 1950).

    zlib has no magic number, only a two-byte header with a checksum property:
    the low nibble of the first byte is the compression method (8 = deflate) and
    the 16-bit big-endian pair is a multiple of 31. Testing both is what keeps
    an ordinary binary file that happens to start with 0x78 from being mistaken
    for a compressed container.
    """
    if len(head) < 2:
        return False
    if head[0] & 0x0F != 8:
        return False
    return ((head[0] << 8) | head[1]) % 31 == 0


def detect_compression(head: bytes) -> Tuple[str | None, bool]:
    """Return ``(label, readable)`` for the compression ``head`` begins with.

    ``readable`` is False for a format we can name but not open, which is a
    materially different answer from "not compressed" and is reported as such
    rather than being quietly treated as a clean scan.
    """
    if not head:
        return None, False
    for magic, label in _MAGIC_SUPPORTED:
        if head.startswith(magic):
            return label, True
    for magic, label in _MAGIC_UNSUPPORTED:
        if head.startswith(magic):
            return label, False
    if _looks_like_zlib(head):
        return _ZLIB, True
    return None, False


def decompress(data: bytes, label: str, limit: int = DECOMPRESS_MAX_BYTES) -> Tuple[bytes | None, bool]:
    """Inflate ``data`` with the named codec; return ``(payload, complete)``.

    ``complete`` is False when the decompressor stopped before the end of the
    stream — because it hit ``limit``, or because the compressed data itself was
    cut short. That distinction has to reach the caller. A payload placed after
    a large compressible value would otherwise sit in the part we never expanded
    while the prefix scanned clean, and a cap nobody reports is somewhere to hide
    a payload rather than a safety measure.

    Returns whatever was recovered before an error when a stream is corrupt — a
    damaged tail must not discard the front, the same reasoning that makes a
    broken zip member worth reading anyway. ``(None, False)`` means nothing at
    all could be read.
    """
    if not data:
        return None, False
    try:
        if label == _ZLIB:
            engine = zlib.decompressobj()
        elif label == _GZIP:
            # 16 + MAX_WBITS selects the gzip wrapper.
            engine = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif label == _BZ2:
            engine = bz2.BZ2Decompressor()
        elif label in (_LZMA, _XZ):
            # FORMAT_AUTO reads both the `.xz` container and the older
            # standalone `.lzma` framing joblib still emits.
            engine = lzma.LZMADecompressor(format=lzma.FORMAT_AUTO)
        else:
            return None, False

        out = engine.decompress(data, limit)
        # Every one of these decompressors exposes `eof`, which is True only
        # once the stream's own end marker has been consumed.
        return (out or None), bool(getattr(engine, "eof", False))
    except Exception:
        return None, False


def unwrap_zfile(data: bytes, limit: int = DECOMPRESS_MAX_BYTES) -> Tuple[bytes | None, bool]:
    """Inflate joblib's legacy ``ZF`` container; return ``(payload, complete)``.

    Layout is the tag, a space-padded decimal length, then a zlib stream. The
    declared length is read past rather than trusted — the decompressor stops at
    the real end of the stream, so a lie in that field buys nothing.
    """
    if not data.startswith(JOBLIB_ZFILE_MAGIC):
        return None, False
    # The length field is fixed-width ASCII in every version that wrote it.
    body = data[len(JOBLIB_ZFILE_MAGIC):]
    match = re.match(rb"\s*([0-9]+)\s*", body[:32])
    start = match.end() if match else 0
    return decompress(body[start:], _ZLIB, limit)


def describe_container(data: bytes, limit: int = DECOMPRESS_MAX_BYTES) -> Dict[str, Any]:
    """Unwrap one layer of compression, if any, and say what was found.

    Returns a dict with ``compression`` (label or None), ``readable`` (whether
    we could open it), ``payload`` (the inner bytes, or None), and ``truncated``
    (whether the decompressor stopped short of the stream's end). An unreadable
    container yields a payload of None with the format still named, so the
    caller can report "we did not read these bytes" instead of "clean" — and a
    truncated one says so rather than passing off a prefix as the whole file.
    """
    result: Dict[str, Any] = {
        "compression": None, "readable": True, "payload": data, "truncated": False,
    }

    if data.startswith(JOBLIB_ZFILE_MAGIC):
        payload, complete = unwrap_zfile(data, limit)
        result.update(compression="zfile", readable=payload is not None,
                      payload=payload, truncated=payload is not None and not complete)
        return result

    label, readable = detect_compression(data[:16])
    if label is None:
        return result

    result["compression"] = label
    if not readable:
        result.update(readable=False, payload=None)
        return result

    payload, complete = decompress(data, label, limit)
    result.update(readable=payload is not None, payload=payload,
                  truncated=payload is not None and not complete)
    return result


def parse_npy_header(data: bytes) -> Dict[str, Any] | None:
    """Read a ``.npy`` header, returning where the data section starts.

    The header is a Python dict *literal* — it is parsed with
    ``ast.literal_eval``, which builds values and cannot call anything, and only
    after the declared length has been bounds-checked. Nothing here evaluates
    the file's contents; a malformed header yields None rather than an
    exception, because a file we cannot parse still gets scanned by the caller.
    """
    if not data.startswith(NPY_MAGIC) or len(data) < 10:
        return None

    major = data[6]
    if major == 1:
        length_field, header_start = 2, 10
    else:
        # v2 and v3 widened the length field to four bytes.
        length_field, header_start = 4, 12
    if len(data) < header_start:
        return None

    header_len = int.from_bytes(data[8:8 + length_field], "little")
    if header_len <= 0 or header_len > NPY_MAX_HEADER_BYTES:
        return None

    raw_header = data[header_start:header_start + header_len]
    if len(raw_header) < header_len:
        # Truncated: the data offset is still known, which is what matters.
        raw_header = data[header_start:]

    descr: Any = None
    fortran_order = None
    shape = None
    try:
        parsed = ast.literal_eval(raw_header.decode("latin-1").strip())
        if isinstance(parsed, dict):
            descr = parsed.get("descr")
            fortran_order = parsed.get("fortran_order")
            shape = parsed.get("shape")
    except Exception:
        # A header we cannot parse is not a reason to stop: fall back to reading
        # the dtype string out of it, and failing that, carry on with the offset
        # alone. The data section is scanned either way.
        match = re.search(rb"'descr'\s*:\s*'([^']*)'", raw_header)
        if match:
            descr = match.group(1).decode("latin-1")

    return {
        "version": f"{major}.{data[7]}",
        "descr": descr,
        "fortran_order": fortran_order,
        "shape": shape,
        "data_offset": header_start + header_len,
        "object_dtype": _is_object_dtype(descr),
    }


def _is_object_dtype(descr: Any) -> bool:
    """True if a dtype descriptor carries Python objects anywhere inside it.

    ``'|O'`` is the plain object array. A structured dtype is a list of
    ``(name, format)`` or ``(name, format, shape)`` entries, and only the
    *format* element is a dtype — searching the whole entry reads field names as
    type codes, so an ordinary ``[('FOO', '<i4')]`` came back True on the
    strength of the letter O in its name.

    Note this only chooses the reported risk label, never whether to scan: the
    data section is disassembled whatever the header claims, because the header
    is attacker-supplied. Getting this wrong is noise, not a bypass.
    """
    if descr is None:
        return False
    if isinstance(descr, str):
        # Strip the byte-order/size prefix, leaving the type character.
        return "O" in descr.lstrip("|<>=")
    if isinstance(descr, list):
        # Structured: inspect each field's format, never its name or shape.
        return any(
            _is_object_dtype(field[1])
            for field in descr
            if isinstance(field, (list, tuple)) and len(field) >= 2
        )
    if isinstance(descr, tuple) and len(descr) == 2:
        # A subarray format, `(format, shape)` — the dtype is the first element.
        return _is_object_dtype(descr[0])
    return False


def npy_data_section(data: bytes, limit: int = DECOMPRESS_MAX_BYTES) -> Tuple[bytes | None, Dict[str, Any] | None]:
    """Return ``(data_section, header)`` for a ``.npy`` buffer.

    The data section is returned whatever the declared dtype says. Deciding by
    the header first would mean trusting an attacker-supplied field to tell us
    whether to look — and a pickle behind a header claiming ``'<f8'`` is exactly
    the shape that trick would take.
    """
    header = parse_npy_header(data)
    if header is None:
        return None, None
    offset = header["data_offset"]
    if offset >= len(data):
        return b"", header
    return data[offset:offset + limit], header
