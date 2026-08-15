"""A minimal, read-only protobuf wire-format reader.

Just enough of the encoding to walk a message's fields without a schema, a
compiler, or a runtime dependency — which is what lets ONNX models be inspected
while the shipped wheel and the PyInstaller bundle stay unchanged.

Two properties matter for scanning hostile input:

* **Nothing is executed and nothing is trusted.** Field numbers and lengths come
  from the file, so a declared length may exceed the bytes actually present.
* **Truncation is normal, not an error.** Model files run to gigabytes and a
  scan reads only the head, so a message will routinely be cut mid-field. The
  reader returns what it has and reports that it was truncated, rather than
  refusing to parse. A scanner that gives up on a file it cannot fully read is
  a scanner that can be evaded by damaging the file.
"""

from __future__ import annotations

from typing import Dict, Iterator, List, Tuple

# Wire types (only these four are valid in current protobuf).
WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_LENGTH_DELIMITED = 2
WIRE_32BIT = 5

# A varint is at most 10 bytes; anything longer is malformed input, not a number.
_MAX_VARINT_BYTES = 10


class TruncatedMessage(Exception):
    """Raised internally when the buffer ends mid-field."""


def read_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    """Decode a base-128 varint at ``pos``; return ``(value, next_pos)``."""
    result = 0
    shift = 0
    for _ in range(_MAX_VARINT_BYTES):
        if pos >= len(buf):
            raise TruncatedMessage("buffer ended inside a varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
    raise TruncatedMessage("varint longer than 10 bytes")


def iter_fields(buf: bytes) -> Iterator[Tuple[int, int, object]]:
    """Yield ``(field_number, wire_type, value)`` for each field in ``buf``.

    Varints yield an ``int``; every other wire type yields ``bytes``. Iteration
    stops cleanly at the first field that runs past the end of the buffer, so a
    truncated message yields the fields that are wholly present.
    """
    pos = 0
    while pos < len(buf):
        try:
            tag, pos = read_varint(buf, pos)
        except TruncatedMessage:
            return

        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number == 0:
            return  # field 0 is not legal; the stream is not a message

        try:
            if wire_type == WIRE_VARINT:
                value, pos = read_varint(buf, pos)
                yield field_number, wire_type, value
            elif wire_type == WIRE_LENGTH_DELIMITED:
                length, pos = read_varint(buf, pos)
                end = pos + length
                if end > len(buf):
                    # Declared longer than what we hold. Hand back the bytes we
                    # do have — for a head-of-file scan this is the whole graph
                    # we are ever going to see, and it is still worth reading.
                    yield field_number, wire_type, buf[pos:]
                    return
                yield field_number, wire_type, buf[pos:end]
                pos = end
            elif wire_type == WIRE_64BIT:
                if pos + 8 > len(buf):
                    return
                yield field_number, wire_type, buf[pos:pos + 8]
                pos += 8
            elif wire_type == WIRE_32BIT:
                if pos + 4 > len(buf):
                    return
                yield field_number, wire_type, buf[pos:pos + 4]
                pos += 4
            else:
                # Groups (3, 4) were removed from proto3 and never appear in
                # ONNX; an unknown wire type means we have lost the framing.
                return
        except TruncatedMessage:
            return


def iter_stream_fields(read_at, start: int, end: int):
    """Walk a message in a file without reading its payloads.

    Yields ``(field_number, wire_type, payload_offset, payload_length)``.
    ``read_at(offset, n)`` must return up to ``n`` bytes at ``offset``.

    This exists so bulk data can be *stepped over* rather than buffered. An
    ONNX model stores its weights inline, so a tensor can be gigabytes while
    the security-relevant parts of the file — the graph structure, and the
    tensors that point *outside* the file — are tiny. Reading a fixed window
    from the front would stop inside the first big tensor and never reach them.
    """
    pos = start
    while pos < end:
        header = read_at(pos, 20)  # a tag plus a length varint fit comfortably
        if not header:
            return
        try:
            tag, consumed = read_varint(header, 0)
        except TruncatedMessage:
            return

        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number == 0:
            return
        pos += consumed

        if wire_type == WIRE_VARINT:
            try:
                _value, used = read_varint(header, consumed)
            except TruncatedMessage:
                return
            length = used - consumed
            yield field_number, wire_type, pos, length
            pos += length
        elif wire_type == WIRE_LENGTH_DELIMITED:
            try:
                length, used = read_varint(header, consumed)
            except TruncatedMessage:
                return
            pos += used - consumed
            if pos + length > end:
                yield field_number, wire_type, pos, max(0, end - pos)
                return
            yield field_number, wire_type, pos, length
            pos += length
        elif wire_type == WIRE_64BIT:
            yield field_number, wire_type, pos, 8
            pos += 8
        elif wire_type == WIRE_32BIT:
            yield field_number, wire_type, pos, 4
            pos += 4
        else:
            return


def parse_message(buf: bytes) -> Dict[int, List[object]]:
    """Group a message's fields by field number, preserving repeat order."""
    fields: Dict[int, List[object]] = {}
    for field_number, _wire_type, value in iter_fields(buf):
        fields.setdefault(field_number, []).append(value)
    return fields


def get_bytes(fields: Dict[int, List[object]], number: int) -> bytes | None:
    """First length-delimited value for ``number``, or None."""
    for value in fields.get(number, []):
        if isinstance(value, bytes):
            return value
    return None


def get_str(fields: Dict[int, List[object]], number: int) -> str | None:
    """First value for ``number`` decoded as UTF-8, or None.

    Invalid bytes are replaced rather than raising: the value is a label to
    show a human, and a hostile file is entitled to contain invalid UTF-8.
    """
    raw = get_bytes(fields, number)
    return None if raw is None else raw.decode("utf-8", errors="replace")


def get_int(fields: Dict[int, List[object]], number: int) -> int | None:
    """First varint value for ``number``, or None."""
    for value in fields.get(number, []):
        if isinstance(value, int):
            return value
    return None


def get_messages(fields: Dict[int, List[object]], number: int) -> List[Dict[int, List[object]]]:
    """Parse every length-delimited value for ``number`` as a submessage."""
    return [parse_message(v) for v in fields.get(number, []) if isinstance(v, bytes)]
