"""nullifAI-class evasions: alternative containers, broken streams, tampered zips.

The family this covers has one shape in common: make the file *look* unreadable
to a scanner while leaving it perfectly loadable by the thing that matters. A
scanner that declines to examine what it cannot cleanly parse is the whole
attack, so the tests below are as much about what the scanner refuses to skip
as about what it detects.

Nothing here is ever unpickled. The payloads are opcode-assembled streams that
name a dangerous global and carry an inert echo as their argument; they are
disassembled with pickletools and never executed.
"""

import io
import struct
import zipfile

import pytest

from aisbom.mock_generator import (
    HARMLESS_COMMAND,
    harmless_reduce_pickle,
    harmless_stack_global_pickle,
)
from aisbom.safety import looks_like_pickle_stream, scan_pickle_stream
from aisbom.scanner import DeepScanner


def pytorch_zip(payload: bytes, compression=zipfile.ZIP_DEFLATED, member="archive/data.pkl") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as z:
        z.writestr(member, payload)
        z.writestr("archive/version", "3")
    return buf.getvalue()


# --- the printable-protocol-0 bypass -------------------------------------

@pytest.mark.parametrize("filename", ["model.bin", "model.pt", "model.pth"])
def test_bare_printable_pickle_is_not_mistaken_for_a_text_config(tmp_path, filename):
    """The green-check-on-a-live-threat case.

    A protocol-0 pickle is printable ASCII, and classifying by shape meant a
    bare pickle naming os.system was reported as a Python path-config file at
    LOW risk. Protocol 0 costs an attacker nothing to choose.
    """
    (tmp_path / filename).write_bytes(harmless_reduce_pickle("os", "system"))
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert "os.system" in art["risk_level"]
    assert art["framework"] == "PyTorch"
    assert art["details"]["threats"] == ["os.system"]


def test_bare_printable_pickle_is_caught_in_strict_mode_too(tmp_path):
    (tmp_path / "model.bin").write_bytes(harmless_reduce_pickle("os", "system"))
    art = DeepScanner(str(tmp_path), strict_mode=True).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert "UNSAFE_IMPORT" in art["risk_level"]


def test_stack_global_variant_is_caught_bare_too(tmp_path):
    """Protocol 4 / STACK_GLOBAL, outside a ZIP container."""
    (tmp_path / "model.pt").write_bytes(harmless_stack_global_pickle("os", "system"))
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert "os.system" in art["risk_level"]


def test_genuine_text_path_config_is_still_low(tmp_path):
    """The false-positive guard the printable heuristic existed to provide."""
    (tmp_path / "site-packages.pth").write_text(
        "/usr/local/lib/python3.11/site-packages\nimport sys\n"
    )
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["risk_level"] == "LOW"
    assert art["framework"] == "Python Path Config"


def test_benign_bare_pickle_is_medium_not_critical(tmp_path):
    """A well-formed pickle with no dangerous global is not an incident.

    This used to be CRITICAL (Legacy Binary) purely because the bytes were not
    printable — a verdict about the file's shape, not its contents.
    """
    import pickle
    (tmp_path / "model.pt").write_bytes(pickle.dumps({"weights": [1, 2, 3]}, protocol=2))
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["risk_level"] == "MEDIUM (Pickle Present)"


def test_unparsable_binary_is_still_critical(tmp_path):
    """Bytes that are neither text, nor a pickle, nor a known container."""
    (tmp_path / "model.pt").write_bytes(bytes(range(256)) * 4)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["risk_level"] == "CRITICAL (Legacy Binary)"


# --- non-standard containers ---------------------------------------------

@pytest.mark.parametrize("magic,label", [
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"\xfd7zXZ\x00\x00", "xz"),
    (b"\x28\xb5\x2f\xfd\x00\x00", "zstd"),
    (b"BZh9", "bzip2"),
    (b"\x1f\x8b\x08\x00", "gzip"),
])
def test_nonstandard_containers_are_named(tmp_path, magic, label):
    """PyTorch's container is ZIP; anything else is the finding itself."""
    (tmp_path / "model.pt").write_bytes(magic + b"\x00" * 128)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert label in art["risk_level"]
    assert art["details"]["container_format"] == label


def test_seven_zip_container_reports_its_format_not_a_generic_blob(tmp_path):
    """A real 7z archive, built with the same library the corpus uses."""
    py7zr = pytest.importorskip("py7zr", reason="py7zr is a dev-only dependency")

    inner = tmp_path / "payload.pkl"
    inner.write_bytes(harmless_reduce_pickle("os", "system"))
    archive_path = tmp_path / "model.pt"
    with py7zr.SevenZipFile(archive_path, "w") as archive:
        archive.write(inner, "archive/data.pkl")
    inner.unlink()

    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["details"]["container_format"] == "7z"
    assert "Non-Standard Container" in art["risk_level"]
    assert "CRITICAL" in art["risk_level"]
    # Deliberately not unpacked, so the payload is not named. Stating this
    # keeps the limit visible instead of letting it look like full detection.
    assert art["details"]["threats"] == []


def test_a_normal_zip_is_not_reported_as_a_nonstandard_container(tmp_path):
    (tmp_path / "model.pt").write_bytes(pytorch_zip(harmless_reduce_pickle("os", "system")))
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "container_format" not in art["details"]
    assert "os.system" in art["risk_level"]


# --- broken and truncated streams ----------------------------------------

def test_truncated_stream_still_reports_the_payload_at_its_front():
    """The pickle VM runs sequentially, so a corrupt tail does not save you."""
    full = harmless_reduce_pickle("os", "system")
    assert scan_pickle_stream(full[: len(full) // 2]) == ["os.system"]


def test_trailing_garbage_does_not_suppress_the_payload():
    payload = harmless_reduce_pickle("os", "system") + b"\xff\xff\xff\xff junk"
    assert scan_pickle_stream(payload) == ["os.system"]


def test_truncated_stream_inside_a_zip_is_critical(tmp_path):
    full = harmless_reduce_pickle("os", "system")
    (tmp_path / "model.pt").write_bytes(pytorch_zip(full[: len(full) // 2]))
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert "os.system" in art["details"]["threats"]


def test_truncated_bare_stream_is_critical(tmp_path):
    full = harmless_reduce_pickle("os", "system")
    (tmp_path / "model.pt").write_bytes(full[: len(full) // 2])
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert "os.system" in art["risk_level"]


# --- zip tampering --------------------------------------------------------

def _corrupt_central_crc(blob: bytes) -> bytes:
    """Wreck the CRC of the *first* central-directory entry (the pickle).

    `find`, not `rfind`: the archive holds `archive/data.pkl` followed by
    `archive/version`, and corrupting the latter proves nothing.
    """
    idx = blob.find(b"PK\x01\x02")
    assert idx != -1
    out = bytearray(blob)
    out[idx + 16:idx + 20] = b"\xde\xad\xbe\xef"
    return bytes(out)


def _rename_local_header(blob: bytes, old: str, new: str) -> bytes:
    assert len(old) == len(new)
    idx = blob.find(b"PK\x03\x04")
    assert idx != -1
    return blob.replace(old.encode(), new.encode(), 1)


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_corrupt_crc_does_not_hide_the_payload(tmp_path, compression):
    """Loaders that skip CRC validation still run it, so we still read it."""
    blob = pytorch_zip(harmless_reduce_pickle("os", "system"), compression)
    (tmp_path / "model.pt").write_bytes(_corrupt_central_crc(blob))

    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert "os.system" in art["details"]["threats"]
    assert "integrity check failed" in art["details"]["member_read"]


def test_tampered_member_filename_does_not_hide_the_payload(tmp_path):
    """Directory and local-header names disagreeing is not a reason to stop."""
    blob = pytorch_zip(harmless_reduce_pickle("os", "system"))
    (tmp_path / "model.pt").write_bytes(
        _rename_local_header(blob, "archive/data.pkl", "archive/data_pkl")
    )

    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert "os.system" in art["details"]["threats"]


def test_a_genuinely_unreadable_member_is_flagged_not_called_clean(tmp_path):
    """When the bytes really cannot be recovered, say so rather than pass it."""
    blob = bytearray(pytorch_zip(harmless_reduce_pickle("os", "system")))
    # Wreck the deflate payload itself, not just its checksum.
    start = blob.find(b"PK\x03\x04")
    blob[start + 40:start + 60] = b"\x00" * 20
    (tmp_path / "model.pt").write_bytes(bytes(blob))

    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]
    assert art["risk_level"] != "LOW"


# --- concatenated streams (legacy torch.save layout) ---------------------

def legacy_torch_bytes(object_pickle: bytes) -> bytes:
    """The layout `torch.save(..., _use_new_zipfile_serialization=False)` writes.

    A magic number, a protocol version and a sys-info dict are each pickled
    before the object itself, so the payload sits in the *fourth* stream.
    """
    import pickle
    return (
        pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2)
        + pickle.dumps(1001, protocol=2)
        + pickle.dumps(
            {"protocol_version": 1001, "little_endian": True, "type_sizes": {}},
            protocol=2,
        )
        + object_pickle
    )


def test_payload_in_a_later_concatenated_stream_is_found():
    """Disassembly must not stop at the first STOP.

    A scan that reads only the first pickle sees the magic number and nothing
    else, so a legacy checkpoint whose object calls os.system reads as clean.
    """
    blob = legacy_torch_bytes(harmless_reduce_pickle("os", "system"))
    assert scan_pickle_stream(blob) == ["os.system"]
    assert scan_pickle_stream(blob, strict_mode=True) == ["UNSAFE_IMPORT: os.system"]


def test_legacy_torch_layout_is_critical_end_to_end(tmp_path):
    (tmp_path / "legacy.pt").write_bytes(
        legacy_torch_bytes(harmless_reduce_pickle("os", "system"))
    )
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert "os.system" in art["risk_level"]


def test_benign_legacy_torch_layout_stays_medium(tmp_path):
    """The multi-stream walk must not manufacture threats from header pickles."""
    import pickle
    (tmp_path / "legacy.pt").write_bytes(
        legacy_torch_bytes(pickle.dumps({"w": [1, 2, 3]}, protocol=2))
    )
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["risk_level"] == "MEDIUM (Pickle Present)"


def test_payload_in_the_last_of_many_streams_is_found():
    import pickle
    blob = b"".join(pickle.dumps({"i": i}, protocol=2) for i in range(20))
    blob += harmless_reduce_pickle("subprocess", "Popen")
    assert scan_pickle_stream(blob) == ["subprocess.Popen"]


def test_concatenated_scan_is_bounded():
    """A file of many tiny pickles must not be walked without limit."""
    import pickle
    from aisbom.safety import MAX_CONCATENATED_STREAMS

    blob = pickle.dumps(1, protocol=2) * (MAX_CONCATENATED_STREAMS + 200)
    blob += harmless_reduce_pickle("os", "system")
    # Past the bound the tail is not reached; the point is that it terminates.
    scan_pickle_stream(blob)


def test_trailing_garbage_after_a_complete_stream_does_not_crash():
    blob = harmless_reduce_pickle("os", "system") + b"\x00\xff\x00trailing"
    assert scan_pickle_stream(blob) == ["os.system"]


# --- looks_like_pickle_stream --------------------------------------------

def test_looks_like_pickle_stream_requires_reaching_stop():
    assert looks_like_pickle_stream(harmless_reduce_pickle("os", "system")) is True
    # Truncated: parses opcodes but never reaches STOP.
    full = harmless_reduce_pickle("os", "system")
    assert looks_like_pickle_stream(full[: len(full) // 2]) is False
    assert looks_like_pickle_stream(b"") is False
    assert looks_like_pickle_stream(b"/usr/local/lib/site-packages") is False
    assert looks_like_pickle_stream(bytes(range(256))) is False


# --- the payload never runs ----------------------------------------------

def test_scanning_never_unpickles(tmp_path, monkeypatch):
    """A scan of a hostile file must not call into pickle's loader at all."""
    import pickle as pickle_module

    def explode(*args, **kwargs):
        raise AssertionError("the scanner must never unpickle its input")

    monkeypatch.setattr(pickle_module, "loads", explode)
    monkeypatch.setattr(pickle_module, "load", explode)

    (tmp_path / "bare.pt").write_bytes(harmless_reduce_pickle("os", "system"))
    (tmp_path / "zipped.pth").write_bytes(pytorch_zip(harmless_reduce_pickle("os", "system")))
    (tmp_path / "seven.bin").write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64)

    results = DeepScanner(str(tmp_path)).scan()
    assert len(results["artifacts"]) == 3
    assert any("os.system" in a["risk_level"] for a in results["artifacts"])


def test_payload_command_is_inert():
    """The corpus payload is an echo, not an exploit."""
    assert "echo" in HARMLESS_COMMAND
    assert "no payload executed" in HARMLESS_COMMAND


# --- CLI ------------------------------------------------------------------

def test_bare_pickle_payload_exits_two(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from aisbom.cli import app

    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    (tmp_path / "model.bin").write_bytes(harmless_reduce_pickle("os", "system"))
    result = CliRunner().invoke(app, ["scan", str(tmp_path)])

    assert "model.bin" in result.output, result.output
    assert "CRITICAL" in result.output, result.output
    assert result.exit_code == 2, result.output


def test_benign_bare_pickle_does_not_exit_two(tmp_path, monkeypatch):
    """MEDIUM must not fail CI."""
    import pickle
    from typer.testing import CliRunner
    from aisbom.cli import app

    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    (tmp_path / "model.pt").write_bytes(pickle.dumps({"w": [1]}, protocol=2))
    result = CliRunner().invoke(app, ["scan", str(tmp_path)])

    assert "model.pt" in result.output, result.output
    assert result.exit_code == 0, result.output
