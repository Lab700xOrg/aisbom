"""joblib / dill / numpy: the pickle carriers that are not `.pt`.

Every format here is a pickle stream behind a wrapper, so the interesting part
is never "does the disassembler work" — it is whether we find the stream at all,
and whether we keep looking once the container stops cooperating. joblib in
particular splices raw array buffers into the middle of its pickle, which kills
a structural disassembly a few hundred bytes in; since every real sklearn model
has arrays, a payload placed after one is the natural shape of an attack here.

Fixtures are built two ways on purpose. Where the point is "we read what the
real library writes", the real library writes them. Where the point is a
specific container or codec, the bytes are assembled by hand from
`mock_generator`'s opcode payloads. Nothing is ever loaded: the malicious
fixtures are disassembled and thrown away, never handed to `pickle.load`,
`joblib.load` or `numpy.load`.
"""

import io
import os
import pickle
import struct
import zipfile
import zlib

import pytest

from aisbom import pickle_containers as pc
from aisbom.mock_generator import (
    HARMLESS_COMMAND,
    harmless_reduce_pickle,
    harmless_stack_global_pickle,
)
from aisbom.properties import build_component_properties
from aisbom.safety import salvage_globals, scan_pickle_stream
from aisbom.scanner import DeepScanner

joblib = pytest.importorskip("joblib")
dill = pytest.importorskip("dill")
np = pytest.importorskip("numpy")


class HarmlessSink:
    """Reduces to `os.system(<echo>)` — realistic shape, inert payload.

    Handed to the real joblib/numpy writers so the fixtures are genuinely what
    those libraries produce. It is never unpickled, so the reduce never runs.
    """

    def __reduce__(self):
        return (os.system, (HARMLESS_COMMAND,))


_scan_counter = iter(range(10_000))


def scan_one(tmp_path, filename, blob, strict=False):
    """Write one artifact into its own empty directory and scan that directory.

    A dedicated subdirectory per call keeps the fixture-building files (written
    by joblib/numpy into `tmp_path` itself) out of the scan, so the count
    assertion below really does mean "one artifact".
    """
    holder = tmp_path / f"scan_{next(_scan_counter)}"
    holder.mkdir()
    (holder / filename).write_bytes(blob)
    results = DeepScanner(str(holder), strict_mode=strict).scan()
    assert len(results["artifacts"]) == 1, results["artifacts"]
    return results["artifacts"][0]


def is_critical(artifact):
    return "CRITICAL" in artifact["risk_level"]


# --- discovery: the extensions were not scanned at all -------------------

@pytest.mark.parametrize(
    "filename",
    ["model.pkl", "model.pickle", "model.joblib", "model.dill", "model.npy", "model.npz"],
)
def test_pickle_variant_extensions_are_discovered(tmp_path, filename):
    """Before this, every one of these scanned clean and exited 0.

    The README documents `aisbom scan model.pkl --strict`; discovery never
    claimed the file, so the walk produced no artifact and no error. A malicious
    file in any of these formats was invisible.
    """
    artifact = scan_one(tmp_path, filename, harmless_reduce_pickle("os", "system"))
    assert is_critical(artifact)
    assert "os.system" in artifact["risk_level"]


def test_single_file_pkl_target_is_claimed(tmp_path):
    """`aisbom scan model.pkl` — the exact invocation the README documents."""
    target = tmp_path / "model.pkl"
    target.write_bytes(harmless_reduce_pickle("os", "system"))
    results = DeepScanner(str(target)).scan()
    assert results["errors"] == []
    assert len(results["artifacts"]) == 1
    assert is_critical(results["artifacts"][0])


# --- joblib: the array block that hid everything behind it ---------------

def test_payload_after_a_numpy_array_is_found(tmp_path):
    """The regression this slice exists for.

    joblib writes the pickle up to an array wrapper, dumps the raw buffer
    inline, then resumes pickling. `pickletools.genops` cannot cross the raw
    bytes, so a structural walk stopped ~226 bytes into a 552-byte file and
    reported nothing — while the payload sat at byte 516. Since every real
    sklearn model carries arrays, "after an array" is where a payload naturally
    goes.
    """
    path = tmp_path / "model.joblib"
    joblib.dump(
        {"a_weights": np.arange(64, dtype=np.float32), "z_payload": HarmlessSink()},
        path,
    )
    blob = path.read_bytes()

    # The premise: a structural disassembly really does stop early here.
    with pytest.raises(Exception):
        import pickletools
        list(pickletools.genops(io.BytesIO(blob)))

    assert scan_pickle_stream(blob) == ["posix.system"] or \
        scan_pickle_stream(blob) == ["os.system"]


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("arrays", [1, 3])
def test_payload_after_arrays_is_flagged_end_to_end(tmp_path, strict, arrays):
    payload = {f"arr_{i}": np.arange(64, dtype=np.float32) for i in range(arrays)}
    payload["z_payload"] = HarmlessSink()
    path = tmp_path / "model.joblib"
    joblib.dump(payload, path)

    artifact = scan_one(tmp_path, "model.joblib", path.read_bytes(), strict=strict)
    assert is_critical(artifact)
    assert "system" in artifact["risk_level"]


@pytest.mark.parametrize("compress", [None, 3, ("gzip", 3), ("bz2", 3), ("lzma", 3), ("xz", 3)])
def test_every_stdlib_joblib_codec_is_opened(tmp_path, compress):
    """joblib picks the codec; we have to read all of the ones stdlib can."""
    path = tmp_path / "src.joblib"
    if compress is None:
        joblib.dump(HarmlessSink(), path)
    else:
        joblib.dump(HarmlessSink(), path, compress=compress)

    artifact = scan_one(tmp_path, "model.joblib", path.read_bytes())
    assert is_critical(artifact)


@pytest.mark.parametrize("compress", [3, ("gzip", 3), ("bz2", 3), ("lzma", 3)])
def test_benign_joblib_scans_clean_in_both_modes(tmp_path, compress):
    """A real sklearn-shaped payload must not be flagged in either mode.

    Strict mode used to report `joblib.numpy_pickle.NumpyArrayWrapper` and
    `dtype.dtype` on an ordinary model — the second of which is not even a real
    global, but the memo-aliasing artifact this slice fixed.
    """
    path = tmp_path / "src.joblib"
    joblib.dump(
        {"coef_": np.arange(32, dtype=np.float64), "intercept_": 0.5, "name": "ridge"},
        path,
        compress=compress,
    )
    blob = path.read_bytes()
    for strict in (False, True):
        artifact = scan_one(tmp_path, "model.joblib", blob, strict=strict)
        assert not is_critical(artifact), artifact["risk_level"]
        assert artifact["details"]["threats"] == []


def test_joblib_compression_is_reported(tmp_path):
    path = tmp_path / "src.joblib"
    joblib.dump({"w": np.arange(8)}, path, compress=("bz2", 3))
    artifact = scan_one(tmp_path, "model.joblib", path.read_bytes())
    assert artifact["framework"] == "Joblib"
    assert artifact["details"]["compression"] == "bz2"
    assert artifact["details"]["decompressed_bytes"] > 0


def test_legacy_zfile_container_is_unwrapped(tmp_path):
    """joblib's pre-0.10 `ZF` container still reads, so it still hides a payload."""
    inner = harmless_stack_global_pickle("os", "system")
    body = zlib.compress(inner)
    blob = pc.JOBLIB_ZFILE_MAGIC + b"%019d" % len(inner) + body

    assert pc.unwrap_zfile(blob) == inner
    artifact = scan_one(tmp_path, "legacy.joblib", blob)
    assert is_critical(artifact)
    assert artifact["details"]["container"] == "zfile"


@pytest.mark.parametrize("magic,label", [(b"\x04\x22\x4d\x18", "lz4"), (b"\x28\xb5\x2f\xfd", "zstd")])
def test_unreadable_codec_is_named_not_called_clean(tmp_path, magic, label):
    """No standard-library decompressor exists for these.

    Following the 7z decision: pulling one in would land in every install and
    every standalone binary. The container is named and the file is reported as
    unscanned — which is a different answer from "clean", and the point.
    """
    artifact = scan_one(tmp_path, "model.joblib", magic + b"\x00" * 256)
    assert artifact["risk_level"] == f"MEDIUM (Unscanned Container: {label})"
    assert artifact["details"]["compression"] == label
    assert "CRITICAL" not in artifact["risk_level"]


# --- numpy -------------------------------------------------------------

def test_npy_object_array_payload_is_flagged(tmp_path):
    path = tmp_path / "src.npy"
    np.save(path, np.array([HarmlessSink()], dtype=object), allow_pickle=True)
    artifact = scan_one(tmp_path, "weights.npy", path.read_bytes())
    assert is_critical(artifact)
    assert artifact["framework"] == "NumPy"
    assert artifact["details"]["object_dtype"] is True


def test_npy_of_ordinary_numbers_is_low_not_pickle_present(tmp_path):
    """A real, fully-read file carrying no pickle. Reporting one would be noise."""
    path = tmp_path / "src.npy"
    np.save(path, np.arange(64, dtype=np.float64))
    artifact = scan_one(tmp_path, "weights.npy", path.read_bytes())
    assert artifact["risk_level"] == "LOW"
    assert artifact["details"]["object_dtype"] is False
    assert artifact["details"]["threats"] == []


def test_declared_dtype_does_not_decide_whether_to_look(tmp_path):
    """The header is attacker-supplied, so it cannot gate the scan.

    A pickle placed in the data section behind a header claiming `'<f8'` is a
    one-line evasion against any scanner that trusts `descr`.
    """
    payload = harmless_stack_global_pickle("os", "system")
    header = b"{'descr': '<f8', 'fortran_order': False, 'shape': (8,), }"
    header = header + b" " * ((64 - (10 + len(header)) % 64) % 64) + b"\n"
    blob = pc.NPY_MAGIC + b"\x01\x00" + struct.pack("<H", len(header)) + header + payload

    parsed = pc.parse_npy_header(blob)
    assert parsed["object_dtype"] is False, "the header is lying, which is the point"

    artifact = scan_one(tmp_path, "weights.npy", blob)
    assert is_critical(artifact)


def test_structured_dtype_with_one_object_field_counts_as_object(tmp_path):
    descr = [("id", "<i8"), ("meta", "|O")]
    assert pc._is_object_dtype(descr) is True
    assert pc._is_object_dtype([("id", "<i8"), ("w", "<f4")]) is False


def test_npz_members_are_each_scanned(tmp_path):
    path = tmp_path / "src.npz"
    np.savez(path, good=np.arange(5), bad=np.array([HarmlessSink()], dtype=object))
    artifact = scan_one(tmp_path, "model.npz", path.read_bytes())
    assert is_critical(artifact)
    assert artifact["details"]["container"] == "npz"
    assert artifact["details"]["internal_files"] == 2


def test_compressed_npz_members_are_scanned(tmp_path):
    path = tmp_path / "src.npz"
    np.savez_compressed(path, bad=np.array([HarmlessSink()], dtype=object))
    artifact = scan_one(tmp_path, "model.npz", path.read_bytes())
    assert is_critical(artifact)


def test_benign_npz_is_low(tmp_path):
    path = tmp_path / "src.npz"
    np.savez(path, a=np.arange(5), b=np.ones(3))
    artifact = scan_one(tmp_path, "model.npz", path.read_bytes())
    assert artifact["risk_level"] == "LOW"


def test_npz_with_a_tampered_crc_is_still_read(tmp_path):
    """The container-integrity evasion, applied to `.npz`.

    numpy's own reader does not verify the CRC the way `ZipFile.open` does, so a
    scanner that bails on a bad checksum skips a member that still loads. This
    reuses the raw local-header read the PyTorch path already had.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        member = pc.NPY_MAGIC + b"\x01\x00" + struct.pack("<H", 54) + \
            b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }" [:53] + b"\n"
        z.writestr("bad.npy", member + harmless_stack_global_pickle("os", "system"))
    blob = bytearray(buf.getvalue())

    # Corrupt the central-directory CRC so a clean open fails.
    central = blob.rfind(b"PK\x01\x02")
    blob[central + 16:central + 20] = b"\xde\xad\xbe\xef"

    artifact = scan_one(tmp_path, "model.npz", bytes(blob))
    assert is_critical(artifact)


# --- dill --------------------------------------------------------------

def test_dill_serialized_function_is_flagged_in_blocklist_mode(tmp_path):
    """A dill'd callable is a marshalled code object rebuilt on load.

    Blocklist mode saw nothing: `dill._dill._create_function` was in no table,
    and strict mode only caught it because `dill` was unrecognized rather than
    because it is dangerous.
    """
    blob = dill.dumps(lambda value: value + 1)
    artifact = scan_one(tmp_path, "model.dill", blob)
    assert is_critical(artifact)
    assert artifact["details"]["dill_code_objects"] is True
    assert any("_create_function" in t for t in artifact["details"]["threats"])


@pytest.mark.parametrize("strict", [False, True])
def test_dill_holding_only_data_scans_clean(tmp_path, strict):
    """dill emits none of its machinery for plain data, which is what keeps
    an ordinary `.dill` from being flagged for the crime of being a `.dill`."""
    blob = dill.dumps({"weights": np.arange(16), "epochs": 10, "name": "run-3"})
    artifact = scan_one(tmp_path, "state.dill", blob, strict=strict)
    assert not is_critical(artifact), artifact["risk_level"]


def test_dill_type_helpers_are_deliberately_not_flagged():
    """Proving the limit, not just asserting the catch.

    `_create_type`, `_load_type` and `_create_array` name or rebuild a value and
    execute nothing by themselves. Flagging them would make every dill file
    holding a custom class or a numpy array CRITICAL, which is the kind of
    result that gets a scanner switched off.
    """
    for name in ("_create_type", "_load_type", "_create_array"):
        blob = harmless_stack_global_pickle("dill._dill", name)
        assert scan_pickle_stream(blob) == [], name

    for name in ("_create_function", "_create_code", "_import_module", "_get_attr"):
        blob = harmless_stack_global_pickle("dill._dill", name)
        assert scan_pickle_stream(blob) == [f"dill._dill.{name}"], name


# --- the memo-table fix ------------------------------------------------

def test_stack_global_operands_arriving_from_the_memo_resolve_correctly():
    """`BINGET` pushes an earlier string; watching only literals misreads it.

    A real joblib file spells `numpy.dtype` as: a dict key 'dtype', a BINGET of
    a much earlier 'numpy', then 'dtype'. Reading the last two *literals* gives
    `dtype.dtype` — a module that does not exist, which strict mode then flagged.
    """
    stream = (
        b"\x80\x04"
        + b"\x8c\x05numpy" + b"\x94"      # push 'numpy', MEMOIZE -> slot 0
        + b"\x8c\x05dtype" + b"\x94"      # push 'dtype' (a decoy literal)
        + b"h\x00"                        # BINGET 0 -> pushes 'numpy'
        + b"\x8c\x05dtype" + b"\x94"
        + b"\x93"                         # STACK_GLOBAL -> numpy.dtype
        + b"."
    )
    # numpy is allowlisted, so a correct resolution is silent in both modes.
    assert scan_pickle_stream(stream) == []
    assert scan_pickle_stream(stream, strict_mode=True) == []


def test_a_dangerous_global_reached_through_the_memo_is_still_caught():
    stream = (
        b"\x80\x04"
        + b"\x8c\x02os" + b"\x94"         # slot 0 = 'os'
        + b"\x8c\x05dtype" + b"\x94"
        + b"h\x00"                        # BINGET 0 -> 'os'
        + b"\x8c\x06system" + b"\x94"
        + b"\x93"
        + b"."
    )
    assert scan_pickle_stream(stream) == ["os.system"]


def test_memoize_after_a_non_string_does_not_record_a_stale_name():
    """A MEMOIZE following a REDUCE must not leave a string in that slot."""
    stream = (
        b"\x80\x04"
        + b"\x8c\x05numpy" + b"\x94"
        + b"\x8c\x05dtype" + b"\x94"
        + b"\x93" + b"\x94"               # STACK_GLOBAL then MEMOIZE (slot 2)
        + b"h\x02"                        # BINGET 2 -> the global, not a string
        + b"."
    )
    assert scan_pickle_stream(stream) == []


# --- the salvage pass and its limits -----------------------------------

def test_salvage_reads_both_global_spellings():
    body = b"\x00" * 32 + harmless_reduce_pickle("os", "system")
    assert ("os", "system") in salvage_globals(body)

    body = b"\x00" * 32 + harmless_stack_global_pickle("subprocess", "Popen")
    assert ("subprocess", "Popen") in salvage_globals(body)


def test_salvage_does_not_apply_the_strict_allowlist():
    """Documented limitation, encoded so it cannot rot.

    The salvage pass has no memo table, so it resolves names approximately. An
    allowlist over approximate names invents false positives on every ordinary
    joblib file; a blocklist over them cannot, because a garbled name matches
    nothing. The cost is that an unrecognized-but-not-dangerous import hidden
    behind a raw array block is not reported in strict mode.
    """
    unreachable = b"\x00\x01\x02\xff" * 8 + harmless_stack_global_pickle(
        "some_unknown_module", "SomeClass"
    )
    assert scan_pickle_stream(unreachable, strict_mode=True) == []
    # ...while a known sink in the same position is reported in both modes.
    reachable = b"\x00\x01\x02\xff" * 8 + harmless_stack_global_pickle("os", "system")
    assert scan_pickle_stream(reachable) == ["os.system"]
    assert scan_pickle_stream(reachable, strict_mode=True) == ["UNSAFE_IMPORT: os.system"]


def test_salvage_cannot_judge_a_dual_use_constructor():
    """Also a documented limit: the argument that decides is a stack
    relationship, and this pass has no stack. `methodcaller("system")` behind a
    raw array block is out of reach."""
    hidden = b"\x00\x01\x02\xff" * 8 + harmless_stack_global_pickle(
        "operator", "methodcaller", "system"
    )
    assert scan_pickle_stream(hidden) == []


def test_salvage_does_not_duplicate_a_structural_finding():
    payload = harmless_reduce_pickle("os", "system")
    # A trailing junk byte makes the walk stop early over bytes it already read.
    assert scan_pickle_stream(payload + b"\x99") == ["os.system"]


def test_salvage_result_is_bounded_on_a_repeating_buffer():
    """A pattern repeated across megabytes must not produce megabytes of output."""
    flood = harmless_stack_global_pickle("os", "system") * 5000
    assert len(salvage_globals(b"\x99" + flood)) <= 50


# --- false-positive sweep ----------------------------------------------

@pytest.mark.parametrize("protocol", [2, 4, 5])
def test_ordinary_objects_do_not_trip_the_new_rules(protocol):
    """Blocklist expansions get a negative sweep, not only positive cases."""
    ordinary = [
        {"a": 1, "b": [1, 2, 3]},
        (1, 2.5, "three", None, True),
        {"nested": {"deep": [{"x": b"bytes"}]}},
        np.arange(10),
        np.zeros((3, 3), dtype=np.float32),
        np.array(["alpha", "beta"], dtype=object),
        {"dtype": "float32", "numpy": "yes", "os": "linux", "system": "darwin"},
        set(range(5)),
        frozenset("abc"),
        complex(1, 2),
    ]
    for obj in ordinary:
        blob = pickle.dumps(obj, protocol=protocol)
        assert scan_pickle_stream(blob) == [], repr(obj)[:60]
        assert scan_pickle_stream(blob, strict_mode=True) == [], repr(obj)[:60]


def test_strings_that_merely_name_a_sink_are_not_a_finding():
    """The salvage pass reads bytes, so a dict of strings is the obvious FP risk."""
    blob = pickle.dumps({"cmd": "os.system", "note": "posix\nsystem\n"}, protocol=4)
    assert scan_pickle_stream(blob) == []


# --- cross-validation, in both directions ------------------------------

def test_our_parser_reads_what_numpy_writes(tmp_path):
    path = tmp_path / "a.npy"
    array = np.arange(24, dtype=np.float32).reshape(2, 3, 4)
    np.save(path, array)
    header = pc.parse_npy_header(path.read_bytes())
    assert header["descr"] == array.dtype.str
    assert header["shape"] == array.shape
    assert header["object_dtype"] is False


def test_numpy_reads_what_we_assemble(tmp_path):
    """The other direction. One alone lets the tests be self-consistent and
    both wrong — the parser and the generator agreeing on a shared mistake."""
    header = b"{'descr': '<i8', 'fortran_order': False, 'shape': (3,), }"
    padded = header + b" " * ((64 - (10 + len(header)) % 64) % 64 - 1) + b"\n"
    body = np.arange(3, dtype=np.int64).tobytes()
    blob = pc.NPY_MAGIC + b"\x01\x00" + struct.pack("<H", len(padded)) + padded + body

    path = tmp_path / "hand.npy"
    path.write_bytes(blob)
    loaded = np.load(path)          # benign by construction; nothing to execute
    assert list(loaded) == [0, 1, 2]
    assert pc.parse_npy_header(blob)["data_offset"] == 10 + len(padded)


def test_joblib_reads_a_benign_file_we_scanned_clean(tmp_path):
    path = tmp_path / "b.joblib"
    joblib.dump({"coef_": np.arange(4, dtype=np.float64)}, path, compress=3)
    artifact = scan_one(tmp_path, "model.joblib", path.read_bytes())
    assert not is_critical(artifact)
    restored = joblib.load(path)    # benign by construction
    assert list(restored["coef_"]) == [0.0, 1.0, 2.0, 3.0]


# --- container helpers -------------------------------------------------

@pytest.mark.parametrize("head,expected,readable", [
    (b"\x1f\x8b\x08\x00", "gzip", True),
    (b"BZh91AY", "bz2", True),
    (b"\xfd7zXZ\x00\x00", "xz", True),
    (b"\x5d\x00\x00\x80\x00", "lzma", True),
    (b"\x78\x9c\x01\x00", "zlib", True),
    (b"\x78\x01\x01\x00", "zlib", True),
    (b"\x04\x22\x4d\x18", "lz4", False),
    (b"\x28\xb5\x2f\xfd", "zstd", False),
    (b"\x80\x04\x95\x00", None, False),
    (b"", None, False),
])
def test_compression_detection(head, expected, readable):
    assert pc.detect_compression(head) == (expected, readable)


def test_zlib_detection_needs_the_header_checksum_not_just_the_first_byte():
    """0x78 is an ordinary byte. Requiring the RFC 1950 header property is what
    stops a binary file that happens to start with it being called compressed."""
    assert pc.detect_compression(b"\x78\x00") == (None, False)
    assert pc._looks_like_zlib(b"\x78\x9c") is True
    assert pc._looks_like_zlib(b"\x79\x9c") is False
    assert pc._looks_like_zlib(b"\x78") is False


def test_decompression_is_bounded():
    """A compression bomb costs the same as a large ordinary file, no more."""
    bomb = zlib.compress(b"\x00" * (4 * 1024 * 1024))
    out = pc.decompress(bomb, "zlib", limit=1024)
    assert out is not None and len(out) <= 1024


def test_decompressing_garbage_returns_none_rather_than_raising():
    assert pc.decompress(b"\x1f\x8b" + b"\xff" * 32, "gzip") is None
    assert pc.decompress(b"", "zlib") is None
    assert pc.decompress(b"anything", "not-a-codec") is None


@pytest.mark.parametrize("blob", [
    b"",
    b"not a npy file at all",
    pc.NPY_MAGIC,                                   # magic only, no header
])
def test_malformed_npy_headers_return_none_not_an_exception(blob):
    assert pc.parse_npy_header(blob) is None


def test_a_header_length_running_past_the_buffer_is_not_fatal(tmp_path):
    """A truncated `.npy` still yields an offset, and the scan still happens.

    Declining to parse would make truncation a way to skip the scan, which is
    the same evasion the zip paths already refuse to fall for.
    """
    blob = pc.NPY_MAGIC + b"\x01\x00" + b"\xff\xff"   # declares 65535 header bytes
    parsed = pc.parse_npy_header(blob)
    assert parsed is not None
    assert parsed["data_offset"] > len(blob)
    section, _ = pc.npy_data_section(blob)
    assert section == b""

    artifact = scan_one(tmp_path, "trunc.npy", blob)
    assert "error" not in artifact


def test_absurd_declared_header_length_is_refused():
    blob = pc.NPY_MAGIC + b"\x02\x00" + struct.pack("<I", 900 * 1024 * 1024)
    assert pc.parse_npy_header(blob) is None


def test_npy_v2_header_uses_the_wider_length_field():
    header = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }\n"
    blob = pc.NPY_MAGIC + b"\x02\x00" + struct.pack("<I", len(header)) + header
    parsed = pc.parse_npy_header(blob)
    assert parsed["version"] == "2.0"
    assert parsed["object_dtype"] is True
    assert parsed["data_offset"] == 12 + len(header)


def test_unparseable_npy_header_still_yields_the_dtype_and_offset():
    """A header we cannot literal_eval is not a reason to stop scanning."""
    header = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,,,), }\n"
    blob = pc.NPY_MAGIC + b"\x01\x00" + struct.pack("<H", len(header)) + header + b"\x80\x04."
    parsed = pc.parse_npy_header(blob)
    assert parsed is not None
    assert parsed["object_dtype"] is True
    assert parsed["data_offset"] == 10 + len(header)


# --- SBOM surface ------------------------------------------------------

def test_findings_reach_the_cyclonedx_properties(tmp_path):
    path = tmp_path / "src.joblib"
    joblib.dump(HarmlessSink(), path, compress=3)
    artifact = scan_one(tmp_path, "model.joblib", path.read_bytes())

    props = dict(build_component_properties(artifact))
    assert props["aisbom:format"] == "joblib"
    assert props["aisbom:joblib:compression"] == "zlib"
    assert props["aisbom:pickle:opcode_count"] == "1"
    assert "CRITICAL" in props["aisbom:risk"]
    # The same key a consumer already reads off a `.pt`, not a parallel one.
    assert any(name == "aisbom:pickle:opcode" for name, _ in
               build_component_properties(artifact))


def test_numpy_properties_describe_the_array(tmp_path):
    path = tmp_path / "src.npy"
    np.save(path, np.array([HarmlessSink()], dtype=object), allow_pickle=True)
    artifact = scan_one(tmp_path, "weights.npy", path.read_bytes())

    props = dict(build_component_properties(artifact))
    assert props["aisbom:format"] == "numpy"
    assert props["aisbom:numpy:object_dtype"] == "true"
    assert props["aisbom:numpy:npy_version"] == "1.0"
    assert props["aisbom:pickle:container"] == "npy"


def test_bare_pickle_shares_the_pytorch_format_token(tmp_path):
    artifact = scan_one(tmp_path, "model.pkl", harmless_reduce_pickle("os", "system"))
    props = dict(build_component_properties(artifact))
    assert props["aisbom:format"] == "pickle"


# --- remote ------------------------------------------------------------

def _serve(content):
    """A Range-request server over one in-memory blob."""
    def fake_get(url, headers=None):
        rng = (headers or {}).get("Range", "bytes=0-0")
        start, _, end = rng.split("=")[1].partition("-")
        start = int(start)
        end = int(end) if end else len(content) - 1
        chunk = content[start:end + 1]

        class Resp:
            status_code = 206

            def __init__(self):
                self.content = chunk
                self.headers = {
                    "Content-Range": f"bytes {start}-{end}/{len(content)}",
                    "Content-Length": str(len(chunk)),
                }

            def raise_for_status(self):
                pass

        return Resp()
    return fake_get


@pytest.mark.parametrize("filename", ["remote.joblib", "remote.npy", "remote.pkl"])
def test_remote_pickle_variants_are_scanned(monkeypatch, tmp_path, filename):
    """The dispatch arm that is easy to forget.

    A format wired into the local walk but not the remote one reports every
    `hf://` model clean, which is worse than not supporting it at all.
    """
    import aisbom.remote as remote

    if filename.endswith(".joblib"):
        joblib.dump(HarmlessSink(), tmp_path / "src.joblib", compress=3)
        content = (tmp_path / "src.joblib").read_bytes()
    elif filename.endswith(".npy"):
        np.save(tmp_path / "src.npy", np.array([HarmlessSink()], dtype=object),
                allow_pickle=True)
        content = (tmp_path / "src.npy").read_bytes()
    else:
        content = harmless_reduce_pickle("os", "system")

    url = f"http://example.com/{filename}"
    monkeypatch.setattr(remote, "requests", remote._RequestsStub())
    monkeypatch.setattr(remote.requests, "get", _serve(content))
    monkeypatch.setattr(
        "aisbom.scanner.DeepScanner._resolve_remote_targets",
        lambda self, target: [url],
    )

    results = DeepScanner(url).scan()
    assert results["errors"] == []
    artifact = results["artifacts"][0]
    assert is_critical(artifact), artifact["risk_level"]
    assert artifact["hash"] == "remote_unhashed"


# --- CLI ---------------------------------------------------------------

def test_cli_exits_2_on_a_malicious_joblib(tmp_path):
    """Exit code *and* output content: Typer exits 2 on a usage error too, so an
    exit-code-only assertion can pass for entirely the wrong reason."""
    from typer.testing import CliRunner
    from aisbom.cli import app

    path = tmp_path / "model.joblib"
    joblib.dump(HarmlessSink(), path, compress=3)

    result = CliRunner().invoke(
        app, ["scan", str(tmp_path)], env={"AISBOM_NO_TELEMETRY": "1"}
    )
    assert result.exit_code == 2
    assert "CRITICAL" in result.stdout


def test_cli_exits_0_on_a_benign_npy(tmp_path):
    from typer.testing import CliRunner
    from aisbom.cli import app

    np.save(tmp_path / "weights.npy", np.arange(32, dtype=np.float32))
    result = CliRunner().invoke(
        app, ["scan", str(tmp_path)], env={"AISBOM_NO_TELEMETRY": "1"}
    )
    assert result.exit_code == 0
