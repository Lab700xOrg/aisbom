"""Parameter count read from a GGUF file's tensor-info block.

The tensor-info block follows the KV metadata and lists every tensor's
dimensions. The dimensions are logical element counts, so a quantised file
still yields the model's true parameter count. As with safetensors the count
is all-or-nothing: a truncated or malformed block records nothing rather than
a silently low number, and only a complete single file or a complete split set
counts.
"""

import io
import struct

import pytest

from aisbom import comply
from aisbom.properties import build_component_properties
from aisbom.scanner import (
    GGUF_REMOTE_FIRST_WINDOW,
    GGUF_REMOTE_MAX_WINDOW,
    DeepScanner,
)

U16, U32, STRING, ARRAY = 2, 4, 8, 9


def _str(s):
    raw = s.encode()
    return struct.pack("<Q", len(raw)) + raw


def _kv(key, val_type, value):
    out = _str(key) + struct.pack("<I", val_type)
    if val_type == STRING:
        return out + _str(value)
    if val_type == U16:
        return out + struct.pack("<H", value)
    if val_type == U32:
        return out + struct.pack("<I", value)
    if val_type == ARRAY:  # array of u32 of the given length
        return out + struct.pack("<IQ", U32, value) + b"\0" * (4 * value)
    raise AssertionError(val_type)


def _tensor(name, dims, ggml_type=0, offset=0):
    return (_str(name) + struct.pack("<I", len(dims))
            + b"".join(struct.pack("<Q", d) for d in dims)
            + struct.pack("<IQ", ggml_type, offset))


def gguf_bytes(tensors, kvs=(), tensor_count=None, tail=b""):
    """A GGUF v3 header: KV pairs, then one tensor-info record per tensor."""
    kv_blob = b"".join(_kv(*kv) for kv in kvs)
    info = b"".join(_tensor(n, d) for n, d in tensors)
    count = len(tensors) if tensor_count is None else tensor_count
    return (b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", count)
            + struct.pack("<Q", len(kvs)) + kv_blob + info + tail)


ARCH = ("general.architecture", STRING, "llama")
TENSORS = [("tok_embd", [64, 100]), ("blk.0.attn_q", [64, 64]), ("norm", [64])]
TOTAL = 64 * 100 + 64 * 64 + 64


def scan_one(tmp_path, data, name="model.gguf"):
    (tmp_path / name).write_bytes(data)
    arts = DeepScanner(str(tmp_path)).scan()["artifacts"]
    return next(a for a in arts if a["name"] == name)


# --- Per-file count --------------------------------------------------------

def test_parameters_are_the_sum_of_tensor_dimension_products(tmp_path):
    art = scan_one(tmp_path, gguf_bytes(TENSORS, [ARCH]))
    assert art["details"]["parameters"] == TOTAL
    props = dict(build_component_properties(art))
    assert props["aisbom:gguf:parameters"] == str(TOTAL)
    # The existing findings are untouched.
    assert props["aisbom:gguf:architecture"] == "llama"
    assert art["risk_level"] == "LOW"


def test_the_tensor_block_is_found_after_arrays_and_strings(tmp_path):
    kvs = [ARCH, ("tokenizer.ggml.token_type", ARRAY, 500),
           ("general.name", STRING, "x" * 300)]
    art = scan_one(tmp_path, gguf_bytes(TENSORS, kvs))
    assert art["details"]["parameters"] == TOTAL


def test_a_file_with_no_tensors_records_no_count(tmp_path):
    art = scan_one(tmp_path, gguf_bytes([], [ARCH]))
    assert "parameters" not in art["details"]


@pytest.mark.parametrize("data", [
    # Header promises more tensors than the file holds.
    gguf_bytes(TENSORS, [ARCH], tensor_count=5),
    # Cut off in the middle of the last record.
    gguf_bytes(TENSORS, [ARCH])[:-6],
    # More dimensions than ggml supports.
    gguf_bytes([("w", [2, 2, 2, 2, 2])], [ARCH]),
    # A dimension so large the element count cannot be real.
    gguf_bytes([("w", [2 ** 62, 4])], [ARCH]),
])
def test_malformed_or_truncated_tensor_info_records_no_count(tmp_path, data):
    art = scan_one(tmp_path, data)
    assert "parameters" not in art["details"]
    assert "error" not in art["details"]
    assert "aisbom:gguf:parameters" not in dict(build_component_properties(art))


def test_truncated_metadata_records_no_count(tmp_path):
    data = gguf_bytes(TENSORS, [ARCH, ("general.name", STRING, "x" * 100)])
    cut = data.index(b"x" * 100) + 10
    art = scan_one(tmp_path, data[:cut])
    assert "parameters" not in art["details"]


def test_tensor_info_reader_never_raises_on_garbage():
    for blob in (b"", b"\xff" * 7, b"\x00" * 40, b"\xff" * 400):
        assert DeepScanner._parse_gguf_tensor_info(blob, 0, 3)["parameters"] is None


# --- Remote window ---------------------------------------------------------

class _Remote(io.BytesIO):
    name = "model.gguf"

    def __init__(self, data):
        super().__init__(data)
        self.reads = []

    def read(self, n=-1):
        self.reads.append(n)
        return super().read(n)


def _remote(data):
    scanner = DeepScanner.__new__(DeepScanner)
    stream = _Remote(data)
    art = scanner._inspect_gguf(stream, "model.gguf", is_remote=True)
    return art, stream


def test_remote_tensor_info_inside_the_first_window_is_counted_in_one_read():
    art, stream = _remote(gguf_bytes(TENSORS, [ARCH]))
    assert art["details"]["parameters"] == TOTAL


def test_remote_widens_once_when_only_the_tensor_info_is_cut_off():
    # Metadata fits the first window; the tensor block straddles its end.
    filler = GGUF_REMOTE_FIRST_WINDOW - 2000
    many = [(f"t{i:05d}", [4]) for i in range(200)]
    data = gguf_bytes(many, [ARCH, ("general.name", STRING, "x" * filler)],
                      tail=b"\0" * GGUF_REMOTE_FIRST_WINDOW)
    art, stream = _remote(data)
    assert art["details"]["parameters"] == 800
    assert GGUF_REMOTE_MAX_WINDOW in stream.reads
    assert max(stream.reads) <= GGUF_REMOTE_MAX_WINDOW


def test_remote_tensor_info_beyond_the_max_window_stays_uncounted():
    filler = GGUF_REMOTE_MAX_WINDOW - 100
    data = gguf_bytes(TENSORS, [ARCH, ("general.name", STRING, "x" * filler)])
    art, stream = _remote(data)
    assert "parameters" not in art["details"]
    assert max(stream.reads) <= GGUF_REMOTE_MAX_WINDOW


# --- Split sets ------------------------------------------------------------

def _shard(directory, index, total, n, split_kv=True, name=None):
    directory.mkdir(parents=True, exist_ok=True)
    kvs = [ARCH]
    if split_kv:
        kvs += [("split.no", U16, index - 1), ("split.count", U16, total)]
    fname = name or f"model-{index:05d}-of-{total:05d}.gguf"
    (directory / fname).write_bytes(gguf_bytes([("w", [n])], kvs))


def _scan(tmp_path):
    return DeepScanner(str(tmp_path)).scan()["artifacts"]


def test_a_complete_split_set_is_marked_on_every_shard(tmp_path):
    _shard(tmp_path / "m", 1, 2, 100)
    _shard(tmp_path / "m", 2, 2, 200)
    arts = _scan(tmp_path)
    assert {a["details"]["set_parameters"] for a in arts} == {300}
    props = dict(build_component_properties(arts[0]))
    assert props["aisbom:gguf:set_parameters"] == "300"
    assert props["aisbom:gguf:set_shards"] == "2"
    assert props["aisbom:gguf:split_count"] == "2"


def test_halves_in_different_directories_are_not_a_set(tmp_path):
    _shard(tmp_path / "a", 1, 2, 100)
    _shard(tmp_path / "b", 2, 2, 200)
    for art in _scan(tmp_path):
        assert "set_parameters" not in art["details"]


def test_a_missing_shard_leaves_the_set_unmarked(tmp_path):
    _shard(tmp_path, 1, 3, 100)
    _shard(tmp_path, 3, 3, 300)
    for art in _scan(tmp_path):
        assert "set_parameters" not in art["details"]


def test_a_shard_whose_header_disagrees_with_its_name_leaves_the_set_unmarked(tmp_path):
    _shard(tmp_path, 1, 2, 100)
    (tmp_path / "model-00002-of-00002.gguf").write_bytes(gguf_bytes(
        [("w", [200])], [ARCH, ("split.no", U16, 0), ("split.count", U16, 3)]))
    for art in _scan(tmp_path):
        assert "set_parameters" not in art["details"]


def test_a_shard_without_a_count_leaves_the_set_unmarked(tmp_path):
    _shard(tmp_path, 1, 2, 100)
    (tmp_path / "model-00002-of-00002.gguf").write_bytes(
        gguf_bytes([("w", [200])], [ARCH], tensor_count=4))
    for art in _scan(tmp_path):
        assert "set_parameters" not in art["details"]


def test_a_renamed_shard_still_records_its_split_count(tmp_path):
    _shard(tmp_path, 1, 2, 100, name="model.gguf")
    art = _scan(tmp_path)[0]
    assert art["details"]["split_count"] == 2
    assert "set_parameters" not in art["details"]


def test_safetensors_and_gguf_sets_with_one_stem_do_not_mix(tmp_path):
    import json
    _shard(tmp_path, 1, 2, 100)
    raw = json.dumps({"w": {"dtype": "F32", "shape": [5], "data_offsets": [0, 20]}}).encode()
    (tmp_path / "model-00002-of-00002.safetensors").write_bytes(
        struct.pack("<Q", len(raw)) + raw)
    for art in _scan(tmp_path):
        assert "set_parameters" not in art["details"]


# --- comply pre-fill -------------------------------------------------------

def _gguf(name, params=None, split_count=None, set_total=None, set_shards=None):
    props = [{"name": "aisbom:format", "value": "gguf"},
             {"name": "aisbom:risk", "value": "LOW"}]
    if params is not None:
        props.append({"name": "aisbom:gguf:parameters", "value": str(params)})
    if split_count is not None:
        props.append({"name": "aisbom:gguf:split_count", "value": str(split_count)})
    if set_total is not None:
        props += [{"name": "aisbom:gguf:set_parameters", "value": str(set_total)},
                  {"name": "aisbom:gguf:set_shards", "value": str(set_shards)}]
    return {"type": "machine-learning-model", "name": name,
            "bom-ref": f"artifact-x-{name}", "properties": props}


def _params_line(*comps):
    from tests.test_comply import _eu
    annex = _eu({"components": list(comps)})[comply.ANNEX_XI_FILE]
    return next(l for l in annex.splitlines() if "**Number of parameters:**" in l)


def test_comply_counts_a_single_gguf_file_with_its_own_label():
    line = _params_line(_gguf("model-Q4_K_M.gguf", 494032768))
    assert "494,032,768 (model-Q4_K_M.gguf)" in line
    assert comply.SOURCE_SCAN_GGUF_PARAMETERS in line
    assert comply.SOURCE_SCAN_PARAMETERS not in line


def test_comply_shows_a_complete_gguf_set_once():
    line = _params_line(
        _gguf("model-00001-of-00002.gguf", 100, 2, 300, 2),
        _gguf("model-00002-of-00002.gguf", 200, 2, 300, 2),
    )
    assert "300 (model-*-of-00002.gguf, 2 shards)" in line
    assert line.count("300 (") == 1


def test_comply_never_sums_unmarked_gguf_shards():
    line = _params_line(
        _gguf("model-00001-of-00002.gguf", 100, 2),
        _gguf("model-00002-of-00002.gguf", 200, 2),
    )
    assert comply.TODO in line
    assert "300" not in line


def test_comply_does_not_count_a_renamed_shard_as_a_whole_model():
    line = _params_line(_gguf("model.gguf", 100, split_count=2))
    assert comply.TODO in line
    assert "100 (" not in line


def test_comply_counts_a_gguf_whose_split_count_is_one():
    line = _params_line(_gguf("model.gguf", 100, split_count=1))
    assert "100 (model.gguf)" in line
