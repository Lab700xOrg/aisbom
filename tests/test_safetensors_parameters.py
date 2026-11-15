"""Per-file parameter count read from a safetensors header.

The header lists every tensor's shape, so a file's parameter count is the sum
of the shapes' products. It is recorded only when every tensor entry has a
well-formed shape: one malformed entry would make the sum silently low.
"""

import json
import struct

import pytest

from aisbom.properties import build_component_properties
from aisbom.scanner import DeepScanner


def write_safetensors(path, header):
    raw = json.dumps(header).encode()
    path.write_bytes(struct.pack("<Q", len(raw)) + raw)


def scan_one(tmp_path, header, name="model.safetensors"):
    write_safetensors(tmp_path / name, header)
    arts = DeepScanner(str(tmp_path)).scan()["artifacts"]
    return next(a for a in arts if a["name"] == name)


def test_parameters_are_the_sum_of_tensor_shape_products(tmp_path):
    art = scan_one(tmp_path, {
        "__metadata__": {"format": "pt"},
        "w": {"dtype": "F32", "shape": [3, 4], "data_offsets": [0, 48]},
        "b": {"dtype": "F32", "shape": [4], "data_offsets": [48, 64]},
        "s": {"dtype": "F32", "shape": [], "data_offsets": [64, 68]},  # scalar = 1
    })
    assert art["details"]["parameters"] == 3 * 4 + 4 + 1
    props = dict(build_component_properties(art))
    assert props["aisbom:safetensors:parameters"] == "17"


@pytest.mark.parametrize("bad", [
    {"dtype": "F32"},                         # no shape
    {"dtype": "F32", "shape": "3x4"},         # not a list
    {"dtype": "F32", "shape": [3, -1]},       # negative dimension
    {"dtype": "F32", "shape": [3, 1.5]},      # non-integer
    {"dtype": "F32", "shape": [True, 2]},     # bool masquerading as int
    "not-a-tensor",
])
def test_one_malformed_entry_leaves_the_count_unrecorded(tmp_path, bad):
    art = scan_one(tmp_path, {
        "w": {"dtype": "F32", "shape": [3, 4], "data_offsets": [0, 48]},
        "x": bad,
    })
    assert "parameters" not in art["details"]
    assert "aisbom:safetensors:parameters" not in dict(build_component_properties(art))


def test_a_header_with_no_tensors_records_no_count(tmp_path):
    art = scan_one(tmp_path, {"__metadata__": {"format": "pt"}})
    assert "parameters" not in art["details"]


# --- Complete shard sets ---------------------------------------------------

def _tensor(n):
    return {"w": {"dtype": "F32", "shape": [n], "data_offsets": [0, 4 * n]}}


def _shard(directory, index, total, n):
    directory.mkdir(parents=True, exist_ok=True)
    write_safetensors(directory / f"model-{index:05d}-of-{total:05d}.safetensors", _tensor(n))


def _scan(tmp_path):
    return DeepScanner(str(tmp_path)).scan()["artifacts"]


def test_a_complete_set_in_one_directory_is_marked_on_every_shard(tmp_path):
    _shard(tmp_path / "m", 1, 2, 100)
    _shard(tmp_path / "m", 2, 2, 200)
    arts = _scan(tmp_path)
    assert {a["details"]["set_parameters"] for a in arts} == {300}
    props = dict(build_component_properties(arts[0]))
    assert props["aisbom:safetensors:set_parameters"] == "300"
    assert props["aisbom:safetensors:set_shards"] == "2"


def test_halves_of_two_models_in_different_directories_are_not_a_set(tmp_path):
    """Component names are basenames, so only the scanner can tell these
    apart; neither model is complete."""
    _shard(tmp_path / "a", 1, 2, 100)
    _shard(tmp_path / "b", 2, 2, 200)
    for art in _scan(tmp_path):
        assert "set_parameters" not in art["details"]


def test_two_complete_sets_in_different_directories_are_marked_separately(tmp_path):
    for d, n in (("a", 10), ("b", 20)):
        _shard(tmp_path / d, 1, 2, n)
        _shard(tmp_path / d, 2, 2, n)
    totals = sorted(a["details"]["set_parameters"] for a in _scan(tmp_path))
    assert totals == [20, 20, 40, 40]


def test_a_missing_shard_leaves_the_set_unmarked(tmp_path):
    _shard(tmp_path, 1, 3, 100)
    _shard(tmp_path, 3, 3, 300)
    for art in _scan(tmp_path):
        assert "set_parameters" not in art["details"]


def test_a_shard_without_a_count_leaves_the_set_unmarked(tmp_path):
    _shard(tmp_path, 1, 2, 100)
    write_safetensors(tmp_path / "model-00002-of-00002.safetensors",
                      {"w": {"dtype": "F32", "shape": "bad"}})
    for art in _scan(tmp_path):
        assert "set_parameters" not in art["details"]


def test_remote_style_names_group_by_their_repo_directory():
    scanner = DeepScanner.__new__(DeepScanner)
    scanner._local_paths = {}
    scanner.artifacts = [
        {"name": f"{d}/model-0000{i}-of-00002.safetensors", "framework": "SafeTensors",
         "details": {"parameters": 5}}
        for d, i in (("x", 1), ("y", 2))
    ]
    scanner._mark_complete_safetensors_sets()
    assert all("set_parameters" not in a["details"] for a in scanner.artifacts)

    scanner.artifacts = [
        {"name": f"x/model-0000{i}-of-00002.safetensors", "framework": "SafeTensors",
         "details": {"parameters": 5}} for i in (1, 2)
    ]
    scanner._mark_complete_safetensors_sets()
    assert all(a["details"]["set_parameters"] == 10 for a in scanner.artifacts)
