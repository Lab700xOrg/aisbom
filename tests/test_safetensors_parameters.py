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
