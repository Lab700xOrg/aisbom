"""ONNX scanning: protobuf metadata, custom operators, and external data.

ONNX carries no pickle, so nothing here is about a payload inside the file.
The signals are what *loading* the model would make a runtime reach for: an
operator from a domain that needs a custom native op library, and tensors
stored outside the model file — where a path that climbs out of the model
directory turns `load_model` into an arbitrary-file read.

No ONNX runtime is imported by the scanner. The `onnx` library appears here as
a **dev-only** dependency, used to cross-validate in both directions: that the
hand-written protobuf walk reads models the real library produced, and that the
hand-written generator produces models the real library accepts.
"""

import json

import pytest

from aisbom.mock_generator import create_mock_onnx
from aisbom.properties import build_component_properties
from aisbom.protobuf_reader import (
    iter_fields,
    parse_message,
    read_varint,
    TruncatedMessage,
)
from aisbom.safety import (
    external_location_escapes,
    onnx_domain_is_custom,
    scan_onnx_model,
)
from aisbom.scanner import DeepScanner

onnx = pytest.importorskip("onnx", reason="onnx is a dev-only fixture dependency")


# --- protobuf_reader ------------------------------------------------------

def test_read_varint_single_and_multibyte():
    assert read_varint(b"\x01", 0) == (1, 1)
    assert read_varint(b"\xac\x02", 0) == (300, 2)


def test_read_varint_raises_on_truncation():
    with pytest.raises(TruncatedMessage):
        read_varint(b"\xac", 0)


def test_parse_message_groups_repeated_fields():
    buf = b"\x08\x01" + b"\x08\x02" + b"\x12\x03abc"
    fields = parse_message(buf)
    assert fields[1] == [1, 2]
    assert fields[2] == [b"abc"]


def test_iter_fields_stops_cleanly_on_truncated_varint():
    # Field 1 is complete; the second tag's varint runs off the end.
    assert list(iter_fields(b"\x08\x01\x10")) == [(1, 0, 1)]


def test_iter_fields_returns_partial_payload_when_length_overruns():
    """A length that exceeds the buffer yields the bytes we actually hold.

    This is the multi-gigabyte-model case: the graph declares its full size but
    only the head was read, and that head is still worth parsing.
    """
    buf = b"\x12\x40" + b"only-ten-b"
    assert list(iter_fields(buf)) == [(2, 2, b"only-ten-b")]


def test_iter_fields_rejects_field_zero_and_bad_wire_type():
    assert list(iter_fields(b"\x00\x01")) == []      # field number 0
    assert list(iter_fields(b"\x0b\x01")) == []      # wire type 3 (group)


def test_parse_message_on_random_bytes_does_not_raise():
    parse_message(bytes(range(256)))


# --- external-path judgement ---------------------------------------------

@pytest.mark.parametrize("location", [
    "../secrets.bin",
    "../../../etc/passwd",
    "weights/../../escape.bin",
    "/etc/passwd",
    "\\\\server\\share\\x.bin",
    "C:\\Windows\\system32\\x.bin",
    "http://attacker.example/w.bin",
    "file:///etc/passwd",
    "s3://bucket/w.bin",
])
def test_locations_that_escape_the_model_directory(location):
    assert external_location_escapes(location) is True


@pytest.mark.parametrize("location", [
    "weights.bin",
    "./weights.bin",
    "shards/weights-00001.bin",
    "a/../b.bin",          # resolves back to the model directory
    "a/b/../../c.bin",     # ditto, deeper
])
def test_locations_that_stay_inside_the_model_directory(location):
    assert external_location_escapes(location) is False


def test_empty_and_non_string_locations_are_not_escapes():
    assert external_location_escapes("") is False
    assert external_location_escapes(None) is False


def test_standard_and_custom_domains():
    assert onnx_domain_is_custom("") is False
    assert onnx_domain_is_custom("ai.onnx") is False
    assert onnx_domain_is_custom("ai.onnx.ml") is False
    assert onnx_domain_is_custom(None) is False
    assert onnx_domain_is_custom("com.attacker.ops") is True


# --- scan_onnx_model ------------------------------------------------------

def test_clean_model_structure_has_no_threats():
    assert scan_onnx_model({"custom_ops": [], "external_data": []}) == []
    assert scan_onnx_model({}) == []


def test_escaping_external_data_is_reported_distinctly():
    threats = scan_onnx_model({"external_data": [{"location": "../../etc/passwd"}]})
    assert threats == ["ONNX_EXTERNAL_DATA_ESCAPE: ../../etc/passwd"]


def test_contained_external_data_is_reported_but_not_as_an_escape():
    threats = scan_onnx_model({"external_data": [{"location": "weights.bin"}]})
    assert threats == ["ONNX_EXTERNAL_DATA: weights.bin"]


def test_custom_op_is_reported():
    threats = scan_onnx_model(
        {"custom_ops": [{"op_type": "Evil", "domain": "com.attacker"}]}
    )
    assert threats == ["ONNX_CUSTOM_OP: com.attacker.Evil"]


# --- DeepScanner end to end ----------------------------------------------

def test_standard_model_scans_clean_with_metadata(tmp_path):
    create_mock_onnx(tmp_path / "model.onnx")
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["framework"] == "ONNX"
    assert art["type"] == "machine-learning-model"
    assert art["risk_level"] == "LOW"
    assert len(art["hash"]) == 64

    details = art["details"]
    assert details["ir_version"] == 9
    assert details["producer_name"] == "aisbom-mock"
    assert details["producer_version"] == "1.0.0"
    assert details["graph_name"] == "mock_graph"
    assert details["op_types"] == ["Relu"]
    assert details["opsets"] == [{"domain": "", "version": 17}]
    assert details["threats"] == []
    assert details["parsed"] is True


def test_custom_op_model_is_flagged_medium(tmp_path):
    create_mock_onnx(tmp_path / "custom.onnx", custom_op=True)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "MEDIUM" in art["risk_level"]
    assert "CRITICAL" not in art["risk_level"]
    assert art["details"]["custom_ops"] == [
        {"op_type": "MyCustomOp", "domain": "com.example.ops"}
    ]
    assert any(t.startswith("ONNX_CUSTOM_OP:") for t in art["details"]["threats"])


def test_external_data_inside_directory_is_medium(tmp_path):
    create_mock_onnx(tmp_path / "ext.onnx", external_location="weights.bin")
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "MEDIUM" in art["risk_level"]
    assert art["details"]["external_data"][0]["location"] == "weights.bin"
    assert art["details"]["external_data"][0]["offset"] == "0"


def test_external_data_traversal_is_critical(tmp_path):
    create_mock_onnx(tmp_path / "evil.onnx", external_location="../../../etc/passwd")
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert "../../../etc/passwd" in art["risk_level"]
    assert any(
        t.startswith("ONNX_EXTERNAL_DATA_ESCAPE:") for t in art["details"]["threats"]
    )


def test_garbage_onnx_file_is_not_reported_as_a_model(tmp_path):
    (tmp_path / "junk.onnx").write_bytes(b"this is not a protobuf at all, really")
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" not in art["risk_level"]
    assert art["details"]["parsed"] is False


def test_empty_onnx_file_does_not_crash(tmp_path):
    (tmp_path / "empty.onnx").write_bytes(b"")
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["framework"] == "ONNX"
    assert art["details"]["parsed"] is False


def test_truncated_model_still_reports_the_nodes_it_covers(tmp_path, monkeypatch):
    """Reading only the head of a large model must still yield its graph."""
    import aisbom.scanner as scanner_mod

    full = create_mock_onnx(
        tmp_path / "big.onnx", custom_op=True, external_location="w.bin"
    ).read_bytes()
    # Force the budget below the file size so the read genuinely truncates.
    monkeypatch.setattr(scanner_mod, "ONNX_MAX_SCAN_BYTES", len(full) - 12)

    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]
    assert art["details"]["truncated"] is True
    # The head carries the nodes, so the custom operator is still seen.
    assert art["details"]["node_count"] >= 1


# --- cross-validation against the real onnx library ----------------------

def _real_onnx_model(tmp_path, custom_op=False, external_location=None):
    """Build a model with the onnx library itself, for cross-validation."""
    import numpy as np
    from onnx import TensorProto, helper, numpy_helper

    if custom_op:
        nodes = [helper.make_node(
            "RealCustomOp", ["x"], ["y"], name="n0", domain="org.thirdparty",
        )]
        opsets = [helper.make_opsetid("", 17), helper.make_opsetid("org.thirdparty", 3)]
    else:
        nodes = [helper.make_node("Relu", ["x"], ["y"], name="n0")]
        opsets = [helper.make_opsetid("", 17)]

    initializers = []
    if external_location is not None:
        tensor = numpy_helper.from_array(np.ones((2, 2), dtype=np.float32), name="W")
        tensor.data_location = TensorProto.EXTERNAL
        tensor.ClearField("raw_data")
        for key, value in (("location", external_location), ("offset", "0"), ("length", "16")):
            entry = tensor.external_data.add()
            entry.key, entry.value = key, value
        initializers.append(tensor)

    graph = helper.make_graph(
        nodes, "real_graph",
        [helper.make_tensor_value_info("x", TensorProto.FLOAT, [1, 2])],
        [helper.make_tensor_value_info("y", TensorProto.FLOAT, [1, 2])],
        initializer=initializers,
    )
    model = helper.make_model(
        graph, producer_name="pytorch", producer_version="2.4.0", opset_imports=opsets
    )
    model.ir_version = 9
    path = tmp_path / "real.onnx"
    path.write_bytes(model.SerializeToString())
    return path


def test_parser_reads_a_model_built_by_the_onnx_library(tmp_path):
    """The hand-written protobuf walk must handle real library output."""
    _real_onnx_model(tmp_path)
    details = DeepScanner(str(tmp_path)).scan()["artifacts"][0]["details"]

    assert details["parsed"] is True
    assert details["ir_version"] == 9
    assert details["producer_name"] == "pytorch"
    assert details["producer_version"] == "2.4.0"
    assert details["graph_name"] == "real_graph"
    assert details["op_types"] == ["Relu"]
    assert {"domain": "", "version": 17} in details["opsets"]
    assert details["threats"] == []


def test_parser_finds_a_custom_op_in_a_real_model(tmp_path):
    _real_onnx_model(tmp_path, custom_op=True)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["details"]["custom_ops"] == [
        {"op_type": "RealCustomOp", "domain": "org.thirdparty"}
    ]
    assert "MEDIUM" in art["risk_level"]


def test_parser_finds_an_external_data_escape_in_a_real_model(tmp_path):
    _real_onnx_model(tmp_path, external_location="../../../../etc/shadow")
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert art["details"]["external_data"][0]["location"] == "../../../../etc/shadow"


def test_generated_mock_is_accepted_by_the_onnx_library(tmp_path):
    """The stdlib generator must emit protobuf the real library can load.

    Without this the tests could be self-consistent and both wrong.
    """
    path = create_mock_onnx(tmp_path / "m.onnx", custom_op=True, external_location="w.bin")
    # `load_external_data=False` matters: the default resolves the external
    # path against the filesystem and opens it. That eager read is exactly the
    # behaviour that makes an escaping location dangerous, and it is why this
    # scanner judges the path textually instead of touching it.
    model = onnx.load(str(path), load_external_data=False)

    assert model.ir_version == 9
    assert model.producer_name == "aisbom-mock"
    assert model.graph.name == "mock_graph"
    assert [n.op_type for n in model.graph.node] == ["Relu", "MyCustomOp"]
    assert model.graph.node[1].domain == "com.example.ops"
    assert model.graph.initializer[0].external_data[0].key == "location"
    assert model.graph.initializer[0].external_data[0].value == "w.bin"


# --- subgraphs -------------------------------------------------------------

def _model_with_subgraph(tmp_path, external_location=None, custom_domain=None):
    """An `If` node whose branch is a subgraph — a real executable graph."""
    import numpy as np
    from onnx import TensorProto, helper, numpy_helper

    inner_nodes = []
    if custom_domain:
        inner_nodes.append(helper.make_node(
            "HiddenOp", ["x"], ["y"], name="hidden", domain=custom_domain
        ))
    else:
        inner_nodes.append(helper.make_node("Relu", ["x"], ["y"], name="inner"))

    initializers = []
    if external_location is not None:
        tensor = numpy_helper.from_array(np.ones((2, 2), dtype=np.float32), name="HW")
        tensor.data_location = TensorProto.EXTERNAL
        tensor.ClearField("raw_data")
        for key, value in (("location", external_location), ("offset", "0"), ("length", "16")):
            entry = tensor.external_data.add()
            entry.key, entry.value = key, value
        initializers.append(tensor)

    then_graph = helper.make_graph(
        inner_nodes, "then_body", [],
        [helper.make_tensor_value_info("y", TensorProto.FLOAT, [1, 2])],
        initializer=initializers,
    )
    else_graph = helper.make_graph(
        [helper.make_node("Identity", ["x"], ["y"], name="else_node")], "else_body", [],
        [helper.make_tensor_value_info("y", TensorProto.FLOAT, [1, 2])],
    )
    node = helper.make_node(
        "If", ["cond"], ["y"], then_branch=then_graph, else_branch=else_graph
    )
    graph = helper.make_graph(
        [node], "outer",
        [helper.make_tensor_value_info("cond", TensorProto.BOOL, [1])],
        [helper.make_tensor_value_info("y", TensorProto.FLOAT, [1, 2])],
    )
    model = helper.make_model(graph, producer_name="sub", opset_imports=[
        helper.make_opsetid("", 17)
    ] + ([helper.make_opsetid(custom_domain, 1)] if custom_domain else []))
    model.ir_version = 9
    path = tmp_path / "sub.onnx"
    path.write_bytes(model.SerializeToString())
    return path


def test_custom_op_inside_a_subgraph_is_found(tmp_path):
    """`If`/`Loop`/`Scan` carry graphs in their attributes, and those execute."""
    _model_with_subgraph(tmp_path, custom_domain="com.attacker.hidden")
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["details"]["subgraph_count"] >= 1
    assert any(
        o["domain"] == "com.attacker.hidden" for o in art["details"]["custom_ops"]
    ), art["details"]["custom_ops"]
    assert "MEDIUM" in art["risk_level"]


def test_external_data_escape_inside_a_subgraph_is_critical(tmp_path):
    """A traversal path one branch down must still trip the gate."""
    _model_with_subgraph(tmp_path, external_location="../../../../etc/passwd")
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert any(
        e.get("location") == "../../../../etc/passwd"
        for e in art["details"]["external_data"]
    )


def test_a_model_without_subgraphs_reports_none(tmp_path):
    create_mock_onnx(tmp_path / "flat.onnx")
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]
    assert art["details"]["subgraph_count"] == 0


# --- large models: seeking past bulk tensor data --------------------------

def test_external_data_after_a_large_inline_tensor_is_found(tmp_path, monkeypatch):
    """A big inline tensor must not hide the entries behind it.

    ONNX stores weights inline, so a window read from the front stops inside
    the first large tensor. Since a tensor pointing at *external* data carries
    no inline payload, bulk data can be stepped over rather than buffered.
    """
    import numpy as np
    import aisbom.scanner as scanner_mod
    from onnx import TensorProto, helper, numpy_helper

    # A genuinely large inline initializer, placed before the external one.
    big = numpy_helper.from_array(
        np.zeros((512, 512), dtype=np.float32), name="bulk"
    )
    external = numpy_helper.from_array(
        np.ones((2, 2), dtype=np.float32), name="W"
    )
    external.data_location = TensorProto.EXTERNAL
    external.ClearField("raw_data")
    for key, value in (("location", "../../secret.bin"), ("offset", "0"), ("length", "16")):
        entry = external.external_data.add()
        entry.key, entry.value = key, value

    graph = helper.make_graph(
        [helper.make_node("Relu", ["x"], ["y"], name="n")], "big_graph",
        [helper.make_tensor_value_info("x", TensorProto.FLOAT, [1, 2])],
        [helper.make_tensor_value_info("y", TensorProto.FLOAT, [1, 2])],
        initializer=[big, external],
    )
    model = helper.make_model(graph, producer_name="big",
                              opset_imports=[helper.make_opsetid("", 17)])
    model.ir_version = 9
    path = tmp_path / "big.onnx"
    path.write_bytes(model.SerializeToString())

    # Force the buffered window well below the bulk tensor so the head read
    # genuinely stops inside it.
    monkeypatch.setattr(scanner_mod, "ONNX_MAX_SCAN_BYTES", 4096)

    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"], art["risk_level"]
    assert any(
        e.get("location") == "../../secret.bin" for e in art["details"]["external_data"]
    )


# --- Hugging Face resolution ----------------------------------------------

def test_onnx_files_are_resolved_from_a_hugging_face_repo(monkeypatch):
    """The dispatch arm is unreachable for `hf://` unless the resolver lists it."""
    import aisbom.remote as remote

    def fake_get(url, headers=None):
        class Resp:
            status_code = 200
            headers = {}

            def raise_for_status(self):
                pass

            def json(self):
                return [{"path": "model.onnx"}, {"path": "README.md"}]

        return Resp()

    monkeypatch.setattr(remote, "requests", remote._RequestsStub())
    monkeypatch.setattr(remote.requests, "get", fake_get)

    urls = remote.resolve_huggingface_repo("hf://org/model")
    assert any(u.endswith("model.onnx") for u in urls), urls


# --- SBOM plumbing --------------------------------------------------------

def test_onnx_format_token_is_registered():
    art = {"framework": "ONNX", "risk_level": "LOW", "legal_status": "UNKNOWN", "details": {}}
    assert dict(build_component_properties(art))["aisbom:format"] == "onnx"


def test_onnx_properties_carry_metadata_and_findings(tmp_path):
    create_mock_onnx(tmp_path / "m.onnx", custom_op=True, external_location="../out.bin")
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]
    props = build_component_properties(art)
    as_dict = dict(props)
    names = {n for n, _ in props}

    assert as_dict["aisbom:format"] == "onnx"
    assert as_dict["aisbom:onnx:ir_version"] == "9"
    assert as_dict["aisbom:onnx:producer_name"] == "aisbom-mock"
    assert as_dict["aisbom:onnx:graph_name"] == "mock_graph"
    assert "ai.onnx:17" in as_dict["aisbom:onnx:opsets"]
    assert as_dict["aisbom:onnx:custom_op_count"] == "1"
    assert "com.example.ops.MyCustomOp" in as_dict["aisbom:onnx:custom_ops"]
    assert as_dict["aisbom:onnx:external_data_count"] == "1"
    assert as_dict["aisbom:onnx:external_data_location"] == "../out.bin"
    assert "aisbom:onnx:threat" in names
    assert as_dict["aisbom:risk"].startswith("CRITICAL")


def test_onnx_appears_in_spdx_export(tmp_path):
    from aisbom.spdx_gen import generate_spdx_sbom

    create_mock_onnx(tmp_path / "m.onnx")
    results = DeepScanner(str(tmp_path)).scan()

    doc = json.loads(generate_spdx_sbom(results))
    pkg = next(p for p in doc["packages"] if p["name"] == "m.onnx")
    assert "Type: onnx" in pkg["comment"]
    assert "Framework: ONNX" in pkg["comment"]


# --- CLI ------------------------------------------------------------------

def test_external_data_escape_exits_two(tmp_path, monkeypatch):
    """A traversal path must trip the CI gate.

    Asserts on output as well as the code, because Typer exits 2 on a usage
    error too — the exit code alone could pass for the wrong reason.
    """
    from typer.testing import CliRunner
    from aisbom.cli import app

    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    create_mock_onnx(tmp_path / "evil.onnx", external_location="../../etc/passwd")
    result = CliRunner().invoke(app, ["scan", str(tmp_path)])

    assert "evil.onnx" in result.output, result.output
    assert "CRITICAL" in result.output, result.output
    assert result.exit_code == 2, result.output


def test_custom_op_alone_does_not_trip_the_gate(tmp_path, monkeypatch):
    """MEDIUM must not exit 2, or the signal becomes unusable in CI."""
    from typer.testing import CliRunner
    from aisbom.cli import app

    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    create_mock_onnx(tmp_path / "custom.onnx", custom_op=True)
    result = CliRunner().invoke(app, ["scan", str(tmp_path)])

    assert "custom.onnx" in result.output, result.output
    assert result.exit_code == 0, result.output


# --- remote ---------------------------------------------------------------

def test_remote_onnx_is_scanned(monkeypatch, tmp_path):
    """Remote ONNX must be scanned, not silently skipped."""
    import aisbom.remote as remote

    content = create_mock_onnx(
        tmp_path / "remote.onnx", external_location="../../escape.bin"
    ).read_bytes()

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

    monkeypatch.setattr(remote, "requests", remote._RequestsStub())
    monkeypatch.setattr(remote.requests, "get", fake_get)
    monkeypatch.setattr(
        "aisbom.scanner.DeepScanner._resolve_remote_targets",
        lambda self, target: ["http://example.com/remote.onnx"],
    )

    results = DeepScanner("http://example.com/remote.onnx").scan()
    art = results["artifacts"][0]

    assert results["errors"] == []
    assert art["framework"] == "ONNX"
    assert "CRITICAL" in art["risk_level"]
    assert art["hash"] == "remote_unhashed"
