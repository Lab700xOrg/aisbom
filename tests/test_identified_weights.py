"""Weights files that are not pickles, and must not be graded as unknown binaries.

A `.pt`/`.pth`/`.bin` that is neither a zip, nor a pickle, nor a path config
used to fall into one catch-all: `CRITICAL (Legacy Binary)`. A top-500 Hugging
Face sweep found that every HIGH/CRITICAL result came from it, and none was a
payload. The formats behind them are recognised here by their content.

The fixtures are built from header bytes read off the real files:

- CTranslate2 (all of faster-whisper): `Systran/faster-whisper-tiny` `model.bin`
- ONNX saved as `.pt`: `Falconsai/nsfw_image_detection`
- OpenVINO IR weights: `sentence-transformers/all-MiniLM-L6-v2` `openvino/`
- Core ML weights: `google-bert/bert-base-uncased` `coreml/…/weight.bin`, and
  the same header in four `.mlpackage`/`.mlmodelc` files from three other repos

Recognition only replaces the last step. The pickle scan still runs first, so
any of these names wrapped around a real payload is still CRITICAL.
"""

import io
import pickle
import struct
import zipfile

import pytest
import requests

import aisbom.remote as remote
import aisbom.scanner as scanner_module
from aisbom.mock_generator import create_mock_onnx
from aisbom.scanner import DeepScanner

# Non-text filler, so a fixture can never be classified by printability.
_FILLER = bytes(range(256)) * 8


def _harmful_pickle() -> bytes:
    """A pickle whose REDUCE would call os.system. Never loaded here."""
    return b"cos\nsystem\n(S'echo pwned'\ntR."


# --- fixtures -------------------------------------------------------------

def _ct2_bytes(version=6, spec=b"WhisperSpec", revision=3, variables=148) -> bytes:
    name = spec + b"\x00"
    first_var = b"decoder/activation\x00"
    return (
        struct.pack("<I", version)
        + struct.pack("<H", len(name)) + name
        + struct.pack("<I", revision)
        + struct.pack("<I", variables)
        + struct.pack("<H", len(first_var)) + first_var
        + _FILLER
    )


def _coreml_bytes(count=0xCB) -> bytes:
    return (
        struct.pack("<II", count, 2)
        + b"\x00" * 56
        + struct.pack("<I", 0xDEADBEEF)
        + struct.pack("<I", 2)
        + _FILLER
    )


_OPENVINO_XML = (
    '<?xml version="1.0"?>\n'
    '<net name="Model0" version="11">\n'
    "\t<layers>\n\t</layers>\n"
    "</net>\n"
)

# Raw little-endian float32 tensor data, which is all an IR `.bin` holds.
_OPENVINO_BIN = struct.pack("<64f", *[(i - 32) / 97.0 for i in range(64)]) + _FILLER


def _scan_one(path) -> tuple[dict, list]:
    results = DeepScanner(str(path)).scan()
    (art,) = results["artifacts"]
    return art, results["errors"]


# --- SBOM format token -----------------------------------------------------

@pytest.mark.parametrize("framework,token", [
    ("CTranslate2", "ctranslate2"),
    ("OpenVINO IR", "openvino"),
    ("Core ML", "coreml"),
])
def test_identified_formats_emit_a_format_token_and_no_pickle_properties(framework, token):
    from aisbom.properties import build_component_properties

    props = dict(build_component_properties({
        "framework": framework, "risk_level": "LOW", "details": {"threats": []},
    }))

    assert props["aisbom:format"] == token
    assert not any(name.startswith("aisbom:pickle:") for name in props)


# --- CTranslate2 ----------------------------------------------------------

def test_ctranslate2_model_bin_is_low_and_named(tmp_path):
    path = tmp_path / "model.bin"
    path.write_bytes(_ct2_bytes())

    art, errors = _scan_one(path)

    assert art["risk_level"] == "LOW"
    assert art["framework"] == "CTranslate2"
    assert art["details"]["binary_version"] == 6
    assert art["details"]["spec"] == "WhisperSpec"
    assert art["details"]["spec_revision"] == 3
    assert art["details"]["variable_count"] == 148
    assert errors == []


def test_ctranslate2_other_specs_are_recognised(tmp_path):
    path = tmp_path / "model.bin"
    path.write_bytes(_ct2_bytes(spec=b"TransformerSpec", revision=7, version=5))
    art, _ = _scan_one(path)
    assert art["framework"] == "CTranslate2"
    assert art["details"]["spec"] == "TransformerSpec"


@pytest.mark.parametrize("blob", [
    _ct2_bytes(spec=b"Whisper"),          # spec name must end in "Spec"
    _ct2_bytes(version=99),               # no such binary version
    _ct2_bytes(variables=0),              # a model with no variables
    _ct2_bytes(spec=b"Whis\x01perSpec"),  # not an identifier
])
def test_ctranslate2_near_misses_stay_in_the_catch_all(tmp_path, blob):
    path = tmp_path / "model.bin"
    path.write_bytes(blob)
    art, _ = _scan_one(path)
    assert art["risk_level"] == "CRITICAL (Legacy Binary)"


# --- ONNX under a PyTorch extension ----------------------------------------

@pytest.mark.parametrize("filename", ["falconsai_yolov9_nsfw_model_quantized.pt", "model.bin"])
def test_onnx_saved_with_a_pytorch_extension_is_inspected_as_onnx(tmp_path, filename):
    onnx_path = create_mock_onnx(tmp_path / "real.onnx")
    path = tmp_path / filename
    path.write_bytes(onnx_path.read_bytes())
    onnx_path.unlink()

    art, errors = _scan_one(path)

    assert art["framework"] == "ONNX"
    assert art["risk_level"] == "LOW"
    assert art["details"]["identified_by_content"] is True
    assert art["details"]["graph_name"] == "mock_graph"
    assert errors == []


def test_onnx_custom_op_findings_survive_the_reroute(tmp_path):
    onnx_path = create_mock_onnx(tmp_path / "real.onnx", custom_op=True)
    path = tmp_path / "model.pt"
    path.write_bytes(onnx_path.read_bytes())
    onnx_path.unlink()

    art, _ = _scan_one(path)

    assert art["framework"] == "ONNX"
    assert art["risk_level"] != "LOW"
    assert art["details"]["custom_ops"]


def test_falconsai_onnx_head_is_recognised(tmp_path):
    """The exact head of the swept file: ir_version 7, producer, version, graph."""
    head = (
        b"\x08\x07"
        b"\x12\x0donnx.quantize"
        b"\x1a\x050.1.0"
        b":\xd9\x92\xc6\x29"  # field 7 (graph), declared ~87 MB
    )
    path = tmp_path / "falconsai_yolov9_nsfw_model_quantized.pt"
    path.write_bytes(head + b"\x0a\x61\x12\x21/vit/embeddings" + _FILLER)

    art, _ = _scan_one(path)

    assert art["framework"] == "ONNX"
    assert art["details"]["producer_name"] == "onnx.quantize"


@pytest.mark.parametrize("blob", [
    b"\x08\x07" + _FILLER,                   # one varint, then nothing ONNX
    b"\x08\x07\x12\x03abc\x98\x01\x05",      # unknown top-level field 19
    b"\x08\xc8\x01\x12\x03abc:\x02\x0a\x00",  # ir_version 200
    b"\x10\x07\x12\x03abc:\x02\x0a\x00",     # does not start with ir_version
])
def test_onnx_near_misses_stay_in_the_catch_all(tmp_path, blob):
    path = tmp_path / "model.pt"
    path.write_bytes(blob + _FILLER)
    art, _ = _scan_one(path)
    assert art["risk_level"] == "CRITICAL (Legacy Binary)"


# --- SafeTensors / GGUF under a PyTorch extension ---------------------------

def test_safetensors_saved_as_bin_is_inspected_as_safetensors(tmp_path):
    header = b'{"__metadata__":{"license":"mit"},"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    path = tmp_path / "pytorch_model.bin"
    path.write_bytes(struct.pack("<Q", len(header)) + header + b"\x00" * 4)

    art, errors = _scan_one(path)

    assert art["framework"] == "SafeTensors"
    assert art["details"]["identified_by_content"] is True
    assert errors == []


def test_gguf_saved_as_bin_is_inspected_as_gguf(tmp_path):
    # Version 3, zero tensors, zero metadata entries.
    path = tmp_path / "model.bin"
    path.write_bytes(b"GGUF" + struct.pack("<IQQ", 3, 0, 0))

    art, _ = _scan_one(path)

    assert art["framework"] == "GGUF"
    assert art["details"]["identified_by_content"] is True


# --- OpenVINO IR -----------------------------------------------------------

def test_openvino_bin_with_its_ir_graph_is_low(tmp_path):
    folder = tmp_path / "openvino"
    folder.mkdir()
    (folder / "openvino_model.xml").write_text(_OPENVINO_XML)
    (folder / "openvino_model.bin").write_bytes(_OPENVINO_BIN)

    results = DeepScanner(str(tmp_path)).scan()
    (art,) = results["artifacts"]

    assert art["risk_level"] == "LOW"
    assert art["framework"] == "OpenVINO IR"
    assert art["details"]["ir_graph"] == "openvino_model.xml"
    assert results["errors"] == []


def test_openvino_bin_alone_stays_in_the_catch_all(tmp_path):
    path = tmp_path / "openvino_model.bin"
    path.write_bytes(_OPENVINO_BIN)
    art, _ = _scan_one(path)
    assert art["risk_level"] == "CRITICAL (Legacy Binary)"


@pytest.mark.parametrize("xml", [
    '<?xml version="1.0"?>\n<html><body>not a graph</body></html>',
    "<netlist/>",
    "net",
    "",
])
def test_openvino_sibling_that_is_not_an_ir_graph_does_not_count(tmp_path, xml):
    (tmp_path / "openvino_model.xml").write_text(xml)
    path = tmp_path / "openvino_model.bin"
    path.write_bytes(_OPENVINO_BIN)
    art, _ = _scan_one(path)
    assert art["risk_level"] == "CRITICAL (Legacy Binary)"


def test_openvino_ir_graph_with_a_leading_comment_counts(tmp_path):
    (tmp_path / "m.xml").write_text("<?xml version='1.0'?>\n<!-- exported -->\n<net name='x'/>")
    path = tmp_path / "m.bin"
    path.write_bytes(_OPENVINO_BIN)
    art, _ = _scan_one(path)
    assert art["framework"] == "OpenVINO IR"


@pytest.mark.parametrize("xml_head", [
    b"<!-- -->" * 30 + b"x",                    # 30 comments, no root
    b"<!-- -->" * 500,                          # fills the 4 KB sniff window
    b"<?xml version='1.0'?>" + b"<!---->" * 580 + b"<netx",
])
def test_ir_graph_check_is_linear_on_hostile_prologs(xml_head):
    """A run of comments with no <net> root after it must fail fast.

    The first version used one regex for the whole prolog, and it backtracked
    exponentially here: 30 comments already took seconds.
    """
    import time

    start = time.perf_counter()
    assert DeepScanner._is_openvino_ir_graph(xml_head) is False
    assert time.perf_counter() - start < 0.1


def test_ir_graph_check_accepts_a_byte_order_mark_and_many_comments():
    head = "﻿<?xml version='1.0'?>\n".encode() + b"<!-- a -->\n" * 50 + b"<net name='m'>"
    assert DeepScanner._is_openvino_ir_graph(head) is True


def test_pickle_payload_next_to_an_ir_graph_is_still_critical(tmp_path):
    """The sibling explains raw bytes; it does not excuse a pickle."""
    (tmp_path / "openvino_model.xml").write_text(_OPENVINO_XML)
    path = tmp_path / "openvino_model.bin"
    path.write_bytes(_harmful_pickle())

    art, _ = _scan_one(path)

    assert art["risk_level"].startswith("CRITICAL (RCE Detected")


# --- Core ML ---------------------------------------------------------------

@pytest.mark.parametrize("rel", [
    "coreml/fill-mask/float32_model.mlpackage/Data/com.apple.CoreML/weights/weight.bin",
    "distil-whisper/AudioEncoder.mlmodelc/weights/weight.bin",
])
def test_coreml_weight_blob_is_low(tmp_path, rel):
    path = tmp_path / rel
    path.parent.mkdir(parents=True)
    path.write_bytes(_coreml_bytes())

    results = DeepScanner(str(tmp_path)).scan()
    (art,) = results["artifacts"]

    assert art["risk_level"] == "LOW"
    assert art["framework"] == "Core ML"
    assert art["details"]["blob_version"] == 2
    assert results["errors"] == []


def test_coreml_header_outside_a_weights_folder_stays_in_the_catch_all(tmp_path):
    path = tmp_path / "weight.bin"
    path.write_bytes(_coreml_bytes())
    art, _ = _scan_one(path)
    assert art["risk_level"] == "CRITICAL (Legacy Binary)"


def test_coreml_path_without_the_blob_header_stays_in_the_catch_all(tmp_path):
    path = tmp_path / "m.mlmodelc" / "weights" / "weight.bin"
    path.parent.mkdir(parents=True)
    path.write_bytes(_FILLER)
    art, _ = _scan_one(path)
    assert art["risk_level"] == "CRITICAL (Legacy Binary)"


def test_pickle_payload_at_a_coreml_path_is_still_critical(tmp_path):
    path = tmp_path / "m.mlpackage" / "Data" / "com.apple.CoreML" / "weights" / "weight.bin"
    path.parent.mkdir(parents=True)
    path.write_bytes(_harmful_pickle())
    art, _ = _scan_one(path)
    assert art["risk_level"].startswith("CRITICAL (RCE Detected")


# --- a zip that could not be opened ----------------------------------------

def _torch_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps({"w": [1, 2, 3]}, protocol=2))
        zf.writestr("archive/version", "3")
        # Padding so the central directory sits well away from the head.
        zf.writestr("archive/data/0", _FILLER * 4)
    return buf.getvalue()


def test_truncated_torch_zip_is_unreadable_not_critical(tmp_path):
    full = _torch_zip_bytes()
    path = tmp_path / "pytorch_model.bin"
    path.write_bytes(full[: len(full) // 2])

    art, errors = _scan_one(path)

    assert "CRITICAL" not in art["risk_level"]
    assert art["unreadable_type"] == "TruncatedStream"
    (err,) = errors
    assert err["unreadable_type"] == "TruncatedStream"
    assert "ZIP" in err["error"]


class _FlakyStream(io.BytesIO):
    """A remote stream whose reads near the end fail the first `failures` times.

    `zipfile.is_zipfile` reads the end-of-archive record and swallows any
    OSError, and every `requests` error is an OSError. So one failed Range
    read there used to turn a torch zip into an "unknown binary".
    """

    def __init__(self, data: bytes, failures: int):
        super().__init__(data)
        self._failures = failures

    def read(self, size=-1):
        if self.tell() > len(self.getvalue()) // 2 and self._failures > 0:
            self._failures -= 1
            raise requests.exceptions.ConnectionError("connection reset")
        return super().read(size)


def test_one_failed_remote_read_does_not_change_the_verdict():
    stream = _FlakyStream(_torch_zip_bytes(), failures=1)
    scanner = DeepScanner("https://example.com/pytorch_model.bin")

    art = scanner._inspect_pytorch(stream, "pytorch_model.bin", is_remote=True)

    assert art["risk_level"] == "MEDIUM (Pickle Present)"
    assert scanner.errors == []


def test_a_remote_zip_that_keeps_failing_is_an_error_not_critical():
    stream = _FlakyStream(_torch_zip_bytes(), failures=10**6)
    scanner = DeepScanner("https://example.com/pytorch_model.bin")

    art = scanner._inspect_pytorch(stream, "pytorch_model.bin", is_remote=True)

    assert "CRITICAL" not in art["risk_level"]
    assert art["unreadable_type"] == "TruncatedStream"
    (err,) = scanner.errors
    assert "connection reset" in err["error"]


# --- remote: OpenVINO needs the listing ------------------------------------

_RESOLVE = "https://huggingface.co/o/m/resolve/main/"


class _ServedStream(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _serve_files(monkeypatch, files: dict, listed: list):
    """Serve `files` (repo path -> bytes) and list `listed` as the repo tree."""
    fetched = []

    def fake_stream(url):
        rel = url[len(_RESOLVE):]
        fetched.append(rel)
        if rel not in files:
            raise requests.exceptions.HTTPError("404")
        return _ServedStream(files[rel])

    listing = remote.HFRepoListing(
        [_RESOLVE + p for p in listed if p.endswith(".bin")],
        paths=listed,
    )
    monkeypatch.setattr(scanner_module, "resolve_huggingface_repo", lambda t: listing)
    monkeypatch.setattr(scanner_module, "RemoteStream", fake_stream)
    monkeypatch.setattr(scanner_module, "fetch_huggingface_model_card", lambda t: None)
    return fetched


def test_remote_openvino_bin_with_a_listed_ir_graph_is_low(monkeypatch):
    fetched = _serve_files(
        monkeypatch,
        {
            "openvino/openvino_model.bin": _OPENVINO_BIN,
            "openvino/openvino_model.xml": _OPENVINO_XML.encode(),
        },
        ["openvino/openvino_model.bin", "openvino/openvino_model.xml", "README.md"],
    )

    results = DeepScanner("hf://o/m").scan()

    (art,) = results["artifacts"]
    assert art["name"] == "openvino/openvino_model.bin"
    assert art["framework"] == "OpenVINO IR"
    assert art["risk_level"] == "LOW"
    assert results["errors"] == []
    assert "openvino/openvino_model.xml" in fetched


def test_remote_openvino_bin_without_a_listed_graph_never_fetches_one(monkeypatch):
    fetched = _serve_files(
        monkeypatch,
        {"openvino/openvino_model.bin": _OPENVINO_BIN},
        ["openvino/openvino_model.bin"],
    )

    results = DeepScanner("hf://o/m").scan()

    (art,) = results["artifacts"]
    assert art["risk_level"] == "CRITICAL (Legacy Binary)"
    assert fetched == ["openvino/openvino_model.bin"]


def test_remote_ir_graph_that_fails_to_fetch_is_an_error_not_critical(monkeypatch):
    # Listed, but the fetch fails: that is "could not check", not "unknown binary".
    _serve_files(
        monkeypatch,
        {"openvino/openvino_model.bin": _OPENVINO_BIN},
        ["openvino/openvino_model.bin", "openvino/openvino_model.xml"],
    )

    results = DeepScanner("hf://o/m").scan()

    (art,) = results["artifacts"]
    assert "CRITICAL" not in art["risk_level"]
    assert results["errors"]


def test_listing_keeps_every_path_for_sibling_checks(monkeypatch):
    def fake_get(url, headers=None):
        resp = requests.Response()
        resp.status_code = 200
        resp._content = (
            b'[{"path":"openvino/openvino_model.bin","type":"file"},'
            b'{"path":"openvino/openvino_model.xml","type":"file"},'
            b'{"path":"openvino","type":"directory"}]'
        )
        return resp

    monkeypatch.setattr(remote, "requests", remote._RequestsStub())
    monkeypatch.setattr(remote.requests, "get", fake_get)

    listing = remote.resolve_huggingface_repo("o/m")

    assert list(listing) == [_RESOLVE + "openvino/openvino_model.bin"]
    assert listing.paths == frozenset({
        "openvino/openvino_model.bin",
        "openvino/openvino_model.xml",
    })
