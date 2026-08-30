"""Keras scanning: `.keras` zip containers and legacy HDF5 `.h5` files.

The threat is the `Lambda` layer, which serializes arbitrary Python as a
base64-encoded marshalled code object that executes on `load_model`. Nothing
here loads a model or unmarshals a payload — the marshalled blobs are real
code objects only so the detector sees a realistic signature, and they are
never passed to `marshal.loads`.

The HDF5 fixtures are built with `h5py`, which is a **dev-only** dependency:
Keras itself writes `.h5` via h5py, so building fixtures with it proves the
scanner's dependency-free byte parsing against the real container layout
rather than against an assumption about it. The scanner never imports h5py.
"""

import base64
import json
import marshal
import struct
import zipfile
from pathlib import Path

import pytest

from aisbom.mock_generator import create_mock_keras_zip
from aisbom.properties import build_component_properties
from aisbom.safety import (
    looks_like_marshalled_code,
    scan_keras_config,
    scan_keras_config_bytes,
)
from aisbom.scanner import DeepScanner

h5py = pytest.importorskip("h5py", reason="h5py is a dev-only fixture dependency")


# --- fixture helpers -------------------------------------------------------

def _marshalled_lambda_b64() -> str:
    """Base64 of a real marshalled code object (never unmarshalled)."""
    fn = lambda x: x + 1  # noqa: E731
    return base64.b64encode(marshal.dumps(fn.__code__)).decode("ascii")


def _keras2_config(with_lambda: bool = False) -> dict:
    """A Keras 2 `model_config` payload, as written into `.h5` attrs."""
    layers = [
        {"class_name": "Dense", "config": {"name": "dense_0", "units": 64}},
    ]
    if with_lambda:
        layers.insert(0, {
            "class_name": "Lambda",
            "config": {
                "name": "lambda_rce",
                "function": [_marshalled_lambda_b64(), None, None],
                "function_type": "lambda",
            },
        })
    return {
        "class_name": "Sequential",
        "config": {"name": "sequential", "layers": layers},
        "keras_version": "2.15.0",
        "backend": "tensorflow",
    }


def write_h5(path: Path, config: dict | None, keras_version: str = "2.15.0") -> Path:
    """Write a Keras-shaped HDF5 file the way Keras itself does."""
    with h5py.File(path, "w") as f:
        if config is not None:
            f.attrs["model_config"] = json.dumps(config)
        f.attrs["keras_version"] = keras_version
        f.attrs["backend"] = "tensorflow"
        grp = f.create_group("model_weights")
        grp.attrs["layer_names"] = [b"dense_0"]
    return path


# --- safety.scan_keras_config ---------------------------------------------

def test_benign_config_has_no_threats():
    assert scan_keras_config(_keras2_config(with_lambda=False)) == []


def test_lambda_layer_is_detected():
    threats = scan_keras_config(_keras2_config(with_lambda=True))
    assert any(t.startswith("KERAS_LAMBDA:") for t in threats)
    assert any("lambda_rce" in t for t in threats)


def test_marshalled_code_blob_is_detected():
    threats = scan_keras_config(_keras2_config(with_lambda=True))
    assert any(t.startswith("KERAS_MARSHALLED_CODE:") for t in threats)


def test_keras3_nested_lambda_shape_is_detected():
    """Keras 3 nests the callable under `__lambda__` with a `code` field."""
    cfg = {
        "module": "keras",
        "class_name": "Sequential",
        "config": {
            "layers": [{
                "module": "keras.layers",
                "class_name": "Lambda",
                "config": {
                    "name": "lambda_k3",
                    "function": {
                        "class_name": "__lambda__",
                        "config": {"code": _marshalled_lambda_b64()},
                    },
                },
                "registered_name": None,
            }],
        },
    }
    threats = scan_keras_config(cfg)
    assert any(t.startswith("KERAS_LAMBDA:") for t in threats)
    assert any(t.startswith("KERAS_MARSHALLED_CODE:") for t in threats)
    # The nested serialized callable is its own finding, so one Lambda layer is
    # never counted twice as a layer.
    assert any(t.startswith("KERAS_SERIALIZED_LAMBDA:") for t in threats)
    assert sum(t.startswith("KERAS_LAMBDA:") for t in threats) == 1


def test_serialized_lambda_without_a_layer_wrapper_is_flagged():
    """A `__lambda__` blob smuggled outside a Lambda layer still reports."""
    cfg = {"class_name": "Dense", "config": {
        "activation": {"class_name": "__lambda__", "config": {"code": "short"}},
    }}
    threats = scan_keras_config(cfg)
    assert threats == ["KERAS_SERIALIZED_LAMBDA: config.activation"]


def test_risk_label_names_layers_and_counts_code_objects():
    label = DeepScanner._keras_risk_label(
        [
            "KERAS_LAMBDA: lambda_a",
            "KERAS_SERIALIZED_LAMBDA: config.layers[0].config.function",
            "KERAS_MARSHALLED_CODE: config.layers[0].config.function.config.code",
        ],
        ["lambda_a"],
    )
    # "CRITICAL" is the substring --fail-on-risk matches on.
    assert label.startswith("CRITICAL")
    assert "lambda_a" in label
    assert "1 embedded code object(s)" in label
    # The verbose JSON paths belong in details, not the risk column.
    assert "config.layers[0]" not in label


def test_risk_label_deduplicates_repeated_layer_names():
    label = DeepScanner._keras_risk_label(
        ["KERAS_LAMBDA: dup", "KERAS_LAMBDA: dup"], ["dup", "dup"]
    )
    assert label.count("dup") == 1


def test_marshalled_code_detected_without_lambda_wrapper():
    """A code blob smuggled outside a Lambda layer is still flagged."""
    cfg = {"class_name": "Dense", "config": {"kernel_initializer": _marshalled_lambda_b64()}}
    threats = scan_keras_config(cfg)
    assert any(t.startswith("KERAS_MARSHALLED_CODE:") for t in threats)


def test_lambda_as_a_layer_name_is_not_a_false_positive():
    """A layer merely *named* "lambda" is not a Lambda layer."""
    cfg = {
        "class_name": "Sequential",
        "config": {"layers": [
            {"class_name": "Dense", "config": {"name": "lambda_like", "units": 8}},
        ]},
    }
    assert scan_keras_config(cfg) == []


def test_plain_base64_strings_are_not_marshalled_code():
    assert not looks_like_marshalled_code(base64.b64encode(b"just some weights").decode())
    assert not looks_like_marshalled_code("not base64 at all !!!")
    assert not looks_like_marshalled_code("")
    assert not looks_like_marshalled_code("YWJj")  # decodes to b"abc"


def test_marshalled_code_survives_newline_wrapped_base64():
    """Keras 2's func_dump uses codecs base64, which inserts newlines."""
    import codecs
    fn = lambda x: x  # noqa: E731
    wrapped = codecs.encode(marshal.dumps(fn.__code__), "base64").decode("ascii")
    assert "\n" in wrapped
    assert looks_like_marshalled_code(wrapped)


def test_config_walk_survives_cycles_and_odd_types():
    cfg = {"class_name": "Sequential", "config": {"layers": []}}
    cfg["self"] = cfg  # a cycle must not hang or blow the stack
    assert scan_keras_config(cfg) == []
    assert scan_keras_config(None) == []
    assert scan_keras_config([1, 2.5, True, None]) == []


# --- safety.scan_keras_config_bytes (fallback signature scan) -------------

def test_byte_scan_flags_lambda_in_unparseable_config():
    raw = b'\x89HDF\r\n\x1a\n...garbage...{"class_name": "Lambda", "config": {trunc'
    threats = scan_keras_config_bytes(raw)
    assert any(t.startswith("KERAS_LAMBDA:") for t in threats)


def test_byte_scan_clean_on_benign_bytes():
    assert scan_keras_config_bytes(b'{"class_name": "Dense", "units": 8}') == []


# --- DeepScanner: .keras zip container ------------------------------------

def test_keras_zip_with_lambda_is_critical(tmp_path):
    create_mock_keras_zip(tmp_path / "evil.keras", with_lambda=True)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["framework"] == "Keras"
    assert art["type"] == "machine-learning-model"
    assert "CRITICAL" in art["risk_level"]
    assert art["details"]["container"] == "keras-zip"
    assert any(t.startswith("KERAS_LAMBDA:") for t in art["details"]["threats"])
    assert len(art["hash"]) == 64


def test_keras_zip_benign_scans_clean(tmp_path):
    create_mock_keras_zip(tmp_path / "clean.keras", with_lambda=False)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["framework"] == "Keras"
    assert "CRITICAL" not in art["risk_level"]
    assert art["details"]["threats"] == []
    assert art["details"]["layer_count"] >= 1


def test_keras_zip_without_config_is_not_critical(tmp_path):
    """A zip that isn't a Keras archive must not be reported as a threat."""
    path = tmp_path / "notkeras.keras"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("weights.bin", b"\x00\x01\x02")
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" not in art["risk_level"]
    assert art["details"]["config_found"] is False


# --- DeepScanner: legacy .h5 (HDF5) --------------------------------------

def test_h5_with_lambda_is_critical(tmp_path):
    write_h5(tmp_path / "evil.h5", _keras2_config(with_lambda=True))
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["framework"] == "Keras"
    assert "CRITICAL" in art["risk_level"]
    assert art["details"]["container"] == "hdf5"
    assert art["details"]["config_found"] is True
    assert any(t.startswith("KERAS_LAMBDA:") for t in art["details"]["threats"])
    assert any(t.startswith("KERAS_MARSHALLED_CODE:") for t in art["details"]["threats"])
    assert art["details"]["keras_version"] == "2.15.0"


def test_h5_benign_scans_clean(tmp_path):
    write_h5(tmp_path / "clean.h5", _keras2_config(with_lambda=False))
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" not in art["risk_level"]
    assert art["details"]["threats"] == []
    assert art["details"]["config_found"] is True


def test_h5_large_config_still_parses(tmp_path):
    """A config far past HDF5's 64KB object-header limit must still be read."""
    cfg = _keras2_config(with_lambda=True)
    cfg["config"]["layers"].extend(
        {"class_name": "Dense", "config": {"name": f"pad_{i}", "units": 64}}
        for i in range(1200)
    )
    assert len(json.dumps(cfg)) > 64 * 1024

    write_h5(tmp_path / "big.h5", cfg)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["details"]["config_found"] is True
    assert "CRITICAL" in art["risk_level"]
    assert art["details"]["layer_count"] == 1202


def test_hdf5_without_model_config_is_not_critical(tmp_path):
    """A plain HDF5 data file carrying no Keras config scans clean."""
    write_h5(tmp_path / "data.h5", None)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["framework"] == "Keras"
    assert "CRITICAL" not in art["risk_level"]
    assert art["details"]["config_found"] is False


def test_hdf5_extension_variant_is_discovered(tmp_path):
    write_h5(tmp_path / "model.hdf5", _keras2_config(with_lambda=True))
    arts = DeepScanner(str(tmp_path)).scan()["artifacts"]

    assert len(arts) == 1
    assert "CRITICAL" in arts[0]["risk_level"]


def test_truncated_h5_still_flags_the_payload(tmp_path):
    """Truncating the container must not stop the scan reaching the signature.

    A scanner that bails out on a malformed container is exactly the evasion
    this project treats as a defect, so a broken file is still scanned.
    """
    full = write_h5(tmp_path / "full.h5", _keras2_config(with_lambda=True)).read_bytes()
    (tmp_path / "full.h5").unlink()

    # Cut shortly after the Lambda signature, so the JSON object is left
    # unterminated and cannot be recovered — the payload is visible in the
    # bytes but the structured parse is guaranteed to fail.
    sig_at = full.find(b'"class_name": "Lambda"')
    assert sig_at != -1
    (tmp_path / "trunc.h5").write_bytes(full[: sig_at + 40])

    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["details"]["config_parsed"] is False, "expected the JSON parse to fail"
    assert "CRITICAL" in art["risk_level"]
    assert art["details"]["threats"] == ["KERAS_LAMBDA: <unparsed config>"]


def test_unreadable_keras_file_records_an_error_not_a_crash(tmp_path):
    path = tmp_path / "empty.h5"
    path.write_bytes(b"")
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["framework"] == "Keras"
    assert "CRITICAL" not in art["risk_level"]


# --- containers that do not present cleanly -------------------------------

def test_hdf5_behind_a_user_block_is_still_recognized(tmp_path):
    """HDF5 allows a user block before the superblock.

    Its size is 512 bytes or a larger power of two, and h5py opens such files
    normally — so demanding the signature at offset 0 would dismiss a real
    Keras model, Lambda layer and all, as an unrecognized container.
    """
    real = write_h5(tmp_path / "real.h5", _keras2_config(with_lambda=True)).read_bytes()
    (tmp_path / "real.h5").unlink()
    (tmp_path / "userblock.h5").write_bytes(b"\x00" * 512 + real)

    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["details"]["container"] == "hdf5"
    assert "CRITICAL" in art["risk_level"]
    assert any(t.startswith("KERAS_LAMBDA:") for t in art["details"]["threats"])


@pytest.mark.parametrize("block", [512, 1024, 2048])
def test_hdf5_user_block_sizes_are_all_found(tmp_path, block):
    real = write_h5(tmp_path / "real.h5", _keras2_config(with_lambda=True)).read_bytes()
    (tmp_path / "real.h5").unlink()
    (tmp_path / "ub.h5").write_bytes(b"\x00" * block + real)

    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]
    assert "CRITICAL" in art["risk_level"]


def test_damaged_keras_archive_still_yields_its_signature(tmp_path):
    """A wrecked central directory must not stop the byte-level fallback.

    `zipfile.is_zipfile` returns False once the directory is gone, so the file
    reaches the unrecognized-container path — but the Lambda signature is still
    sitting in the bytes, and corrupting the container must not hide it.
    """
    full = create_mock_keras_zip(
        tmp_path / "full.keras", with_lambda=True
    ).read_bytes()
    (tmp_path / "full.keras").unlink()
    # Drop the central directory at the end; the stored member survives.
    (tmp_path / "broken.keras").write_bytes(full[: full.rfind(b"PK\x01\x02")])

    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert "CRITICAL" in art["risk_level"]
    assert any(t.startswith("KERAS_LAMBDA:") for t in art["details"]["threats"])


def test_unrecognized_container_with_no_signature_stays_unknown(tmp_path):
    (tmp_path / "junk.keras").write_bytes(b"not a container at all" * 10)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["risk_level"] == "UNKNOWN (Unrecognized Container)"
    assert "CRITICAL" not in art["risk_level"]


def test_config_larger_than_the_read_budget_is_not_called_clean(tmp_path, monkeypatch):
    """A config past the read window must not report LOW.

    Padding a config with ordinary layers so the Lambda falls beyond the cut is
    cheap, and the compressed archive stays small and loadable.
    """
    import aisbom.scanner as scanner_mod

    cfg = _keras2_config(with_lambda=False)
    cfg["config"]["layers"].extend(
        {"class_name": "Dense", "config": {"name": f"pad_{i}", "units": 64}}
        for i in range(2000)
    )
    path = tmp_path / "big.keras"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("config.json", json.dumps(cfg))
        z.writestr("metadata.json", json.dumps({"keras_version": "3.5.0"}))

    monkeypatch.setattr(scanner_mod, "KERAS_MAX_SCAN_BYTES", 4096)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]

    assert art["details"]["truncated"] is True
    assert "MEDIUM" in art["risk_level"]
    assert "CRITICAL" not in art["risk_level"]


def test_truncated_config_is_not_cleared_in_vex_either(tmp_path, monkeypatch):
    """The same "not called clean" rule, end to end through VEX (#113).

    Found on a live target rather than a fixture: `hf://google-bert/
    bert-base-uncased` ships a `tf_model.h5` whose config exceeds the read
    budget over a range request, and the first VEX implementation answered
    `not_affected` — "declares no Lambda layer" — for it. Over a range request
    that is the common case for a `.h5`, so this asserts the scanner's
    truncation flag actually reaches the compliance artifact.
    """
    import aisbom.scanner as scanner_mod
    from aisbom.vex import derive_statements

    cfg = _keras2_config(with_lambda=False)
    cfg["config"]["layers"].extend(
        {"class_name": "Dense", "config": {"name": f"pad_{i}", "units": 64}}
        for i in range(2000)
    )
    with zipfile.ZipFile(tmp_path / "big.keras", "w") as z:
        z.writestr("config.json", json.dumps(cfg))
        z.writestr("metadata.json", json.dumps({"keras_version": "3.5.0"}))

    monkeypatch.setattr(scanner_mod, "KERAS_MAX_SCAN_BYTES", 4096)
    artifacts = DeepScanner(str(tmp_path)).scan()["artifacts"]

    statements = derive_statements(artifacts)
    keras_statements = [
        s for s in statements
        if s.finding_class.id == "AISBOM-KERAS-LAMBDA-RCE"
    ]
    assert [s.status for s in keras_statements] == ["under_investigation"]
    assert keras_statements[0].justification is None


# --- Hugging Face resolution ----------------------------------------------

@pytest.mark.parametrize("filename", [
    "model.keras", "model.h5", "model.hdf5",
])
def test_keras_files_are_resolved_from_a_hugging_face_repo(monkeypatch, filename):
    """The dispatch arm is unreachable for `hf://` unless the resolver lists it.

    Without this the remote scan of a repo holding a backdoored Keras model
    returns no artifacts and no errors — a silent pass.
    """
    import aisbom.remote as remote

    def fake_get(url, headers=None):
        class Resp:
            status_code = 200
            headers = {}

            def raise_for_status(self):
                pass

            def json(self):
                return [{"path": filename}, {"path": "README.md"}]

        return Resp()

    monkeypatch.setattr(remote, "requests", remote._RequestsStub())
    monkeypatch.setattr(remote.requests, "get", fake_get)

    urls = remote.resolve_huggingface_repo("hf://org/model")
    assert any(u.endswith(filename) for u in urls), urls


# --- SBOM plumbing --------------------------------------------------------

def test_keras_format_token_is_registered():
    art = {"framework": "Keras", "risk_level": "LOW", "legal_status": "UNKNOWN", "details": {}}
    props = dict(build_component_properties(art))
    assert props["aisbom:format"] == "keras"


def test_keras_properties_carry_findings(tmp_path):
    create_mock_keras_zip(tmp_path / "evil.keras", with_lambda=True)
    art = DeepScanner(str(tmp_path)).scan()["artifacts"][0]
    props = build_component_properties(art)
    names = {n for n, _ in props}
    as_dict = dict(props)

    assert as_dict["aisbom:format"] == "keras"
    assert as_dict["aisbom:keras:container"] == "keras-zip"
    assert "aisbom:keras:threat" in names
    assert int(as_dict["aisbom:keras:threat_count"]) >= 1
    assert "lambda" in as_dict["aisbom:keras:lambda_layers"].lower()
    assert as_dict["aisbom:risk"].startswith("CRITICAL")


def test_keras_appears_in_spdx_export(tmp_path):
    """The shared format token must reach SPDX, not just CycloneDX."""
    from aisbom.spdx_gen import generate_spdx_sbom

    create_mock_keras_zip(tmp_path / "evil.keras", with_lambda=True)
    results = DeepScanner(str(tmp_path)).scan()

    doc = json.loads(generate_spdx_sbom(results))
    pkgs = doc["packages"]
    assert any(p["name"] == "evil.keras" for p in pkgs)
    keras_pkg = next(p for p in pkgs if p["name"] == "evil.keras")
    assert "Type: keras" in keras_pkg["comment"]
    assert "CRITICAL" in keras_pkg["comment"]


def test_scan_exits_two_on_keras_lambda(tmp_path, monkeypatch):
    """End-to-end: a Lambda layer must trip the CI gate (exit 2).

    Asserts on the rendered output as well as the code, because Typer also
    exits 2 on a usage error — the code alone would pass for the wrong reason.
    """
    from typer.testing import CliRunner
    from aisbom.cli import app

    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    create_mock_keras_zip(tmp_path / "evil.keras", with_lambda=True)
    result = CliRunner().invoke(app, ["scan", str(tmp_path)])

    assert "evil.keras" in result.output, result.output
    assert "CRITICAL" in result.output, result.output
    assert result.exit_code == 2, result.output


def test_benign_keras_scan_exits_zero(tmp_path, monkeypatch):
    """The clean case must not trip the gate — otherwise the signal is useless."""
    from typer.testing import CliRunner
    from aisbom.cli import app

    monkeypatch.setenv("AISBOM_NO_TELEMETRY", "1")
    create_mock_keras_zip(tmp_path / "clean.keras", with_lambda=False)
    result = CliRunner().invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0, result.output


# --- remote scanning ------------------------------------------------------

def test_remote_keras_lambda_is_detected(monkeypatch, tmp_path):
    """A Keras model on a remote host must be scanned, not silently skipped.

    Without this the `hf://` path would report a backdoored Keras model clean.
    """
    import aisbom.remote as remote

    content = create_mock_keras_zip(tmp_path / "remote.keras", with_lambda=True).read_bytes()

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
        lambda self, target: ["http://example.com/remote.keras"],
    )

    results = DeepScanner("http://example.com/remote.keras").scan()
    art = results["artifacts"][0]

    assert results["errors"] == []
    assert art["framework"] == "Keras"
    assert "CRITICAL" in art["risk_level"]
    # No bytes were hashed, so no digest may be asserted.
    assert art["hash"] == "remote_unhashed"


# --- mock_generator -------------------------------------------------------

def test_mock_keras_zip_is_a_real_keras_archive(tmp_path):
    path = create_mock_keras_zip(tmp_path / "m.keras", with_lambda=True)
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        assert "config.json" in names
        assert "metadata.json" in names
        cfg = json.loads(z.read("config.json"))
    assert cfg["class_name"] == "Sequential"


def test_mock_keras_zip_benign_has_no_lambda(tmp_path):
    path = create_mock_keras_zip(tmp_path / "m.keras", with_lambda=False)
    with zipfile.ZipFile(path) as z:
        cfg = json.loads(z.read("config.json"))
    assert scan_keras_config(cfg) == []
