import pytest
import json
import importlib.metadata
from aisbom.spdx_gen import generate_spdx_sbom

# A real 64-hex SHA256, the shape ``DeepScanner._calculate_hash`` returns.
SHA_A = "a" * 64
SHA_B = "b" * 64


def _pytorch_artifact(name="model.pt", artifact_hash=SHA_A, **overrides):
    """Build an artifact dict shaped like the one ``DeepScanner`` emits.

    Constructed fresh on each call so two "runs" produce equal-but-distinct
    dicts — which is what makes the determinism test meaningful.
    """
    art = {
        "name": name,
        "type": "machine-learning-model",
        "framework": "PyTorch",
        "risk_level": "MEDIUM (Pickle Present)",
        "license": "Unknown",
        "legal_status": "UNKNOWN",
        "hash": artifact_hash,
        "details": {},
    }
    art.update(overrides)
    return art


def _generate(artifacts=None, dependencies=None):
    return json.loads(generate_spdx_sbom({
        "artifacts": artifacts or [],
        "dependencies": dependencies or [],
        "errors": [],
    }))


def _artifact_packages(data):
    return [p for p in data["packages"] if p["SPDXID"].startswith("SPDXRef-Artifact-")]


def test_spdx_generation():
    # Mock Results
    results = {
        "artifacts": [
            {
                "name": "model.pkl",
                "filename": "model.pkl",
                "risk_level": "LOW",
                "legal_status": "PASS",
                "framework": "PyTorch",
                "format": "pickle",
                "hash": "abcdef123456"
            }
        ],
        "dependencies": [
            {
                "name": "requests",
                "version": "2.28.1"
            }
        ],
        "errors": []
    }

    # Generate SPDX
    spdx_json_str = generate_spdx_sbom(results)

    # Verify it is valid JSON
    data = json.loads(spdx_json_str)

    # Verify Structure
    assert "SPDXID" in data
    assert data["name"] == "AIsbom-Scan"
    assert len(data.get("packages", [])) == 2

    # Check Artifact Mapping
    pkgs = data["packages"]
    model_pkg = next(p for p in pkgs if "model" in p["name"])
    assert model_pkg["name"] == "model.pkl"
    assert "SPDXRef-Artifact-" in model_pkg["SPDXID"]
    assert "PyTorch" in model_pkg.get("comment", "")

    # Check Dependency Mapping
    lib_pkg = next(p for p in pkgs if p["name"] == "requests")
    assert lib_pkg["versionInfo"] == "2.28.1"
    assert "SPDXRef-Lib-" in lib_pkg["SPDXID"]


# --- Artifact naming -------------------------------------------------------

def test_artifact_uses_scanner_name_key():
    """The scanner emits ``name``; the exporter used to read ``filename``, so
    every artifact in every emitted document was called ``unknown-model``."""
    data = _generate([_pytorch_artifact(name="mock_malware.pt")])
    pkg = _artifact_packages(data)[0]
    assert pkg["name"] == "mock_malware.pt"
    assert "unknown-model" not in pkg["SPDXID"]


def test_artifact_falls_back_to_filename_then_placeholder():
    data = _generate([
        {"filename": "legacy.pt", "framework": "PyTorch", "hash": SHA_A},
        {"framework": "PyTorch", "hash": SHA_B},
    ])
    names = [p["name"] for p in _artifact_packages(data)]
    assert names == ["legacy.pt", "unknown-model"]


# --- SPDXID determinism and uniqueness -------------------------------------

def test_spdxids_deterministic_across_runs():
    """Two scans of unchanged inputs must yield byte-identical package IDs and
    relationship refs. The old ID was built from ``id(artifact)`` — a memory
    address — so this failed."""
    def run():
        return _generate(
            [_pytorch_artifact(name="model.pt"),
             _pytorch_artifact(name="other.safetensors", artifact_hash=SHA_B,
                               framework="SafeTensors")],
            [{"name": "requests", "version": "2.28.1"}],
        )

    first, second = run(), run()

    assert [p["SPDXID"] for p in first["packages"]] == \
           [p["SPDXID"] for p in second["packages"]]
    assert [r["relatedSpdxElement"] for r in first["relationships"]] == \
           [r["relatedSpdxElement"] for r in second["relationships"]]


def test_spdxid_derived_from_content_hash():
    """Same name, different bytes -> different IDs. Different name, same bytes
    -> different IDs. Neither may depend on object identity."""
    data = _generate([
        _pytorch_artifact(name="model.pt", artifact_hash=SHA_A),
        _pytorch_artifact(name="model.pt", artifact_hash=SHA_B),
    ])
    ids = [p["SPDXID"] for p in _artifact_packages(data)]
    assert ids[0] != ids[1]
    assert SHA_A[:12] in ids[0]
    assert SHA_B[:12] in ids[1]


def test_spdxids_unique_for_identical_name_and_hash():
    """The same file content under the same basename in two directories still
    needs two distinct package IDs."""
    data = _generate([
        _pytorch_artifact(name="model.pt", artifact_hash=SHA_A),
        _pytorch_artifact(name="model.pt", artifact_hash=SHA_A),
        _pytorch_artifact(name="model.pt", artifact_hash=SHA_A),
    ])
    ids = [p["SPDXID"] for p in _artifact_packages(data)]
    assert len(set(ids)) == 3


def test_spdxids_unique_when_names_sanitize_identically():
    """``safe_name`` maps every non-alphanumeric char to ``-``, so ``model.pt``
    and ``model-pt`` collapse to the same token."""
    data = _generate([
        _pytorch_artifact(name="model.pt", artifact_hash=SHA_A),
        _pytorch_artifact(name="model-pt", artifact_hash=SHA_A),
    ])
    ids = [p["SPDXID"] for p in _artifact_packages(data)]
    assert len(set(ids)) == 2


def test_spdxids_unique_when_every_artifact_is_remote_unhashed():
    """Remote scans set ``hash`` to the literal ``remote_unhashed``, so a
    hash-only ID would collapse every remote artifact onto one package."""
    data = _generate([
        _pytorch_artifact(name="model.pt", artifact_hash="remote_unhashed"),
        _pytorch_artifact(name="model.pt", artifact_hash="remote_unhashed"),
        _pytorch_artifact(name="weights.pt", artifact_hash="remote_unhashed"),
    ])
    ids = [p["SPDXID"] for p in _artifact_packages(data)]
    assert len(set(ids)) == 3
    assert not any("remote_unhashed" in i for i in ids)


def test_spdxids_match_the_spdx_ref_pattern():
    import re
    data = _generate(
        [_pytorch_artifact(name="odd name!@#$.pt")],
        [{"name": "some-lib", "version": "2.0.*"}],
    )
    for pkg in data["packages"]:
        assert re.fullmatch(r"SPDXRef-[a-zA-Z0-9.\-]+", pkg["SPDXID"]), pkg["SPDXID"]


# --- Checksums -------------------------------------------------------------

def test_checksum_emitted_for_local_artifact():
    data = _generate([_pytorch_artifact(artifact_hash=SHA_A)])
    pkg = _artifact_packages(data)[0]
    assert pkg["checksums"] == [{"algorithm": "SHA256", "checksumValue": SHA_A}]


@pytest.mark.parametrize("sentinel", ["remote_unhashed", "hash_error", "", None])
def test_checksum_omitted_not_faked_for_non_digest_hashes(sentinel):
    """Sentinels are not digests. Omitting the field is correct; emitting the
    sentinel as a checksum value would be a lie in a security SBOM."""
    art = _pytorch_artifact(artifact_hash=sentinel)
    if sentinel is None:
        del art["hash"]
    data = _generate([art])
    pkg = _artifact_packages(data)[0]
    assert not pkg.get("checksums")


def test_checksum_omitted_for_malformed_digest():
    data = _generate([_pytorch_artifact(artifact_hash="abcdef123456")])
    pkg = _artifact_packages(data)[0]
    assert not pkg.get("checksums")


# --- Package comment format ------------------------------------------------

@pytest.mark.parametrize("framework,expected", [
    ("PyTorch", "pickle"),
    ("SafeTensors", "safetensors"),
    ("GGUF", "gguf"),
])
def test_comment_reports_real_format(framework, expected):
    data = _generate([_pytorch_artifact(framework=framework)])
    assert f"Type: {expected}" in _artifact_packages(data)[0]["comment"]


def test_comment_falls_back_to_unknown_for_unrecognised_framework():
    data = _generate([_pytorch_artifact(framework="Klingon")])
    assert "Type: unknown" in _artifact_packages(data)[0]["comment"]


def test_comment_retains_risk_and_framework():
    data = _generate([_pytorch_artifact(risk_level="CRITICAL (RCE Detected)")])
    comment = _artifact_packages(data)[0]["comment"]
    assert "Risk: CRITICAL (RCE Detected)" in comment
    assert "Framework: PyTorch" in comment


# --- Creators --------------------------------------------------------------

def test_creators_reports_running_cli_version():
    data = _generate([_pytorch_artifact()])
    version = importlib.metadata.version("aisbom-cli")
    assert data["creationInfo"]["creators"] == [f"Tool: aisbom-cli-{version}"]


def test_creators_falls_back_when_distribution_missing(monkeypatch):
    """The PyInstaller binary has no installed distribution metadata; the
    exporter must not crash there."""
    def boom(_name):
        raise importlib.metadata.PackageNotFoundError("aisbom-cli")

    monkeypatch.setattr(importlib.metadata, "version", boom)
    data = _generate([_pytorch_artifact()])
    creators = data["creationInfo"]["creators"]
    assert len(creators) == 1
    assert creators[0].startswith("Tool: aisbom-cli")


# --- Dependencies ----------------------------------------------------------

def test_dependency_spdxids_unique_for_repeated_pins():
    """The same pin listed in two requirements.txt files must not produce two
    packages sharing one SPDXID."""
    data = _generate(dependencies=[
        {"name": "requests", "version": "2.28.1"},
        {"name": "requests", "version": "2.28.1"},
    ])
    ids = [p["SPDXID"] for p in data["packages"]]
    assert len(set(ids)) == 2


# --- Whole-document validity ----------------------------------------------

def test_empty_scan_emits_a_valid_document():
    """A scan that finds no models and no requirements still has to produce a
    document. SPDX requires a DESCRIBES relationship whenever there isn't
    exactly one package, so an empty document must describe NONE explicitly —
    otherwise the writer's own validator rejects it and the CLI crashes."""
    data = _generate([], [])
    assert data["relationships"] == [{
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relatedSpdxElement": "NONE",
        "relationshipType": "DESCRIBES",
    }]


def test_document_validates_as_spdx_2_3():
    from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
    from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

    data = _generate(
        [
            _pytorch_artifact(name="mock_malware.pt", artifact_hash=SHA_A),
            _pytorch_artifact(name="mock_restricted.safetensors",
                              artifact_hash=SHA_B, framework="SafeTensors"),
            _pytorch_artifact(name="remote.pt", artifact_hash="remote_unhashed"),
        ],
        [
            {"name": "requests", "version": "2.28.1"},
            {"name": "torch", "version": "2.0.*"},
        ],
    )
    document = JsonLikeDictParser().parse(data)
    assert validate_full_spdx_document(document) == []
