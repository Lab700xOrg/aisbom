"""Tests for `aisbom comply` — regulator-facing documentation packs."""

import csv
import io
import json
import re

import pytest
from typer.testing import CliRunner

from aisbom import comply
from aisbom.cli import app

runner = CliRunner()


# The verdict words the aisbom.io compliance guides are held to. The generated
# documents describe files, so wording that reads as a regulatory verdict
# about the provider is banned here too. Keep the two lists in step.
VERDICT_WORDS = [
    "compliant",
    "compliance verdict",
    "certified",
    "certifies",
    "guarantee",
    "guaranteed",
    "meets the requirement",
    "satisfies the requirement",
    "legally",
    "approved by",
    "audit-proof",
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _hf_sbom():
    """The shape an `hf://` scan writes: model cards, no hashes."""
    card = {
        "modelParameters": {
            "task": "fill-mask",
            "architectureFamily": "bert",
            "modelArchitecture": "BertForMaskedLM",
            "datasets": [
                {"type": "dataset", "name": "bookcorpus"},
                {"type": "dataset", "name": "wikipedia"},
            ],
        },
        "properties": [
            {"name": "aisbom:hf:repo_id", "value": "google-bert/bert-base-uncased"},
            {"name": "aisbom:hf:license", "value": "apache-2.0"},
            {"name": "aisbom:hf:library_name", "value": "transformers"},
            {"name": "aisbom:hf:revision", "value": "86b5e09"},
        ],
    }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
        "metadata": {"timestamp": "2026-11-08T00:00:00+00:00"},
        "components": [
            {
                "type": "machine-learning-model",
                "name": "model.safetensors",
                "bom-ref": "artifact-0-model.safetensors",
                "properties": [
                    {"name": "aisbom:format", "value": "safetensors"},
                    {"name": "aisbom:risk", "value": "LOW"},
                ],
                "modelCard": card,
            },
            {
                "type": "machine-learning-model",
                "name": "model.onnx",
                "bom-ref": "artifact-1-model.onnx",
                "properties": [
                    {"name": "aisbom:format", "value": "onnx"},
                    {"name": "aisbom:risk", "value": "LOW"},
                ],
                "modelCard": card,
            },
        ],
    }


def _local_sbom():
    """The shape a local scan with no Hugging Face match writes: hashes, a
    dangerous pickle, a pinned dependency, and no model card at all."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:44444444-4444-4444-4444-444444444444",
        "metadata": {"timestamp": "2026-11-08T00:00:00+00:00"},
        "components": [
            {
                "type": "machine-learning-model",
                "name": "weights|v2.pt",
                "bom-ref": "artifact-0-weights|v2.pt",
                "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                "properties": [
                    {"name": "aisbom:format", "value": "pickle"},
                    {"name": "aisbom:risk", "value": "CRITICAL"},
                    {"name": "aisbom:pickle:opcode", "value": "posix.system"},
                ],
            },
            {
                "type": "library",
                "name": "torch",
                "version": "2.10.0",
                "bom-ref": "dependency-0-torch",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                "purl": "pkg:pypi/torch@2.10.0",
            },
        ],
    }


def _all_text(pack):
    return "\n".join(pack.values())


def _eu(doc):
    return comply.build_eu_ai_act_pack(doc, target="hf://google-bert/bert-base-uncased")


def _fda(doc, statements=()):
    return comply.build_fda_pack(
        doc,
        target="./models",
        vex_statements=list(statements),
        vex_files=["sbom.openvex.json", "sbom.vex.cdx.json"],
    )


# ---------------------------------------------------------------------------
# EU AI Act pack: structure
# ---------------------------------------------------------------------------

def test_eu_pack_writes_the_two_documents_and_an_index():
    assert set(_eu(_hf_sbom())) == {
        comply.ANNEX_XI_FILE,
        comply.ART53_FILE,
        comply.README_FILE,
    }


ART53_SECTIONS = [
    "1.1", "1.2", "1.3",
    "2.1", "2.2", "2.2.1", "2.2.2", "2.3", "2.4", "2.5", "2.6",
    "3.1", "3.2", "3.3",
]


def test_art53_follows_the_commission_template_section_order():
    text = _eu(_hf_sbom())[comply.ART53_FILE]
    headings = re.findall(r"^#{2,4} (\d(?:\.\d)+)\.? ", text, flags=re.M)
    assert headings == ART53_SECTIONS


def test_art53_names_the_template_it_follows():
    text = _eu(_hf_sbom())[comply.ART53_FILE]
    assert "Template for the Public Summary of Training Content" in text
    assert "24 July 2025" in text


ANNEX_XI_POINTS = [
    "1(a)", "1(b)", "1(c)", "1(d)", "1(e)", "1(f)",
    "2(a)", "2(b)", "2(c)", "2(d)", "2(e)",
]


def test_annex_xi_covers_every_section_1_point_in_order():
    text = _eu(_hf_sbom())[comply.ANNEX_XI_FILE]
    found = re.findall(r"^### Point (\d\([a-f]\))", text, flags=re.M)
    assert found == ANNEX_XI_POINTS


def test_annex_xi_carries_the_systemic_risk_section():
    text = _eu(_hf_sbom())[comply.ANNEX_XI_FILE]
    assert "Section 2" in text
    assert "systemic risk" in text
    for item in ("Evaluation strategies", "Adversarial testing", "System architecture"):
        assert item in text


# ---------------------------------------------------------------------------
# EU AI Act pack: what is pre-filled, and only from what the scan read
# ---------------------------------------------------------------------------

def test_model_card_facts_are_prefilled_with_their_source():
    pack = _eu(_hf_sbom())
    annex = pack[comply.ANNEX_XI_FILE]
    art53 = pack[comply.ART53_FILE]

    assert "fill-mask" in annex
    assert "BertForMaskedLM" in annex
    assert "apache-2.0" in annex
    assert "transformers" in annex
    assert "bookcorpus" in annex and "wikipedia" in annex
    assert "google-bert/bert-base-uncased@86b5e09" in art53
    assert "bookcorpus" in art53
    assert comply.SOURCE_HF in annex


def test_identical_values_across_artifacts_are_listed_once():
    annex = _eu(_hf_sbom())[comply.ANNEX_XI_FILE]
    point = _section(annex, "### Point 1(a)", "### Point 1(b)")
    assert point.count("fill-mask") == 1


def test_a_card_free_scan_leaves_model_facts_as_todo():
    pack = _eu(_local_sbom())
    annex = pack[comply.ANNEX_XI_FILE]
    for point, nxt in (("1(a)", "1(b)"), ("1(d)", "1(e)"), ("1(f)", "2(a)")):
        body = _section(annex, f"### Point {point}", f"### Point {nxt}")
        assert comply.TODO in body
        assert comply.SOURCE_HF not in body
    art53 = pack[comply.ART53_FILE]
    model_id = _section(art53, "### 1.2", "### 1.3")
    assert comply.TODO in model_id


def test_parameter_count_is_never_prefilled():
    """The scan cannot read it reliably, so it is always left to the provider."""
    annex = _eu(_hf_sbom())[comply.ANNEX_XI_FILE]
    body = _section(annex, "### Point 1(d)", "### Point 1(e)")
    params_line = next(line for line in body.splitlines() if "Number of parameters" in line)
    assert comply.TODO in params_line


def test_provider_identity_is_always_todo():
    art53 = _eu(_hf_sbom())[comply.ART53_FILE]
    body = _section(art53, "### 1.1", "### 1.2")
    assert body.count(comply.TODO) >= 2


def test_declared_datasets_are_offered_for_confirmation_not_asserted():
    art53 = _eu(_hf_sbom())[comply.ART53_FILE]
    body = _section(art53, "### 2.1", "### 2.2 ")
    assert "bookcorpus" in body
    assert "confirm" in body.lower()
    # Whether public datasets were used is the provider's answer to give.
    used_line = next(line for line in body.splitlines()
                     if "publicly available datasets to train" in line)
    assert comply.TODO in used_line


def test_artifact_inventory_shows_hashes_and_marks_unhashed_files():
    local = _eu(_local_sbom())[comply.ANNEX_XI_FILE]
    assert "a" * 64 in local
    remote = _eu(_hf_sbom())[comply.ANNEX_XI_FILE]
    assert "not computed" in remote


def test_security_findings_are_listed_with_their_opcodes():
    annex = _eu(_local_sbom())[comply.ANNEX_XI_FILE]
    assert "CRITICAL" in annex
    assert "posix.system" in annex


def _model_with(fmt, risk, props):
    return {
        "components": [{
            "type": "machine-learning-model",
            "name": f"m.{fmt}",
            "bom-ref": f"artifact-0-m.{fmt}",
            "properties": [
                {"name": "aisbom:format", "value": fmt},
                {"name": "aisbom:risk", "value": risk},
                *[{"name": n, "value": v} for n, v in props],
            ],
        }],
    }


@pytest.mark.parametrize("fmt,prop,value", [
    ("keras", "aisbom:keras:threat", "Lambda layer: marshalled bytecode"),
    ("gguf", "aisbom:gguf:chat_template_threat", "jinja: __globals__ access"),
    ("onnx", "aisbom:onnx:threat", "custom operator domain: evil.ops"),
])
def test_non_pickle_threats_are_listed(fmt, prop, value):
    """The summary must never contradict the SBOM it bundles."""
    annex = _eu(_model_with(fmt, "CRITICAL", [(prop, value)]))[comply.ANNEX_XI_FILE]
    row = next(line for line in annex.splitlines() if line.startswith(f"| m.{fmt}"))
    assert value in row
    assert "| none |" not in row


def test_a_high_risk_file_never_reads_none():
    """A threat property this module does not know yet still cannot surface
    as 'none' beside a CRITICAL rating."""
    annex = _eu(_model_with("newfmt", "CRITICAL (something)", []))[comply.ANNEX_XI_FILE]
    row = next(line for line in annex.splitlines() if line.startswith("| m.newfmt"))
    assert "| none |" not in row
    assert "sbom.json" in row


def test_pipes_in_file_names_do_not_break_tables():
    annex = _eu(_local_sbom())[comply.ANNEX_XI_FILE]
    row = next(line for line in annex.splitlines() if "weights" in line and line.startswith("|"))
    assert "weights\\|v2.pt" in row


def test_software_dependencies_are_listed_for_integrators():
    annex = _eu(_local_sbom())[comply.ANNEX_XI_FILE]
    assert "torch" in annex and "2.10.0" in annex and "BSD-3-Clause" in annex


def test_eu_index_counts_prefilled_and_todo_fields():
    readme = _eu(_hf_sbom())[comply.README_FILE]
    assert re.search(r"\d+ field\(s\) pre-filled", readme)
    assert re.search(r"\d+ left as TODO", readme)
    assert comply.ANNEX_XI_FILE in readme and comply.ART53_FILE in readme


# ---------------------------------------------------------------------------
# FDA pack
# ---------------------------------------------------------------------------

def test_fda_pack_writes_support_table_and_index():
    assert set(_fda(_local_sbom())) == {comply.SUPPORT_FILE, comply.README_FILE}


def test_support_table_has_a_row_per_component_with_todo_lifecycle():
    table = _fda(_local_sbom())[comply.SUPPORT_FILE]
    rows = list(csv.DictReader(io.StringIO(table)))
    assert [r["name"] for r in rows] == ["weights|v2.pt", "torch"]
    for row in rows:
        assert row["support_level"] == comply.TODO
        assert row["end_of_support_date"] == comply.TODO
    torch = rows[1]
    assert torch["version"] == "2.10.0"
    assert torch["license"] == "BSD-3-Clause"
    assert rows[0]["sha256"] == "a" * 64


def test_fda_index_lists_bundle_and_vex_counts():
    class _S:
        def __init__(self, status):
            self.status = status

    readme = _fda(_local_sbom(), [_S("affected"), _S("not_affected"), _S("not_affected")])[
        comply.README_FILE
    ]
    for name in ("sbom.json", "sbom.openvex.json", "sbom.vex.cdx.json", comply.SUPPORT_FILE):
        assert name in readme
    assert "3 statement(s)" in readme
    assert "1 affected" in readme


def test_fda_index_does_not_claim_vex_is_required():
    readme = _fda(_local_sbom())[comply.README_FILE].lower()
    assert "vex required" not in readme
    assert "requires vex" not in readme
    assert "one machine-readable way" in readme


def test_fda_index_names_what_it_cannot_evidence():
    readme = _fda(_local_sbom())[comply.README_FILE]
    assert "supplier" in readme.lower()
    assert "end-of-support" in readme.lower()


# ---------------------------------------------------------------------------
# Guards shared by every generated document
# ---------------------------------------------------------------------------

ALL_PACKS = [
    pytest.param(lambda: _eu(_hf_sbom()), id="eu-hf"),
    pytest.param(lambda: _eu(_local_sbom()), id="eu-local"),
    pytest.param(lambda: _eu({"components": []}), id="eu-empty"),
    pytest.param(lambda: _fda(_hf_sbom()), id="fda-hf"),
    pytest.param(lambda: _fda(_local_sbom()), id="fda-local"),
]


@pytest.mark.parametrize("make", ALL_PACKS)
def test_no_generated_file_uses_verdict_language(make):
    text = _all_text(make()).lower()
    hits = [w for w in VERDICT_WORDS if w in text]
    assert hits == []


@pytest.mark.parametrize("make", ALL_PACKS)
def test_every_markdown_file_carries_disclaimer_and_template_version(make):
    for name, text in make().items():
        if not name.endswith(".md"):
            continue
        assert "not legal advice" in text, name
        assert comply.TEMPLATE_VERSION in text, name
        # The disclaimer closes the document.
        assert text.rstrip().endswith(comply.DISCLAIMER), name


def test_malformed_components_are_ignored_not_fatal():
    doc = {"components": ["junk", {"type": "machine-learning-model"}, None]}
    assert comply.ANNEX_XI_FILE in _eu(doc)
    assert comply.SUPPORT_FILE in _fda(doc)


def _section(text, start, end):
    i = text.index(start)
    j = text.index(end, i + len(start))
    return text[i:j]


# ---------------------------------------------------------------------------
# The CLI command
# ---------------------------------------------------------------------------

def _restricted_tree(tmp_path):
    from aisbom.mock_generator import create_mock_restricted_file

    src = tmp_path / "models"
    src.mkdir()
    create_mock_restricted_file(src)
    return src


def test_cli_eu_ai_act_writes_the_pack(tmp_path):
    src = _restricted_tree(tmp_path)
    out = tmp_path / "pack"
    result = runner.invoke(app, [
        "comply", str(src), "--framework", "eu-ai-act", "--output-dir", str(out), "--offline",
    ])
    assert result.exit_code == 0, result.stdout
    for name in (comply.ANNEX_XI_FILE, comply.ART53_FILE, comply.README_FILE, "sbom.json"):
        assert (out / name).is_file(), name
    sbom = json.loads((out / "sbom.json").read_text())
    assert sbom["bomFormat"] == "CycloneDX"


def test_cli_fda_writes_sbom_vex_and_support_table(tmp_path, monkeypatch):
    from aisbom import osv

    def _boom(*a, **k):  # --offline must keep OSV untouched
        raise AssertionError("OSV queried in offline mode")

    monkeypatch.setattr(osv, "lookup_dependency_statements", _boom)
    src = _restricted_tree(tmp_path)
    (src / "requirements.txt").write_text("torch==2.10.0\n")
    out = tmp_path / "pack"
    result = runner.invoke(app, [
        "comply", str(src), "--framework", "fda", "--output-dir", str(out), "--offline",
    ])
    assert result.exit_code == 0, result.stdout
    for name in ("sbom.json", "sbom.openvex.json", "sbom.vex.cdx.json",
                 comply.SUPPORT_FILE, comply.README_FILE):
        assert (out / name).is_file(), name
    serial = json.loads((out / "sbom.json").read_text())["serialNumber"]
    openvex = json.loads((out / "sbom.openvex.json").read_text())
    assert any(serial in json.dumps(s) for s in openvex["statements"])


def test_cli_default_output_dir_is_named_for_the_framework(tmp_path, monkeypatch):
    src = _restricted_tree(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["comply", str(src), "--framework", "fda", "--offline"])
    assert result.exit_code == 0, result.stdout
    assert (tmp_path / "aisbom-comply-fda" / comply.README_FILE).is_file()


def test_cli_refuses_a_partial_scan(tmp_path, monkeypatch):
    from aisbom import cli as cli_mod

    class _PartialScanner:
        def __init__(self, *a, **kw):
            pass

        def scan(self):
            return {
                "artifacts": [],
                "dependencies": [],
                "errors": [{"file": "broken.pt", "error": "unreadable"}],
            }

    monkeypatch.setattr(cli_mod, "DeepScanner", _PartialScanner)
    out = tmp_path / "pack"
    result = runner.invoke(app, [
        "comply", str(tmp_path), "--framework", "eu-ai-act", "--output-dir", str(out), "--offline",
    ])
    assert result.exit_code == 1
    assert "broken.pt" in result.stdout
    assert not out.exists()


def test_cli_rejects_an_unusable_target(tmp_path):
    result = runner.invoke(app, [
        "comply", str(tmp_path / "nope"), "--framework", "fda", "--offline",
    ])
    assert result.exit_code == 1
    assert "Cannot build" in result.stdout


def test_cli_requires_a_framework(tmp_path):
    result = runner.invoke(app, ["comply", str(tmp_path)])
    assert result.exit_code == 2


def test_cli_rejects_an_unknown_framework(tmp_path):
    result = runner.invoke(app, ["comply", str(tmp_path), "--framework", "hipaa"])
    assert result.exit_code == 2
