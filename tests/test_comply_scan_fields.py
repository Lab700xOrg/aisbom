"""`aisbom comply` fields pre-filled from model-card, header and registry data.

Each field has a present and an absent case. Declared values get their own
"declared" row and never answer the regulatory field itself; interpretations
are tagged *AIsbom's mapping*; the parameter count is summed only over a
provably complete set of safetensors files (GGUF: tests/test_gguf_parameters.py).
"""

import copy
import csv
import io
from dataclasses import dataclass

import pytest

from aisbom import comply

from tests.test_comply import _eu, _fda, _hf_sbom, _local_sbom


def _line(text, label):
    return next(line for line in text.splitlines() if f"**{label}:**" in line)


def _with_card_props(doc, *props, card_extra=None):
    doc = copy.deepcopy(doc)
    for comp in doc["components"]:
        if comp.get("type") != "machine-learning-model" or "modelCard" not in comp:
            continue
        comp["modelCard"] = copy.deepcopy(comp["modelCard"])
        comp["modelCard"]["properties"] += [{"name": n, "value": v} for n, v in props]
        if card_extra:
            comp["modelCard"].update(copy.deepcopy(card_extra))
    return doc


def _declared_sbom():
    return _with_card_props(
        _hf_sbom(),
        ("aisbom:hf:author", "google-bert"),
        ("aisbom:hf:base_model", "google-bert/bert-large-uncased"),
        ("aisbom:hf:language", "en"),
        ("aisbom:hf:language", "de"),
        ("aisbom:hf:created_at", "2024-07-18T08:56:00.000Z"),
        ("aisbom:hf:parameters_total", "110106428"),
        ("aisbom:hf:co2_eq_emissions", "149.2"),
        ("aisbom:hf:co2_eq_emissions:source", "codecarbon"),
        ("aisbom:hf:co2_eq_emissions:training_type", "pre-training"),
        ("aisbom:hf:co2_eq_emissions:hardware_used", "8 x V100"),
        card_extra={"quantitativeAnalysis": {"performanceMetrics": [
            {"type": "accuracy", "value": "0.91",
             "slice": "text-classification on glue (sst2, validation)"},
        ]}},
    )


def _annex(doc):
    return _eu(doc)[comply.ANNEX_XI_FILE]


def _art53(doc):
    return _eu(doc)[comply.ART53_FILE]


# ---------------------------------------------------------------------------
# Base model and languages (Art. 53 §1.2 / §1.3)
# ---------------------------------------------------------------------------

def test_base_model_fills_model_dependencies_with_its_source():
    line = _line(_art53(_declared_sbom()), "Model dependencies")
    assert "google-bert/bert-large-uncased" in line
    assert comply.SOURCE_HF in line
    assert comply.TODO not in line


def test_model_dependencies_stay_todo_without_a_base_model():
    assert comply.TODO in _line(_art53(_hf_sbom()), "Model dependencies")


def test_declared_languages_get_their_own_row_and_leave_the_field_todo():
    art53 = _art53(_declared_sbom())
    declared = _line(art53, "Languages declared in the model card")
    assert "`en`" in declared and "`de`" in declared
    assert "not necessarily" in declared
    assert comply.TODO in _line(art53, "Linguistic characteristics of the overall training data")


def test_no_card_languages_leaves_the_declared_row_todo():
    assert comply.TODO in _line(_art53(_hf_sbom()), "Languages declared in the model card")


# ---------------------------------------------------------------------------
# First published on Hugging Face (Annex XI 1(c))
# ---------------------------------------------------------------------------

def test_first_published_is_offered_and_release_date_stays_todo():
    annex = _annex(_declared_sbom())
    published = _line(annex, "First published on Hugging Face")
    assert "2024-07-18T08:56:00.000Z" in published
    assert comply.SOURCE_HF_REPO in published
    assert "not necessarily the release date" in published
    assert comply.TODO in _line(annex, "Date of release")


def test_first_published_is_todo_without_a_creation_date():
    assert comply.TODO in _line(_annex(_hf_sbom()), "First published on Hugging Face")


# ---------------------------------------------------------------------------
# Number of parameters (Annex XI 1(d))
# ---------------------------------------------------------------------------

def test_hf_parameter_total_is_prefilled_with_its_source():
    line = _line(_annex(_declared_sbom()), "Number of parameters")
    assert "110,106,428" in line
    assert comply.SOURCE_HF_PARAMETERS in line


def test_parameter_count_stays_todo_with_no_source():
    assert comply.TODO in _line(_annex(_hf_sbom()), "Number of parameters")


def _safetensors(name, params=None, set_total=None, set_shards=None):
    props = [{"name": "aisbom:format", "value": "safetensors"},
             {"name": "aisbom:risk", "value": "LOW"}]
    if params is not None:
        props.append({"name": "aisbom:safetensors:parameters", "value": str(params)})
    if set_total is not None:
        props += [{"name": "aisbom:safetensors:set_parameters", "value": str(set_total)},
                  {"name": "aisbom:safetensors:set_shards", "value": str(set_shards)}]
    return {"type": "machine-learning-model", "name": name,
            "bom-ref": f"artifact-x-{name}", "properties": props}


def _params_line(*comps):
    return _line(_annex({"components": list(comps)}), "Number of parameters")


def test_a_single_unsharded_file_is_counted():
    line = _params_line(_safetensors("model.safetensors", 1234567))
    assert "1,234,567 (model.safetensors)" in line
    assert comply.SOURCE_SCAN_PARAMETERS in line


def test_a_shard_set_the_scanner_marked_complete_is_shown_once():
    line = _params_line(
        _safetensors("model-00001-of-00002.safetensors", 100, 300, 2),
        _safetensors("model-00002-of-00002.safetensors", 200, 300, 2),
    )
    assert "300 (model-*-of-00002.safetensors, 2 shards)" in line
    assert line.count("300 (") == 1


def test_remote_shard_names_with_a_directory_are_read_by_basename():
    line = _params_line(
        _safetensors("sub/model-00001-of-00001.safetensors", 7, 7, 1))
    assert "7 (model-*-of-00001.safetensors, 1 shards)" in line


def test_shards_the_scanner_did_not_mark_are_never_summed():
    """Per-file counts on shards are not enough: names are basenames for a
    local scan, so `a/…-00001-of-00002` and `b/…-00002-of-00002` would look
    complete. Only the scanner, which sees directories, can mark a set."""
    line = _params_line(
        _safetensors("model-00001-of-00002.safetensors", 100),
        _safetensors("model-00002-of-00002.safetensors", 200),
    )
    assert comply.TODO in line
    assert "300" not in line


def test_an_unsharded_file_without_a_count_is_not_counted():
    assert comply.TODO in _params_line(_safetensors("model.safetensors"))


def test_non_safetensors_formats_are_never_counted():
    gguf = {"type": "machine-learning-model", "name": "model.gguf", "properties": [
        {"name": "aisbom:safetensors:parameters", "value": "99"}]}
    assert comply.TODO in _params_line(gguf)


def test_hf_total_and_local_sum_are_both_shown():
    doc = _with_card_props(_hf_sbom(), ("aisbom:hf:parameters_total", "110106428"))
    doc["components"][0]["properties"].append(
        {"name": "aisbom:safetensors:parameters", "value": "110106428"})
    line = _line(_annex(doc), "Number of parameters")
    assert comply.SOURCE_HF_PARAMETERS in line
    assert comply.SOURCE_SCAN_PARAMETERS in line


# ---------------------------------------------------------------------------
# Modality (Annex XI 1(e))
# ---------------------------------------------------------------------------

def test_modality_follows_the_task_table_and_is_labelled_a_mapping():
    annex = _annex(_hf_sbom())  # task: fill-mask
    for label in ("Input modality and format", "Output modality and format"):
        line = _line(annex, label)
        assert "`text`" in line
        assert comply.SOURCE_MODALITY in line
        assert comply.MAPPING in line


def test_an_unmapped_task_leaves_modality_todo():
    doc = copy.deepcopy(_hf_sbom())
    for comp in doc["components"]:
        comp["modelCard"]["modelParameters"]["task"] = "reinforcement-learning"
    annex = _annex(doc)
    assert comply.TODO in _line(annex, "Input modality and format")
    assert comply.TODO in _line(annex, "Output modality and format")


def test_every_task_in_the_table_is_documented():
    docs = open("docs/comply.md").read()
    for task in comply.TASK_MODALITIES:
        assert f"`{task}`" in docs, task


# ---------------------------------------------------------------------------
# CO2, hardware and evaluation results (Annex XI 2(d), 2(e), Section 2)
# ---------------------------------------------------------------------------

def test_co2_is_declared_and_energy_stays_todo():
    annex = _annex(_declared_sbom())
    co2 = _line(annex, "CO2 emissions declared in the model card")
    assert "149.2 g CO2eq (source: codecarbon; training type: pre-training)" in co2
    assert "not energy" in co2
    assert comply.TODO in _line(annex, "Known or estimated energy consumption")


def test_training_hardware_is_declared_and_compute_stays_todo():
    annex = _annex(_declared_sbom())
    assert "8 x V100" in _line(annex, "Training hardware declared in the model card")
    assert comply.TODO in _line(annex, "Computational resources")


def test_evaluation_results_are_declared_and_the_evaluation_field_stays_todo():
    annex = _annex(_declared_sbom())
    declared = _line(annex, "Evaluation results declared in the model card")
    assert "accuracy 0.91 (text-classification on glue (sst2, validation))" in declared
    assert "self-reported" in declared
    assert comply.TODO in _line(annex, "Evaluation strategies, criteria, metrics and results")


@pytest.mark.parametrize("label", [
    "CO2 emissions declared in the model card",
    "Training hardware declared in the model card",
    "Evaluation results declared in the model card",
])
def test_declared_rows_are_todo_without_card_data(label):
    assert comply.TODO in _line(_annex(_hf_sbom()), label)


# ---------------------------------------------------------------------------
# Scan values beside --answers values
# ---------------------------------------------------------------------------

def test_a_provider_answer_sits_beside_a_new_scan_value():
    answers = comply.load_answers(
        "version: 1\nfields:\n  annex_xi.1d.parameter_count: 110 million\n")
    pack = comply.build_eu_ai_act_pack(_declared_sbom(), target="t", answers=answers)
    line = _line(pack[comply.ANNEX_XI_FILE], "Number of parameters")
    assert line.index("110,106,428") < line.index("110 million")
    assert "annex_xi.1d.parameter_count" in pack[comply.README_FILE]


# ---------------------------------------------------------------------------
# FDA: supplier and end-of-support lookup
# ---------------------------------------------------------------------------

def _rows(pack):
    return {r["name"]: r for r in csv.DictReader(io.StringIO(pack[comply.SUPPORT_FILE]))}


def test_new_csv_columns_are_appended_after_the_existing_ones():
    header = _fda(_local_sbom())[comply.SUPPORT_FILE].splitlines()[0].split(",")
    assert header[:9] == ["bom_ref", "name", "type", "version", "sha256", "license",
                          "support_level", "end_of_support_date", "support_source"]
    assert header[9:] == ["supplier", "supplier_source",
                          "end_of_support_lookup", "end_of_support_lookup_source"]


def test_model_supplier_is_the_repo_owner_when_no_foreign_base_model():
    doc = _with_card_props(_hf_sbom(), ("aisbom:hf:author", "google-bert"))
    row = _rows(_fda(doc))["model.safetensors"]
    assert row["supplier"] == "google-bert"
    assert row["supplier_source"] == comply.SOURCE_SUPPLIER_HF


def test_a_base_model_in_the_owners_namespace_keeps_the_owner_as_supplier():
    row = _rows(_fda(_declared_sbom()))["model.safetensors"]  # google-bert/bert-large-uncased
    assert row["supplier"] == "google-bert"


@pytest.mark.parametrize("base", ["meta-llama/Llama-3.1-8B", "bert-base-uncased"])
def test_a_fine_tune_of_another_namespace_leaves_supplier_todo(base):
    doc = _with_card_props(_hf_sbom(), ("aisbom:hf:author", "acme"),
                           ("aisbom:hf:base_model", base))
    row = _rows(_fda(doc))["model.safetensors"]
    assert row["supplier"] == comply.TODO
    assert row["supplier_source"] == f"not filled: derived from {base}"


def test_a_model_with_no_repo_owner_has_no_supplier():
    row = _rows(_fda(_local_sbom()))["weights|v2.pt"]
    assert row["supplier"] == comply.TODO and row["supplier_source"] == ""


def test_package_supplier_is_its_pypi_author():
    doc = copy.deepcopy(_local_sbom())
    doc["components"][1]["properties"] = [{"name": "aisbom:pypi:author", "value": "PyTorch Team"}]
    row = _rows(_fda(doc))["torch"]
    assert row["supplier"] == "PyTorch Team"
    assert row["supplier_source"] == comply.SOURCE_SUPPLIER_PYPI
    assert "1 of 2 component(s) carry one" in _fda(doc)[comply.README_FILE]


def test_package_without_author_has_no_supplier():
    assert _rows(_fda(_local_sbom()))["torch"]["supplier"] == comply.TODO


@dataclass
class _Eol:
    date: str
    source: str


def _fda_eol(doc, answers=None, note=None, eol=None):
    return comply.build_fda_pack(
        doc, target="./models", vex_statements=[], vex_files=[],
        answers=answers, eol_answers=eol, eol_note=note,
    )


_TORCH_EOL = {"dependency-0-torch": _Eol("2027-01-31", "endoflife.date torch 2.10")}


def test_lookup_date_fills_end_of_support_and_is_recorded():
    pack = _fda_eol(_local_sbom(), eol=_TORCH_EOL)
    torch = _rows(pack)["torch"]
    assert torch["end_of_support_date"] == "2027-01-31"
    assert torch["end_of_support_lookup"] == "2027-01-31"
    assert torch["end_of_support_lookup_source"] == "endoflife.date torch 2.10"
    assert torch["support_level"] == comply.TODO
    assert "1 of 2 component(s) carry the date endoflife.date publishes" in pack[comply.README_FILE]


def test_a_provider_date_keeps_the_cell_and_the_lookup_stays_visible():
    answers = comply.load_answers(
        "version: 1\ncomponents:\n  - name: torch\n    end_of_support_date: 2030-12-31\n")
    torch = _rows(_fda_eol(_local_sbom(), answers=answers, eol=_TORCH_EOL))["torch"]
    assert torch["end_of_support_date"] == "2030-12-31"
    assert torch["support_source"] == comply.SOURCE_PROVIDER
    assert torch["end_of_support_lookup"] == "2027-01-31"


def test_model_files_never_take_a_lookup_date():
    eol = {"artifact-0-weights|v2.pt": _Eol("2027-01-31", "x")}
    row = _rows(_fda_eol(_local_sbom(), eol=eol))["weights|v2.pt"]
    assert row["end_of_support_date"] == comply.TODO
    assert row["end_of_support_lookup"] == ""


def test_untracked_components_stay_todo():
    torch = _rows(_fda_eol(_local_sbom(), eol={}))["torch"]
    assert torch["end_of_support_date"] == comply.TODO
    assert torch["end_of_support_lookup"] == ""


def test_the_readme_says_why_the_lookup_did_not_run():
    readme = _fda_eol(_local_sbom(), note="skipped (--offline)")[comply.README_FILE]
    assert "Lookup: skipped (--offline)." in readme
    assert "not in `sbom.json`" in readme


def test_eol_targets_are_exact_pins_only_keyed_by_bom_ref():
    """`numpy>=2.2.0` is recorded as version 2.2.0 but is not what is
    installed; matching it to the 2.2 cycle would be a guess."""
    deps = [
        {"name": "torch", "version": "2.10.0", "pinned": True},
        {"name": "numpy", "version": "2.2.0", "pinned": False},
        {"name": "requests", "version": "unknown", "pinned": False},
    ]
    assert comply.eol_targets(deps) == [("dependency-0-torch", "torch", "2.10.0")]


# ---------------------------------------------------------------------------
# CLI: the endoflife.date lookup
# ---------------------------------------------------------------------------

def _fda_cli(tmp_path, monkeypatch, *flags, lookup=None):
    from typer.testing import CliRunner

    from aisbom import eol
    from aisbom.cli import app
    from tests.test_comply import _restricted_tree

    calls = []

    def fake_lookup(pins, **kw):
        calls.append(list(pins))
        return lookup or eol.EolLookupResult(answers={
            ("torch", "2.10.0"): eol.EolAnswer("2027-01-31", "torch", "2.10")})

    monkeypatch.setattr(eol, "lookup_end_of_support", fake_lookup)
    src = _restricted_tree(tmp_path)
    (src / "requirements.txt").write_text("torch==2.10.0\nnumpy>=2.2.0\n")
    out = tmp_path / "pack"
    result = CliRunner().invoke(app, ["comply", str(src), "--framework", "fda",
                                      "--output-dir", str(out), *flags])
    assert result.exit_code == 0, result.stdout
    return calls, out, result


def test_cli_fills_end_of_support_from_the_lookup(tmp_path, monkeypatch):
    calls, out, _ = _fda_cli(tmp_path, monkeypatch, "--no-osv")
    # The unpinned numpy>=2.2.0 is never looked up.
    assert calls == [[("torch", "2.10.0")]]
    rows = {r["name"]: r for r in csv.DictReader(io.StringIO(
        (out / comply.SUPPORT_FILE).read_text()))}
    assert rows["torch"]["end_of_support_date"] == "2027-01-31"
    assert rows["torch"]["end_of_support_lookup_source"] == "endoflife.date torch 2.10"
    assert rows["numpy"]["end_of_support_date"] == comply.TODO


@pytest.mark.parametrize("flags, env, note", [
    (("--offline",), {}, "skipped (--offline)"),
    (("--no-eol-lookup", "--no-osv"), {}, "skipped (--no-eol-lookup)"),
    (("--no-osv",), {"AISBOM_NO_EOL_LOOKUP": "1"}, "skipped (--no-eol-lookup)"),
])
def test_cli_skips_the_lookup_when_told_to(tmp_path, monkeypatch, flags, env, note):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    calls, out, _ = _fda_cli(tmp_path, monkeypatch, *flags)
    assert calls == []
    assert f"Lookup: {note}." in (out / comply.README_FILE).read_text()


def test_cli_reports_a_failed_lookup_and_still_writes_the_pack(tmp_path, monkeypatch):
    from aisbom import eol

    failed = eol.EolLookupResult(error="endoflife.date lookup failed for 1 of 1 package(s) (x)")
    calls, out, result = _fda_cli(tmp_path, monkeypatch, "--no-osv", lookup=failed)
    assert "endoflife.date lookup failed" in result.stdout
    assert "Lookup: endoflife.date lookup failed" in (out / comply.README_FILE).read_text()


def test_cli_eu_pack_never_looks_up_end_of_support(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from aisbom import eol
    from aisbom.cli import app
    from tests.test_comply import _restricted_tree

    def boom(*a, **k):
        raise AssertionError("endoflife.date queried for an EU pack")

    monkeypatch.setattr(eol, "lookup_end_of_support", boom)
    src = _restricted_tree(tmp_path)
    (src / "requirements.txt").write_text("torch==2.10.0\n")
    result = CliRunner().invoke(app, ["comply", str(src), "--framework", "eu-ai-act",
                                      "--output-dir", str(tmp_path / "eu")])
    assert result.exit_code == 0, result.stdout


@pytest.mark.parametrize("make", [
    lambda: _eu(_declared_sbom()),
    lambda: _fda_eol(_declared_sbom(), eol=_TORCH_EOL, note="failed"),
])
def test_new_wording_uses_no_verdict_language(make):
    text = "\n".join(make().values()).lower()
    for word in comply.VERDICT_WORDS:
        assert word not in text, word
