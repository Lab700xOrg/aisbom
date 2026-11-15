"""`aisbom comply --answers`: the provider-maintained file that fills the
TODO fields of a comply pack, so the provider writes each answer once."""

import csv
import io
import re
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from aisbom import comply
from aisbom.cli import app

from tests.test_comply import _eu, _fda, _hf_sbom, _local_sbom, _restricted_tree, _section

runner = CliRunner()

DOCS = Path(__file__).resolve().parent.parent / "docs" / "comply.md"


def _answers(text):
    return comply.load_answers(text)


def _support_rows(pack):
    return list(csv.DictReader(io.StringIO(pack[comply.SUPPORT_FILE])))


# ---------------------------------------------------------------------------
# Field ids
# ---------------------------------------------------------------------------

def test_every_field_has_a_unique_stable_id():
    ids = comply.field_ids()
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"(annex_xi|art53)\.[a-z0-9_]+\.[a-z0-9_]+", i) for i in ids), ids
    # Spot-check ids the docs and users depend on.
    for fid in ("annex_xi.1c.release_date", "annex_xi.1d.parameter_count",
                "art53.1_1.provider", "art53.2_1.declared_datasets",
                "art53.2_3.modalities", "art53.2_5.modalities"):
        assert fid in ids


def test_every_todo_in_an_empty_pack_has_an_id():
    """No field may be unanswerable: every TODO line maps to an id."""
    pack = _eu({"components": []})
    todo_lines = sum(
        1
        for name, text in pack.items() if name != comply.README_FILE
        for line in text.splitlines()
        if line.startswith("- **") and f"**{comply.TODO}**" in line
    )
    assert todo_lines == len(comply.field_ids())


def test_docs_list_every_field_id():
    text = DOCS.read_text()
    missing = [fid for fid in comply.field_ids() if f"`{fid}`" not in text]
    assert missing == []


# ---------------------------------------------------------------------------
# Loading and validating the file
# ---------------------------------------------------------------------------

def test_values_are_normalised():
    a = _answers(
        "version: 1\n"
        "fields:\n"
        "  annex_xi.1c.release_date: 2025-07-01\n"
        "  art53.2_1.used: yes\n"
        "  art53.2_3.crawlers_used: false\n"
        "  annex_xi.2d.compute: 3.1e+23\n"
        "  art53.1_3.modalities: [Text, Image]\n"
        "  art53.1_1.provider: '  Acme AI  '\n"
        "  art53.3_3.other_information: ''\n"
        "  art53.3_2.illegal_content_measures:\n"
    )
    assert a.fields == {
        "annex_xi.1c.release_date": "2025-07-01",
        "art53.2_1.used": "Yes",
        "art53.2_3.crawlers_used": "No",
        "annex_xi.2d.compute": "3.1e+23",
        "art53.1_3.modalities": "Text; Image",
        "art53.1_1.provider": "Acme AI",
    }


def test_an_empty_file_is_an_empty_answer_set():
    a = _answers("")
    assert a.fields == {} and a.components == []


@pytest.mark.parametrize("text,needle", [
    ("fields: [unclosed", "YAML"),
    ("- just\n- a list\n", "mapping"),
    ("version: 2\n", "version"),
    ("colour: blue\n", "colour"),
    ("fields:\n  annex_xi.1c.release_dat: 2025-07-01\n", "annex_xi.1c.release_dat"),
    ("fields:\n  art53.1_1.provider: {name: Acme}\n", "art53.1_1.provider"),
    ("fields: [a, b]\n", "fields"),
    ("components: {name: torch}\n", "components"),
    ("components:\n  - support_level: x\n", "match"),
    ("components:\n  - name: torch\n    owner: me\n", "owner"),
    ("components:\n  - just-a-string\n", "components[0]"),
    ("fields:\n  art53.1_1.provider: A\n  art53.1_1.provider: B\n", "duplicate"),
    ("? [a, b]\n: 1\n", "YAML"),
    ("components:\n  - name: torch\n    support_level: {a: 1}\n", "components[0].support_level"),
])
def test_malformed_files_fail_loudly(text, needle):
    with pytest.raises(comply.AnswersError) as err:
        _answers(text)
    assert needle in str(err.value)


def test_every_problem_is_reported_at_once():
    with pytest.raises(comply.AnswersError) as err:
        _answers("fields:\n  nope.a.b: 1\n  nope.c.d: 2\n")
    assert "nope.a.b" in str(err.value) and "nope.c.d" in str(err.value)
    assert len(err.value.problems) == 2


# ---------------------------------------------------------------------------
# EU AI Act pack with answers
# ---------------------------------------------------------------------------

_EU_ANSWERS = (
    "fields:\n"
    "  annex_xi.1c.release_date: 2025-07-01\n"
    "  art53.1_1.provider: Acme AI, ops@acme.example\n"
    "  annex_xi.1f.licence: Acme Community Licence\n"
    "  annex_xi.2b.training_methods: |\n"
    "    Pre-training on public text.\n"
    "\n"
    "    Then supervised fine-tuning.\n"
)


def test_answers_fill_todo_fields_tagged_as_provider_supplied():
    pack = comply.build_eu_ai_act_pack(
        _hf_sbom(), target="hf://x", answers=_answers(_EU_ANSWERS))
    annex = pack[comply.ANNEX_XI_FILE]
    line = next(l for l in annex.splitlines() if l.startswith("- **Date of release"))
    assert "2025-07-01" in line
    assert comply.SOURCE_PROVIDER in line
    assert comply.TODO not in line
    art53 = pack[comply.ART53_FILE]
    body = _section(art53, "### 1.1", "### 1.2")
    assert "Acme AI, ops@acme.example" in body


def test_multi_line_answers_keep_their_paragraphs():
    annex = comply.build_eu_ai_act_pack(
        _hf_sbom(), target="hf://x", answers=_answers(_EU_ANSWERS))[comply.ANNEX_XI_FILE]
    body = _section(annex, "### Point 2(b)", "### Point 2(c)")
    assert "  Pre-training on public text.\n\n  Then supervised fine-tuning." in body


def test_scan_read_values_are_never_overwritten():
    pack = comply.build_eu_ai_act_pack(
        _hf_sbom(), target="hf://x", answers=_answers(_EU_ANSWERS))
    annex = pack[comply.ANNEX_XI_FILE]
    line = next(l for l in annex.splitlines() if l.startswith("- **Licence:**"))
    assert "apache-2.0" in line and comply.SOURCE_HF in line
    assert "Acme Community Licence" in line and comply.SOURCE_PROVIDER in line
    assert line.index("apache-2.0") < line.index("Acme Community Licence")
    readme = pack[comply.README_FILE]
    both = readme.split("both", 1)[1]
    assert "`annex_xi.1f.licence`" in both


def test_an_answer_for_a_field_the_scan_missed_is_just_provider_supplied():
    pack = comply.build_eu_ai_act_pack(
        _local_sbom(), target="./m", answers=_answers(_EU_ANSWERS))
    line = next(l for l in pack[comply.ANNEX_XI_FILE].splitlines()
                if l.startswith("- **Licence:**"))
    assert "Acme Community Licence" in line and comply.TODO not in line
    assert "annex_xi.1f.licence" not in pack[comply.README_FILE]


def test_index_counts_provider_supplied_fields_separately():
    plain = comply.build_eu_ai_act_pack(_hf_sbom(), target="hf://x")[comply.README_FILE]
    filled = int(re.search(r"(\d+) field\(s\) pre-filled", plain).group(1))
    todo = int(re.search(r"(\d+) left as TODO", plain).group(1))
    readme = comply.build_eu_ai_act_pack(
        _hf_sbom(), target="hf://x", answers=_answers(_EU_ANSWERS))[comply.README_FILE]
    assert re.search(rf"\b{filled} field\(s\) pre-filled", readme)
    assert "3 provider-supplied" in readme
    assert re.search(rf"\b{todo - 3} left as TODO", readme)


def test_a_pack_without_answers_is_unchanged():
    """No answers file: no provider values, legend, counts or conflict list."""
    for text in comply.build_eu_ai_act_pack(_hf_sbom(), target="hf://x").values():
        field_lines = [l for l in text.splitlines() if l.startswith("- **")]
        assert not any(comply.SOURCE_PROVIDER in l for l in field_lines)
        assert "come from the provider's answers file" not in text
        assert "provider-supplied from the answers file" not in text
        assert "Fields with both" not in text


# ---------------------------------------------------------------------------
# FDA pack with answers
# ---------------------------------------------------------------------------

_FDA_ANSWERS = (
    "components:\n"
    "  - name: torch\n"
    "    support_level: Supported by Acme\n"
    "    end_of_support_date: 2027-12-31\n"
    "  - name: retired-package\n"
    "    support_level: none\n"
)


def _fda_with(answers_text, doc=None):
    return comply.build_fda_pack(
        doc or _local_sbom(), target="./m", vex_statements=[], vex_files=[],
        answers=_answers(answers_text),
    )


def test_support_table_takes_lifecycle_from_answers_per_component():
    rows = _support_rows(_fda_with(_FDA_ANSWERS))
    model, torch = rows
    assert torch["support_level"] == "Supported by Acme"
    assert torch["end_of_support_date"] == "2027-12-31"
    assert torch["support_source"] == "provider-supplied"
    assert model["support_level"] == comply.TODO
    assert model["support_source"] == ""


@pytest.mark.parametrize("key", [
    "sha256: " + "A" * 64,
    "purl: pkg:pypi/torch@2.10.0",
    "bom_ref: dependency-0-torch",
])
def test_components_match_on_hash_purl_or_bom_ref(key):
    text = f"components:\n  - {key}\n    support_level: matched\n"
    rows = _support_rows(_fda_with(text))
    assert "matched" in [r["support_level"] for r in rows]


def test_every_given_match_key_must_agree():
    text = "components:\n  - name: torch\n    version: '9.9'\n    support_level: wrong\n"
    rows = _support_rows(_fda_with(text))
    assert all(r["support_level"] == comply.TODO for r in rows)


def test_first_matching_entry_wins_per_column():
    text = (
        "components:\n"
        "  - name: torch\n    end_of_support_date: 2027-01-01\n"
        "  - name: torch\n    support_level: second\n    end_of_support_date: 2099-01-01\n"
    )
    torch = _support_rows(_fda_with(text))[1]
    assert torch["end_of_support_date"] == "2027-01-01"
    assert torch["support_level"] == "second"


def test_unmatched_component_entries_are_reported():
    unmatched = comply.unmatched_component_answers(_local_sbom(), _answers(_FDA_ANSWERS))
    assert unmatched == ["name=retired-package"]


def test_fda_index_counts_components_with_provider_support_data():
    readme = _fda_with(_FDA_ANSWERS)[comply.README_FILE]
    assert "1 of 2 component(s)" in readme
    assert "provider-supplied" in readme
    plain = _fda(_local_sbom())[comply.README_FILE]
    assert "component(s) in" not in plain
    assert f"marks both {comply.TODO}" in plain


# ---------------------------------------------------------------------------
# Verdict words in provider text
# ---------------------------------------------------------------------------

def test_verdict_words_in_provider_text_are_found_by_field():
    a = _answers(
        "fields:\n"
        "  art53.3_1.rights_reservation_measures: We are fully compliant.\n"
        "  art53.3_2.illegal_content_measures: Illegally obtained data is removed.\n"
        "components:\n"
        "  - name: torch\n    support_level: Guaranteed until 2030\n"
    )
    hits = comply.verdict_words_in(a)
    assert ("art53.3_1.rights_reservation_measures", "compliant") in hits
    assert ("components[0].support_level", "guaranteed") in hits
    # Word boundaries: "illegally" is not the verdict word "legally".
    assert not any(loc.startswith("art53.3_2") for loc, _ in hits)


def test_provider_text_is_written_as_given():
    a = _answers("fields:\n  art53.3_1.rights_reservation_measures: We are compliant.\n")
    art53 = comply.build_eu_ai_act_pack(_hf_sbom(), target="x", answers=a)[comply.ART53_FILE]
    assert "We are compliant." in art53


def test_aisbom_wording_with_answers_has_no_verdict_words():
    """The guard still holds for everything AIsbom itself writes."""
    pack = comply.build_eu_ai_act_pack(_hf_sbom(), target="x", answers=_answers(_EU_ANSWERS))
    text = "\n".join(pack.values()).lower()
    assert [w for w in comply.VERDICT_WORDS if w in text] == []
    fda = _fda_with(_FDA_ANSWERS)
    text = "\n".join(fda.values()).lower()
    assert [w for w in comply.VERDICT_WORDS if w in text] == []


# ---------------------------------------------------------------------------
# The starter template
# ---------------------------------------------------------------------------

def test_template_lists_every_field_id_and_the_scanned_components():
    text = comply.answers_template(_local_sbom())
    data = yaml.safe_load(text)
    assert data["version"] == 1
    assert list(data["fields"]) == comply.field_ids()
    assert all(v is None for v in data["fields"].values())
    assert {"name": "torch", "version": "2.10.0",
            "support_level": None, "end_of_support_date": None} in data["components"]
    assert "Date of release" in text  # labels ride along as comments


def test_template_loads_as_an_empty_answer_set():
    a = _answers(comply.answers_template(_hf_sbom()))
    assert a.fields == {}


def test_filled_template_round_trips_into_the_pack():
    text = comply.answers_template(_local_sbom()).replace(
        "\n  annex_xi.1c.release_date:\n", "\n  annex_xi.1c.release_date: 2025-07-01\n", 1)
    assert "  annex_xi.1c.release_date: 2025-07-01\n" in text
    pack = comply.build_eu_ai_act_pack(_local_sbom(), target="x", answers=_answers(text))
    assert "2025-07-01" in pack[comply.ANNEX_XI_FILE]


def test_template_deduplicates_components_and_quotes_odd_names():
    doc = _local_sbom()
    doc["components"].append(dict(doc["components"][1]))
    doc["components"].append({"type": "library", "name": "a: b # c"})
    doc["components"].append({"type": "library"})  # nameless: nothing to match on
    data = yaml.safe_load(comply.answers_template(doc))
    names = [c["name"] for c in data["components"]]
    assert names.count("torch") == 1
    assert "a: b # c" in names
    assert len(names) == 3
    comply.load_answers(comply.answers_template(doc))  # still a valid file


def test_template_for_a_scan_with_no_components_is_valid():
    text = comply.answers_template({"components": []})
    assert yaml.safe_load(text)["components"] == []
    assert comply.load_answers(text).components == []


# ---------------------------------------------------------------------------
# Where users learn the answers file exists
# ---------------------------------------------------------------------------

def test_template_points_at_docs_a_pip_install_can_reach():
    """pip ships only the package, so the template links the docs online."""
    text = comply.answers_template(_hf_sbom())
    assert comply.DOCS_URL in text
    assert comply.DOCS_URL.startswith("https://")
    for how in ("2025-07-01", "yes", "[Text, Image]", "|"):
        assert how in text, how


@pytest.mark.parametrize("make", [
    lambda: comply.build_eu_ai_act_pack(_hf_sbom(), target="x"),
    lambda: _fda(_local_sbom()),
], ids=["eu", "fda"])
def test_every_pack_readme_explains_how_to_fill_the_todos(make):
    readme = make()[comply.README_FILE]
    assert "--write-answers-template" in readme
    assert "--answers" in readme
    assert comply.DOCS_URL in readme


def test_answers_errors_link_the_field_id_list():
    with pytest.raises(comply.AnswersError) as err:
        _answers("fields:\n  nope.a.b: 1\n")
    assert comply.DOCS_URL in str(err.value)


def test_main_readme_documents_the_answers_file():
    readme = (DOCS.parent.parent / "README.md").read_text()
    section = readme.split("### Documentation packs", 1)[1].split("\n### ", 1)[0]
    assert "--answers" in section and "--write-answers-template" in section


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _run(tmp_path, *extra, framework="eu-ai-act"):
    src = _restricted_tree(tmp_path)
    out = tmp_path / "pack"
    result = runner.invoke(app, [
        "comply", str(src), "--framework", framework, "--output-dir", str(out),
        "--offline", *extra,
    ])
    return result, out


def test_cli_fills_the_pack_from_an_answers_file(tmp_path):
    answers = tmp_path / "comply.yaml"
    answers.write_text(_EU_ANSWERS)
    result, out = _run(tmp_path, "--answers", str(answers))
    assert result.exit_code == 0, result.stdout
    assert "Acme AI" in (out / comply.ART53_FILE).read_text()
    assert "provider-supplied" in (out / comply.README_FILE).read_text()


def test_cli_rejects_a_bad_answers_file_before_scanning(tmp_path):
    answers = tmp_path / "comply.yaml"
    answers.write_text("fields:\n  annex_xi.nope.x: 1\n")
    result, out = _run(tmp_path, "--answers", str(answers))
    assert result.exit_code == 1
    assert "annex_xi.nope.x" in result.stdout
    assert not out.exists()


def test_cli_rejects_a_missing_answers_file(tmp_path):
    result, out = _run(tmp_path, "--answers", str(tmp_path / "missing.yaml"))
    assert result.exit_code == 1
    assert "missing.yaml" in result.stdout
    assert not out.exists()


def test_cli_warns_on_verdict_words_and_still_writes(tmp_path):
    answers = tmp_path / "comply.yaml"
    answers.write_text("fields:\n  art53.3_1.rights_reservation_measures: fully compliant\n")
    result, out = _run(tmp_path, "--answers", str(answers))
    assert result.exit_code == 0, result.stdout
    assert "art53.3_1.rights_reservation_measures" in result.stdout
    assert "fully compliant" in (out / comply.ART53_FILE).read_text()


def test_cli_warns_on_unmatched_components_for_fda(tmp_path):
    answers = tmp_path / "comply.yaml"
    answers.write_text(_FDA_ANSWERS)
    result, out = _run(tmp_path, "--answers", str(answers), framework="fda")
    assert result.exit_code == 0, result.stdout
    assert "retired-package" in result.stdout


def test_cli_closing_line_points_at_the_template_flag(tmp_path):
    result, _ = _run(tmp_path)
    assert result.exit_code == 0, result.stdout
    assert "--write-answers-template" in " ".join(result.stdout.split())


def test_cli_closing_line_skips_the_hint_once_answers_are_used(tmp_path):
    answers = tmp_path / "comply.yaml"
    answers.write_text(_EU_ANSWERS)
    result, _ = _run(tmp_path, "--answers", str(answers))
    assert result.exit_code == 0, result.stdout
    assert "--write-answers-template" not in " ".join(result.stdout.split())


def test_cli_writes_a_template_and_refuses_to_overwrite_one(tmp_path):
    template = tmp_path / "comply.yaml"
    result, _ = _run(tmp_path, "--write-answers-template", str(template))
    assert result.exit_code == 0, result.stdout
    assert yaml.safe_load(template.read_text())["version"] == 1

    template.write_text("# my answers\n")
    out = tmp_path / "pack2"
    result = runner.invoke(app, [
        "comply", str(tmp_path / "models"), "--framework", "fda", "--output-dir", str(out),
        "--offline", "--write-answers-template", str(template),
    ])
    assert result.exit_code == 1
    assert template.read_text() == "# my answers\n"
    assert not out.exists()
