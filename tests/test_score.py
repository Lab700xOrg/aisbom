"""Tests for `aisbom score` — AIBOM completeness/quality grading (#114)."""

import json

import pytest
from typer.testing import CliRunner

from aisbom import score
from aisbom.cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures: three documents spanning the grade range.
# ---------------------------------------------------------------------------

def _minimal_sbom():
    """The least a CycloneDX document can carry and still parse."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": [
            {"type": "machine-learning-model", "name": "model.pt"},
        ],
    }


def _partial_sbom():
    """What a local `aisbom scan` actually produces today: hashes and identity,
    no model card, no datasets, patchy licenses."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
        "metadata": {"timestamp": "2026-08-30T00:00:00+00:00"},
        "components": [
            {
                "type": "machine-learning-model",
                "name": "clean.safetensors",
                "bom-ref": "artifact-0-clean.safetensors",
                "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            {
                "type": "machine-learning-model",
                "name": "model.pt",
                "bom-ref": "artifact-1-model.pt",
                "hashes": [{"alg": "SHA-256", "content": "b" * 64}],
            },
            {
                "type": "library",
                "name": "torch",
                "bom-ref": "lib-torch",
                "version": "2.10.0",
            },
        ],
    }


def _complete_sbom():
    """Everything a dimension can ask for, so the top of the scale is reachable."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
        "metadata": {
            "timestamp": "2026-08-30T00:00:00+00:00",
            "tools": {"components": [{"type": "application", "name": "aisbom-cli"}]},
        },
        "components": [
            {
                "type": "machine-learning-model",
                "name": "bert.safetensors",
                "bom-ref": "artifact-0-bert.safetensors",
                "version": "main",
                "hashes": [{"alg": "SHA-256", "content": "c" * 64}],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "modelCard": {
                    "modelParameters": {
                        "task": "fill-mask",
                        "architectureFamily": "bert",
                        "datasets": [{"type": "dataset", "name": "bookcorpus"}],
                    },
                },
            },
            {
                "type": "library",
                "name": "torch",
                "bom-ref": "lib-torch",
                "version": "2.10.0",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
            },
        ],
        "vulnerabilities": [
            {"id": "aisbom-pickle-rce", "analysis": {"state": "not_affected"}}
        ],
    }


# ---------------------------------------------------------------------------
# Tracer bullet: the core API exists and grades the range.
# ---------------------------------------------------------------------------

def test_minimal_sbom_scores_low():
    report = score.score_sbom(_minimal_sbom())
    assert 0 <= report.overall <= 100
    assert report.grade == "F"


def test_complete_sbom_scores_high():
    report = score.score_sbom(_complete_sbom())
    assert report.grade == "A"


def test_partial_sbom_lands_between_the_two():
    minimal = score.score_sbom(_minimal_sbom()).overall
    partial = score.score_sbom(_partial_sbom()).overall
    complete = score.score_sbom(_complete_sbom()).overall
    assert minimal < partial < complete


# ---------------------------------------------------------------------------
# The weighting scheme itself.
# ---------------------------------------------------------------------------

def test_weights_sum_to_100():
    assert sum(d.weight for d in score.DIMENSIONS) == 100


def test_every_dimension_is_reported():
    report = score.score_sbom(_partial_sbom())
    assert [d.key for d in report.dimensions] == [d.key for d in score.DIMENSIONS]


def test_overall_is_the_weighted_mean_of_the_dimensions():
    report = score.score_sbom(_partial_sbom())
    expected = sum(d.score * d.weight for d in report.dimensions) / 100.0
    assert report.overall == pytest.approx(expected, abs=0.05)


@pytest.mark.parametrize(
    "overall,grade",
    [(100, "A"), (85, "A"), (84.9, "B"), (70, "B"), (69.9, "C"),
     (55, "C"), (54.9, "D"), (40, "D"), (39.9, "F"), (0, "F")],
)
def test_grade_bands(overall, grade):
    assert score.grade_for(overall) == grade


# ---------------------------------------------------------------------------
# Per-dimension behaviour.
# ---------------------------------------------------------------------------

def _dim(report, key):
    return next(d for d in report.dimensions if d.key == key)


def test_placeholder_version_earns_no_identity_credit():
    """`version: "unknown"` carries no more information than an absent field."""
    doc = _minimal_sbom()
    doc["components"] = [
        {"type": "library", "name": "numpy", "bom-ref": "r", "version": "unknown"},
    ]
    real = _minimal_sbom()
    real["components"] = [
        {"type": "library", "name": "numpy", "bom-ref": "r", "version": "2.1.0"},
    ]
    assert _dim(score.score_sbom(doc), "identity").score < \
        _dim(score.score_sbom(real), "identity").score


def test_model_components_are_not_penalised_for_having_no_version():
    """A model file has a digest, not a release number."""
    doc = _minimal_sbom()
    doc["components"] = [
        {"type": "machine-learning-model", "name": "m.pt", "bom-ref": "r"},
    ]
    assert _dim(score.score_sbom(doc), "identity").score == 100.0


def test_hf_license_property_is_credited_and_named():
    """#111 routes HF licenses to a property, not licenses[] — crediting it
    stops the grade punishing users for a decision they cannot influence."""
    doc = _minimal_sbom()
    doc["components"] = [{
        "type": "machine-learning-model",
        "name": "bert.safetensors",
        "bom-ref": "r",
        "modelCard": {"properties": [
            {"name": "aisbom:hf:license", "value": "apache-2.0"},
        ]},
    }]
    dim = _dim(score.score_sbom(doc), "licenses")
    assert dim.score == 100.0
    assert any("aisbom:hf:license" in g and "apache-2.0" in g for g in dim.gaps)


def test_a_component_with_no_license_anywhere_scores_zero():
    doc = _minimal_sbom()
    dim = _dim(score.score_sbom(doc), "licenses")
    assert dim.score == 0.0
    assert any("no license declared" in g for g in dim.gaps)


def test_checksum_remediation_explains_the_remote_scan_cause():
    """The cause lives on the dimension, not repeated on every component."""
    dim = _dim(score.score_sbom(_minimal_sbom()), "checksums")
    assert dim.score == 0.0
    assert "remote scans" in dim.remediation
    assert all("remote scans" not in g for g in dim.gaps)


def test_empty_hash_entry_is_not_a_checksum():
    doc = _minimal_sbom()
    doc["components"][0]["hashes"] = [{"alg": "SHA-256"}]
    assert _dim(score.score_sbom(doc), "checksums").score == 0.0


def test_dependency_only_sbom_fails_the_ai_dimensions():
    """An SBOM with no models is not an AIBOM, and says so rather than
    collecting free points on dimensions it never had to satisfy."""
    doc = _minimal_sbom()
    doc["components"] = [
        {"type": "library", "name": "torch", "bom-ref": "r", "version": "2.10.0"},
    ]
    report = score.score_sbom(doc)
    for key in ("checksums", "modelcard", "datasets"):
        assert _dim(report, key).score == 0.0
    assert any("not an AIBOM" in g for g in _dim(report, "checksums").gaps)


@pytest.mark.parametrize("params,expected", [
    ({"task": "fill-mask"}, 100.0),
    ({"architectureFamily": "bert"}, 100.0),
    ({"modelArchitecture": "BertForMaskedLM"}, 100.0),
    ({"datasets": [{"name": "x"}]}, 0.0),
    ({}, 0.0),
])
def test_modelcard_needs_task_or_architecture(params, expected):
    doc = _minimal_sbom()
    doc["components"][0]["modelCard"] = {"modelParameters": params}
    assert _dim(score.score_sbom(doc), "modelcard").score == expected


def test_datasets_dimension_reads_model_parameters():
    doc = _minimal_sbom()
    doc["components"][0]["modelCard"] = {
        "modelParameters": {"datasets": [{"type": "dataset", "name": "bookcorpus"}]}
    }
    assert _dim(score.score_sbom(doc), "datasets").score == 100.0


def test_document_provenance_names_each_missing_field():
    dim = _dim(score.score_sbom(_minimal_sbom()), "docprov")
    assert dim.score == 25.0  # specVersion only
    joined = " ".join(dim.gaps)
    assert "metadata.tools" in joined and "serialNumber" in joined


def test_malformed_components_are_ignored_not_fatal():
    doc = _minimal_sbom()
    doc["components"] = ["not a dict", None, {"type": "library", "name": "ok",
                                              "bom-ref": "r", "version": "1.0"}]
    report = score.score_sbom(doc)
    assert report.component_count == 1


def test_empty_document_scores_zero_without_raising():
    report = score.score_sbom({"bomFormat": "CycloneDX"})
    assert report.overall == 0.0
    assert report.grade == "F"


# ---------------------------------------------------------------------------
# The improvement plan.
# ---------------------------------------------------------------------------

def test_improvement_plan_is_ranked_by_points_recoverable():
    """The ordering is the feature: a one-flag ten-point fix must outrank a
    sub-point missing version string."""
    plan = score.score_sbom(_partial_sbom()).improvement_plan()
    points = [d.points_recoverable for d in plan]
    assert points == sorted(points, reverse=True)


def test_improvement_plan_omits_complete_dimensions():
    plan = score.score_sbom(_complete_sbom()).improvement_plan()
    assert plan == []


def test_points_recoverable_is_the_dimension_shortfall():
    dim = _dim(score.score_sbom(_minimal_sbom()), "vex")
    assert dim.score == 0.0
    assert dim.points_recoverable == 10.0  # the full weight


def test_potential_is_what_closing_every_gap_would_score():
    report = score.score_sbom(_partial_sbom())
    assert report.potential == pytest.approx(
        min(100.0, report.overall + sum(d.points_recoverable
                                        for d in report.dimensions)), abs=0.05
    )
    assert report.potential > report.overall


def test_a_complete_document_has_no_potential_left():
    report = score.score_sbom(_complete_sbom())
    assert report.potential == pytest.approx(report.overall, abs=0.05)


def test_incomplete_dimensions_carry_a_remediation():
    for dim in score.score_sbom(_partial_sbom()).improvement_plan():
        assert dim.remediation, f"{dim.key} has no remediation"
        assert dim.summary, f"{dim.key} has no summary"


def test_complete_dimensions_carry_no_remediation():
    for dim in score.score_sbom(_complete_sbom()).dimensions:
        assert dim.remediation is None


def test_vex_remediation_names_the_actual_flag():
    dim = _dim(score.score_sbom(_minimal_sbom()), "vex")
    assert "--vex" in dim.remediation


def test_gaps_are_not_repeated_per_component_in_the_remediation():
    """The wall-of-lines problem: one remedy per dimension, not per component."""
    report = score.score_sbom(_partial_sbom())
    dim = _dim(report, "modelcard")
    assert len(dim.gaps) == 2          # both models
    assert isinstance(dim.remediation, str)   # but only one remedy


# ---------------------------------------------------------------------------
# Review findings (PR #100).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("alg", ["MD5", "SHA-1"])
def test_a_non_sha256_digest_earns_no_checksum_credit(alg):
    """The dimension is defined as SHA-256; a weaker digest is not it."""
    doc = _minimal_sbom()
    doc["components"][0]["hashes"] = [{"alg": alg, "content": "d" * 32}]
    assert _dim(score.score_sbom(doc), "checksums").score == 0.0


def test_a_malformed_sha256_earns_no_checksum_credit():
    doc = _minimal_sbom()
    doc["components"][0]["hashes"] = [{"alg": "SHA-256", "content": "not-a-digest"}]
    assert _dim(score.score_sbom(doc), "checksums").score == 0.0


def test_sha256_alongside_a_weaker_digest_still_counts():
    doc = _minimal_sbom()
    doc["components"][0]["hashes"] = [
        {"alg": "MD5", "content": "d" * 32},
        {"alg": "SHA-256", "content": "e" * 64},
    ]
    assert _dim(score.score_sbom(doc), "checksums").score == 100.0


def test_vulnerabilities_without_an_analysis_state_are_not_vex():
    """A vulnerability inventory is not an exploitability statement."""
    doc = _minimal_sbom()
    doc["vulnerabilities"] = [{"id": "CVE-2024-1", "ratings": [{"severity": "high"}]}]
    assert _dim(score.score_sbom(doc), "vex").score == 0.0


def test_vulnerabilities_with_an_analysis_state_are_vex():
    doc = _minimal_sbom()
    doc["vulnerabilities"] = [
        {"id": "CVE-2024-1", "analysis": {"state": "not_affected"}}
    ]
    assert _dim(score.score_sbom(doc), "vex").score == 100.0


def _openvex(serial, ref="artifact-0-model.pt"):
    return {
        "@id": f"{serial}#openvex",
        "statements": [{
            "vulnerability": {"name": "AISBOM-PICKLE-RCE"},
            "status": "not_affected",
            "products": [{"@id": f"{serial}#{ref}"}],
        }],
    }


def test_a_stale_sibling_vex_from_a_previous_scan_earns_nothing(tmp_path):
    """Regenerating an SBOM without --vex leaves the old VEX files on disk.
    They describe a document with a different serial, so crediting them would
    award ten points for statements about a scan that no longer exists."""
    doc = _minimal_sbom()
    doc["serialNumber"] = "urn:uuid:aaaaaaaa-0000-0000-0000-000000000000"
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(doc))
    (tmp_path / "sbom.openvex.json").write_text(json.dumps(
        _openvex("urn:uuid:bbbbbbbb-1111-1111-1111-111111111111")   # a prior run
    ))
    report = score.score_sbom(doc, vex_documents=score.discover_vex(sbom))
    assert _dim(report, "vex").score == 0.0


def test_a_sibling_vex_for_this_document_is_credited(tmp_path):
    doc = _minimal_sbom()
    doc["serialNumber"] = "urn:uuid:aaaaaaaa-0000-0000-0000-000000000000"
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(doc))
    (tmp_path / "sbom.openvex.json").write_text(
        json.dumps(_openvex(doc["serialNumber"]))
    )
    report = score.score_sbom(doc, vex_documents=score.discover_vex(sbom))
    assert _dim(report, "vex").score == 100.0


def test_a_cyclonedx_vex_is_matched_on_its_serial_number(tmp_path):
    doc = _minimal_sbom()
    doc["serialNumber"] = "urn:uuid:aaaaaaaa-0000-0000-0000-000000000000"
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(doc))
    (tmp_path / "sbom.vex.cdx.json").write_text(json.dumps({
        "bomFormat": "CycloneDX",
        "serialNumber": doc["serialNumber"],
        "vulnerabilities": [{"id": "X", "analysis": {"state": "not_affected"}}],
    }))
    report = score.score_sbom(doc, vex_documents=score.discover_vex(sbom))
    assert _dim(report, "vex").score == 100.0


def test_vex_cannot_be_bound_to_a_document_with_no_serial(tmp_path):
    """Without a serial there is nothing to bind the statements to, so the
    claim that they describe *this* document cannot be checked."""
    doc = _minimal_sbom()                      # no serialNumber
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(doc))
    (tmp_path / "sbom.openvex.json").write_text(
        json.dumps(_openvex("urn:uuid:cccccccc-2222-2222-2222-222222222222"))
    )
    report = score.score_sbom(doc, vex_documents=score.discover_vex(sbom))
    assert _dim(report, "vex").score == 0.0


def test_load_sbom_requires_the_cyclonedx_bomformat(tmp_path):
    """`specVersion` alone does not identify a document as CycloneDX."""
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"specVersion": "1.7", "components": []}))
    with pytest.raises(score.ScoreInputError, match="not a CycloneDX"):
        score.load_sbom(path)


def test_load_sbom_rejects_a_document_declaring_another_bomformat(tmp_path):
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"bomFormat": "SomethingElse", "specVersion": "1.7"}))
    with pytest.raises(score.ScoreInputError, match="not a CycloneDX"):
        score.load_sbom(path)


# ---------------------------------------------------------------------------
# VEX discovery.
# ---------------------------------------------------------------------------

def test_sibling_vex_filenames_match_what_scan_writes(tmp_path):
    """Mirrors cli._vex_paths so `scan --vex` then `score` needs no flags."""
    paths = score.vex_paths_for(tmp_path / "sbom.json")
    assert [p.name for p in paths] == ["sbom.openvex.json", "sbom.vex.cdx.json"]


def test_discover_vex_finds_only_files_that_exist(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}")
    assert score.discover_vex(sbom) == []
    openvex = tmp_path / "sbom.openvex.json"
    openvex.write_text(json.dumps({"statements": [{"vulnerability": {"name": "x"}}]}))
    assert score.discover_vex(sbom) == [openvex]


def test_a_discovered_vex_document_scores_the_dimension(tmp_path):
    doc = _minimal_sbom()
    doc["serialNumber"] = "urn:uuid:dddddddd-3333-3333-3333-333333333333"
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(doc))
    (tmp_path / "sbom.openvex.json").write_text(
        json.dumps(_openvex(doc["serialNumber"]))
    )
    report = score.score_sbom(doc, vex_documents=score.discover_vex(sbom))
    assert _dim(report, "vex").score == 100.0


def test_an_empty_or_unreadable_vex_document_does_not_score(tmp_path):
    empty = tmp_path / "sbom.openvex.json"
    empty.write_text(json.dumps({"statements": []}))
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    report = score.score_sbom(_minimal_sbom(), vex_documents=[empty, broken])
    assert _dim(report, "vex").score == 0.0


# ---------------------------------------------------------------------------
# Input handling.
# ---------------------------------------------------------------------------

def test_load_sbom_reads_a_cyclonedx_document(tmp_path):
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(_complete_sbom()))
    assert score.load_sbom(path)["specVersion"] == "1.7"


def test_load_sbom_rejects_spdx_23_by_name(tmp_path):
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": []}))
    with pytest.raises(score.ScoreInputError, match="SPDX"):
        score.load_sbom(path)


def test_load_sbom_rejects_spdx_30_jsonld(tmp_path):
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"@context": "x", "@graph": []}))
    with pytest.raises(score.ScoreInputError, match="SPDX"):
        score.load_sbom(path)


def test_load_sbom_rejects_unrelated_json(tmp_path):
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(score.ScoreInputError, match="not a CycloneDX"):
        score.load_sbom(path)


def test_load_sbom_rejects_malformed_json(tmp_path):
    path = tmp_path / "s.json"
    path.write_text("{not json")
    with pytest.raises(score.ScoreInputError, match="not valid JSON"):
        score.load_sbom(path)


def test_load_sbom_rejects_a_missing_file(tmp_path):
    with pytest.raises(score.ScoreInputError, match="Could not read"):
        score.load_sbom(tmp_path / "nope.json")


def test_report_to_dict_is_json_serializable():
    payload = score.score_sbom(_complete_sbom()).to_dict()
    assert json.loads(json.dumps(payload))["grade"] == "A"
    assert {d["key"] for d in payload["dimensions"]} == {d.key for d in score.DIMENSIONS}


# ---------------------------------------------------------------------------
# The CLI command.
# ---------------------------------------------------------------------------

def _write(tmp_path, doc, name="sbom.json"):
    path = tmp_path / name
    path.write_text(json.dumps(doc))
    return path


def test_cli_scores_a_file_and_names_the_dimensions(tmp_path):
    path = _write(tmp_path, _partial_sbom())
    result = runner.invoke(app, ["score", str(path)])
    assert result.exit_code == 0
    assert "Component identity" in result.stdout
    assert "Model-card coverage" in result.stdout


def test_cli_json_output_is_parseable(tmp_path):
    path = _write(tmp_path, _complete_sbom())
    result = runner.invoke(app, ["score", str(path), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["grade"] == "A"
    assert len(payload["dimensions"]) == len(score.DIMENSIONS)


def test_cli_fail_under_exits_2_when_below(tmp_path):
    path = _write(tmp_path, _minimal_sbom())
    result = runner.invoke(app, ["score", str(path), "--fail-under", "90"])
    assert result.exit_code == 2


def test_cli_fail_under_exits_0_when_at_or_above(tmp_path):
    path = _write(tmp_path, _complete_sbom())
    result = runner.invoke(app, ["score", str(path), "--fail-under", "100"])
    assert result.exit_code == 0


def test_cli_fail_under_still_gates_in_json_mode(tmp_path):
    """A CI gate that only works in human mode is not a CI gate."""
    path = _write(tmp_path, _minimal_sbom())
    result = runner.invoke(app, ["score", str(path), "--fail-under", "90", "--json"])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["grade"] == "F"


def test_cli_rejects_spdx_with_exit_1(tmp_path):
    path = _write(tmp_path, {"spdxVersion": "SPDX-2.3", "packages": []})
    result = runner.invoke(app, ["score", str(path)])
    assert result.exit_code == 1
    assert "SPDX" in result.stdout


def test_cli_rejects_an_unusable_target_with_exit_1(tmp_path):
    result = runner.invoke(app, ["score", str(tmp_path / "nope.json")])
    assert result.exit_code == 1
    assert "Cannot score" in result.stdout


def test_cli_missing_vex_override_is_an_error_not_a_silent_zero(tmp_path):
    path = _write(tmp_path, _partial_sbom())
    result = runner.invoke(
        app, ["score", str(path), "--vex", str(tmp_path / "absent.json")]
    )
    assert result.exit_code == 1
    assert "VEX document not found" in result.stdout


def test_cli_autodiscovers_sibling_vex(tmp_path):
    doc = _partial_sbom()
    path = _write(tmp_path, doc)
    (tmp_path / "sbom.openvex.json").write_text(
        json.dumps(_openvex(doc["serialNumber"], ref="artifact-1-model.pt"))
    )
    result = runner.invoke(app, ["score", str(path), "--json"])
    payload = json.loads(result.stdout)
    vex = next(d for d in payload["dimensions"] if d["key"] == "vex")
    assert vex["score"] == 100.0


def _plan_section(stdout):
    """Just the 'How to improve' block — the dimension table above it lists
    every dimension in fixed order and would mask the plan's ranking."""
    return stdout.split("How to improve", 1)[1].split("Next steps", 1)[0]


def test_cli_shows_a_ranked_improvement_plan_not_a_flat_gap_list(tmp_path):
    path = _write(tmp_path, _partial_sbom())
    result = runner.invoke(app, ["score", str(path)])
    assert "How to improve" in result.stdout
    plan = _plan_section(result.stdout)
    # The richest fix (+15.0 model card) is listed before the poorest
    # (+2.5 document provenance).
    assert plan.index("Model-card coverage") < plan.index("Document provenance")


def test_cli_omits_complete_dimensions_from_the_plan(tmp_path):
    """Identity is already 100 on this fixture, so it is not a to-do."""
    path = _write(tmp_path, _partial_sbom())
    plan = _plan_section(runner.invoke(app, ["score", str(path)]).stdout)
    assert "Component identity" not in plan


def test_cli_collapses_repeated_gaps_by_default(tmp_path):
    """Both models lack a model card, but the remedy is printed once and no
    component is named — that collapse is what keeps a 50-model scan readable."""
    path = _write(tmp_path, _partial_sbom())
    plan = _plan_section(runner.invoke(app, ["score", str(path)]).stdout)
    assert plan.count("task and architecture are read") == 1
    assert "clean.safetensors" not in plan
    assert "model.pt" not in plan


def test_cli_verbose_lists_every_affected_component(tmp_path):
    path = _write(tmp_path, _partial_sbom())
    result = runner.invoke(app, ["score", str(path), "--verbose"])
    assert "clean.safetensors" in result.stdout
    assert "model.pt" in result.stdout


def test_cli_prints_the_next_steps_footer(tmp_path):
    path = _write(tmp_path, _partial_sbom())
    result = runner.invoke(app, ["score", str(path)])
    assert "Next steps" in result.stdout
    assert "advisories" in result.stdout


def test_cli_footer_does_not_sell_the_gaps(tmp_path):
    """Almost every gap is fixable with the free CLI, so the footer points at
    trend tracking — not at paying to fix what `--vex` fixes for nothing."""
    path = _write(tmp_path, _partial_sbom())
    result = runner.invoke(app, ["score", str(path)])
    lowered = result.stdout.lower()
    for pitch in ("upgrade", "pricing", "paid plan", "buy"):
        assert pitch not in lowered


def test_json_carries_remediation_and_recoverable_points(tmp_path):
    path = _write(tmp_path, _partial_sbom())
    payload = json.loads(runner.invoke(app, ["score", str(path), "--json"]).stdout)
    assert payload["potential"] > payload["overall"]
    vex = next(d for d in payload["dimensions"] if d["key"] == "vex")
    assert vex["pointsRecoverable"] == 10.0
    assert "--vex" in vex["remediation"]


def test_json_still_carries_every_per_component_gap(tmp_path):
    """Grouping is a human-output concern; machines get the full list."""
    path = _write(tmp_path, _partial_sbom())
    payload = json.loads(runner.invoke(app, ["score", str(path), "--json"]).stdout)
    modelcard = next(d for d in payload["dimensions"] if d["key"] == "modelcard")
    assert len(modelcard["gaps"]) == 2


def test_cli_refuses_to_grade_a_partial_scan(tmp_path, monkeypatch):
    """A fetch or parse failure is recorded in results["errors"] and the scan
    returns normally, so scoring what survived would hand back a completeness
    grade for a document that is missing the shard that failed."""
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
    result = runner.invoke(app, ["score", str(tmp_path)])
    assert result.exit_code == 1
    assert "broken.pt" in result.stdout


def test_cli_scores_a_scan_target_directory(tmp_path):
    """AC #1's second half: score a target, not just a file."""
    from aisbom.mock_generator import create_mock_restricted_file

    create_mock_restricted_file(tmp_path)
    result = runner.invoke(app, ["score", str(tmp_path), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["models"] >= 1


def test_scoring_a_directory_matches_scanning_then_scoring_the_file(tmp_path):
    """`score <dir>` and `scan` + `score sbom.json` run the same builder, so a
    grade cannot depend on which route the user took."""
    from aisbom.mock_generator import create_mock_restricted_file

    create_mock_restricted_file(tmp_path)
    out = tmp_path / "out" / "sbom.json"
    out.parent.mkdir()

    scanned = runner.invoke(app, [
        "scan", str(tmp_path), "--output", str(out), "--no-fail-on-risk",
    ])
    assert scanned.exit_code == 0

    direct = json.loads(runner.invoke(
        app, ["score", str(tmp_path), "--json"]).stdout)
    via_file = json.loads(runner.invoke(
        app, ["score", str(out), "--json"]).stdout)

    assert direct["overall"] == via_file["overall"]
    assert direct["grade"] == via_file["grade"]


def test_cli_vex_override_is_honoured(tmp_path):
    doc = _partial_sbom()
    path = _write(tmp_path, doc)
    override = tmp_path / "elsewhere.json"
    override.write_text(json.dumps(
        _openvex(doc["serialNumber"], ref="artifact-1-model.pt")
    ))
    result = runner.invoke(app, ["score", str(path), "--vex", str(override), "--json"])
    payload = json.loads(result.stdout)
    vex = next(d for d in payload["dimensions"] if d["key"] == "vex")
    assert vex["score"] == 100.0
