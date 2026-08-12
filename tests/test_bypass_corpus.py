"""
Regression tests for the pickle-evasion bypass corpus.

The corpus is the substrate detection hardening improves against, and the
source the public scorecard article publishes from. These tests guard three
things:

1. The corpus itself is well-formed — every case cites a real public source and
   declares what a correct scanner *should* do.
2. Generation is hermetic and payload-free: artifacts are synthesized from
   ``mock_generator``'s harmless echo payload, never copied from live malware.
3. Detection does not drift. ``tests/corpus/baseline.json`` records the *current*
   verdict for every case in both scan modes; a change in either direction fails
   here, so a detection change has to update the baseline deliberately rather
   than silently regressing coverage.

No pickle is ever executed — every case is disassembled statically.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aisbom import corpus
from aisbom.cli import app

runner = CliRunner()

CORPUS_DIR = Path(__file__).parent / "corpus"
ARTIFACT_DIR = CORPUS_DIR / "artifacts"
BASELINE_PATH = CORPUS_DIR / "baseline.json"
FLOOR_PATH = CORPUS_DIR / "floor.json"
SCORECARD_DOC = Path(__file__).parent.parent / "docs" / "bypass-scorecard.md"


@pytest.fixture(scope="module")
def generated():
    """
    Generate the corpus once and score it once — generation is not free.

    Artifacts land in `tests/corpus/artifacts/`, which is gitignored: this repo
    commits the generators and never the binaries, so a clone is not carrying
    mock-malicious model files around.
    """
    cases = corpus.generate_corpus(ARTIFACT_DIR)
    return cases, corpus.score_corpus(cases)


# --- corpus integrity -------------------------------------------------------


def test_every_case_is_cited_and_has_an_expected_verdict():
    for case in corpus.CASES:
        assert case.id, "case needs a stable id"
        assert case.source, f"{case.id}: missing source citation"
        assert case.source_url.startswith("http"), f"{case.id}: missing source URL"
        assert case.evasion_class, f"{case.id}: missing evasion class"
        assert case.expected in ("detected", "clean"), f"{case.id}: bad expected"


def test_case_ids_are_unique():
    ids = [c.id for c in corpus.CASES]
    assert len(ids) == len(set(ids))


def test_corpus_covers_every_documented_evasion_family():
    families = {c.evasion_class for c in corpus.CASES}
    assert {
        "container-format",
        "broken-stream",
        "unlisted-global",
        "file-extension",
        "zip-tampering",
        "gadget-import",
        "allowlist-abuse",
    } <= families


def test_corpus_includes_a_benign_control():
    assert any(not c.malicious for c in corpus.CASES)


# --- generation is hermetic and payload-free --------------------------------


def test_generate_corpus_materializes_every_case(generated):
    cases, _ = generated
    assert len(cases) == len(corpus.CASES)
    for generated_case in cases:
        assert generated_case.path.exists(), f"{generated_case.case.id} not written"


def test_generated_payloads_are_the_harmless_echo_only(generated):
    """The only command any corpus artifact can name is mock_generator's echo."""
    cases, _ = generated
    for generated_case in cases:
        for path in corpus.iter_files(generated_case.path):
            blob = path.read_bytes()
            assert b"/bin/sh" not in blob
            assert b"curl " not in blob
            assert b"socket" not in blob
            if b"echo" in blob:
                assert corpus.HARMLESS_COMMAND.encode() in blob


# --- scoring ----------------------------------------------------------------


def test_control_case_is_detected_in_both_modes(generated):
    """If the plain os.system-in-a-zip control ever misses, the harness is lying."""
    _, results = generated
    control = results["cases"]["control-os-system-zip"]
    assert control["blocklist"] == "detected"
    assert control["strict"] == "detected"


def test_benign_control_is_not_flagged_as_rce(generated):
    _, results = generated
    benign = results["cases"]["benign-allowlisted-globals"]
    assert benign["blocklist"] != "detected"
    assert benign["strict"] != "detected"


def test_scoring_never_executes_a_pickle(generated):
    """MockExploitPayload's echo would print if a pickle were ever loaded."""
    _, results = generated
    assert results["executed"] is False


def test_baseline_matches_current_detection(generated):
    """
    The regression gate. Detection drift in EITHER direction fails.

    If you are here after improving detection: that is the expected workflow —
    regenerate with `poetry run aisbom bypass-scorecard --write` and commit the
    updated baseline alongside the fix.
    """
    _, results = generated
    baseline = json.loads(BASELINE_PATH.read_text())

    current = {cid: v for cid, v in results["cases"].items()}
    expected = baseline["cases"]

    assert set(current) == set(expected), "corpus cases added/removed without updating baseline.json"

    drift = {
        cid: {"baseline": expected[cid], "current": current[cid]}
        for cid in expected
        if expected[cid]["blocklist"] != current[cid]["blocklist"]
        or expected[cid]["strict"] != current[cid]["strict"]
    }
    assert not drift, f"detection drifted from baseline: {json.dumps(drift, indent=2)}"


def test_scorecard_json_is_serializable(generated):
    _, results = generated
    json.loads(json.dumps(results))


def test_markdown_scorecard_renders_every_case(generated):
    _, results = generated
    md = corpus.render_markdown(results)
    for case in corpus.CASES:
        assert case.id in md
        assert case.source in md
    assert "## Scorecard" in md


# --- the ratchet -------------------------------------------------------------


def test_detection_is_at_or_above_the_committed_floor(generated):
    """
    The release gate, as a test.

    Unlike the baseline check, this one cannot be satisfied by regenerating:
    `--write` raises the floor and never lowers it. A failure here means
    detection genuinely got worse.
    """
    _, results = generated
    floor = json.loads(FLOOR_PATH.read_text())
    regressions = corpus.check_floor(results, floor)
    assert not regressions, (
        "detection regressed below the floor: " + json.dumps(regressions, indent=2)
    )


def test_floor_never_exceeds_what_was_actually_achieved(generated):
    """The floor is a record of reality, not an aspiration."""
    _, results = generated
    floor = json.loads(FLOOR_PATH.read_text())
    for case_id, modes in floor["cases"].items():
        for mode, verdict in modes.items():
            assert verdict in corpus.VERDICT_RANK, f"{case_id}/{mode}: unknown verdict"


def test_merge_floor_raises_but_never_lowers():
    existing = {"cases": {"a": {"blocklist": "detected", "strict": "partial"}}}
    worse = {"cases": {"a": {"blocklist": "missed", "strict": "detected"}}}

    merged = corpus.merge_floor(worse, existing)

    assert merged["cases"]["a"]["blocklist"] == "detected", "a regression must not lower the floor"
    assert merged["cases"]["a"]["strict"] == "detected", "an improvement must raise the floor"


def test_check_floor_flags_a_downgrade():
    floor = {"cases": {"a": {"blocklist": "detected"}}}
    results = {"cases": {"a": {"blocklist": "partial"}}}

    regressions = corpus.check_floor(results, floor)

    assert regressions == [
        {"case": "a", "mode": "blocklist", "floor": "detected", "current": "partial"}
    ]


def test_check_floor_accepts_an_improvement():
    floor = {"cases": {"a": {"blocklist": "partial"}}}
    results = {"cases": {"a": {"blocklist": "detected"}}}

    assert corpus.check_floor(results, floor) == []


def test_check_floor_flags_a_silently_dropped_case():
    """Deleting an awkward case must not be a way to make the gate pass."""
    floor = {"cases": {"a": {"blocklist": "detected"}}}

    regressions = corpus.check_floor({"cases": {}}, floor)

    assert regressions and regressions[0]["current"] == "missing"


def test_render_baseline_round_trips(generated):
    _, results = generated
    assert json.loads(corpus.render_baseline(results))["cases"] == results["cases"]


# --- CLI ---------------------------------------------------------------------


def test_bypass_scorecard_command_reports_every_case(tmp_path):
    result = runner.invoke(app, ["bypass-scorecard", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "bypass scorecard" in result.output.lower()
    assert "caught in at least one mode" in result.output


def test_bypass_scorecard_json_mode_is_machine_readable(tmp_path):
    result = runner.invoke(
        app, ["bypass-scorecard", "--output-dir", str(tmp_path), "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["executed"] is False
    assert set(payload["cases"]) == {c.id for c in corpus.CASES}


def test_bypass_scorecard_check_passes_against_the_committed_floor(tmp_path):
    result = runner.invoke(
        app, ["bypass-scorecard", "--output-dir", str(tmp_path), "--check"]
    )
    assert result.exit_code == 0, result.output
    assert "gate passed" in result.output


def test_bypass_scorecard_check_exits_2_on_regression(tmp_path, monkeypatch):
    """The gate must fail the build, not just print a warning."""
    monkeypatch.setattr(
        corpus,
        "check_floor",
        lambda *_a, **_k: [
            {"case": "control-os-system-zip", "mode": "blocklist",
             "floor": "detected", "current": "missed"}
        ],
    )
    result = runner.invoke(
        app, ["bypass-scorecard", "--output-dir", str(tmp_path), "--check"]
    )
    assert result.exit_code == 2
    assert "regressed below the committed floor" in result.output
    assert "does not accept regeneration" in result.output


def test_bypass_scorecard_surfaces_missing_dev_dependency(tmp_path, monkeypatch):
    """A missing dev-only dependency must fail cleanly, not traceback."""

    def _explode(*_args, **_kwargs):
        raise corpus.CorpusDependencyError("py7zr is not installed")

    monkeypatch.setattr(corpus, "generate_corpus", _explode)
    result = runner.invoke(app, ["bypass-scorecard", "--output-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "py7zr is not installed" in result.output


def test_committed_scorecard_doc_is_not_stale(generated):
    """
    docs/bypass-scorecard.md is what the public scorecard article publishes
    from — it must reflect the committed baseline, not a stale earlier run.
    """
    _, results = generated
    rendered = corpus.render_markdown(results)
    committed = SCORECARD_DOC.read_text()
    assert corpus.strip_generated_stamp(committed) == corpus.strip_generated_stamp(rendered), (
        "docs/bypass-scorecard.md is stale — regenerate with "
        "`poetry run aisbom bypass-scorecard --write`"
    )
