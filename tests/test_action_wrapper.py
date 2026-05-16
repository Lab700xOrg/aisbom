"""
Unit tests for the Phase 4.5 GitHub Action wrapper (action/post_comment.py).

The wrapper is shipped only inside the Docker image — not the PyPI package —
so it lives outside the `aisbom` Python package. Tests import it via
`from action.post_comment import ...` (aisbom-cli root is on sys.path).

Three test classes match the three risk areas in PHASE_4_5_DESIGN.md §8.1:
  - TestMarkdownRendering   — comment body shape, severity counts, max-rows
                              truncation, empty-state copy.
  - TestShareURLParsing     — regex extracts the URL across rich/ANSI noise.
  - TestCommentIdempotency  — find-or-create with the marker; mock PyGithub.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Action wrapper lives in aisbom-cli/action/, not on the package path.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from action.post_comment import (  # noqa: E402
    MARKER,
    collect_findings,
    count_by_severity,
    max_severity,
    parse_share_url,
    post_or_update_comment,
    render_body,
    _split_risk_label,
)


# ---------------------------------------------------------------------------
# Helpers — synthetic CycloneDX SBOMs for the renderer
# ---------------------------------------------------------------------------

def _component(name: str, description: str) -> dict:
    return {
        "name": name,
        "type": "machine-learning-model",
        "description": description,
    }


def _library(name: str) -> dict:
    """A pip dependency component — must be ignored by collect_findings."""
    return {"name": name, "type": "library"}


SBOM_CLEAN = {"components": [
    _component("safe.safetensors", "Risk: LOW | Framework: SafeTensors | Legal: OK | License: MIT"),
]}

SBOM_CRITICAL = {"components": [
    _component("evil.pt", "Risk: CRITICAL (Pickle Bomb) | Framework: PyTorch | Legal: UNKNOWN | License: Unknown"),
    _component("ok.safetensors", "Risk: LOW | Framework: SafeTensors | Legal: OK | License: Apache-2.0"),
    _library("requests"),  # must be filtered out
]}

SBOM_MIXED = {"components": [
    _component("a.pt", "Risk: HIGH (Suspicious) | Framework: PyTorch | Legal: OK | License: MIT"),
    _component("b.pt", "Risk: CRITICAL (Pickle) | Framework: PyTorch | Legal: OK | License: MIT"),
    _component("c.safetensors", "Risk: MEDIUM | Framework: SafeTensors | Legal: OK | License: MIT"),
    _component("d.gguf", "Risk: LOW | Framework: GGUF | Legal: OK | License: MIT"),
]}


# ---------------------------------------------------------------------------
# Risk-label splitter
# ---------------------------------------------------------------------------

class TestSplitRiskLabel:
    def test_plain_severity(self):
        assert _split_risk_label("CRITICAL") == ("CRITICAL", "")

    def test_severity_with_parenthetical(self):
        assert _split_risk_label("CRITICAL (Legacy Binary)") == ("CRITICAL", "Legacy Binary")

    def test_lowercase_collapses_to_unknown(self):
        sev, _ = _split_risk_label("critical")
        assert sev == "UNKNOWN"


# ---------------------------------------------------------------------------
# Finding collection
# ---------------------------------------------------------------------------

class TestCollectFindings:
    def test_skips_library_components(self):
        findings = collect_findings(SBOM_CRITICAL)
        names = [f["name"] for f in findings]
        assert "requests" not in names
        assert "evil.pt" in names
        assert "ok.safetensors" in names

    def test_sorts_highest_severity_first(self):
        findings = collect_findings(SBOM_MIXED)
        severities = [f["severity"] for f in findings]
        assert severities == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def test_extracts_framework_legal_license(self):
        findings = collect_findings(SBOM_CRITICAL)
        evil = next(f for f in findings if f["name"] == "evil.pt")
        assert evil["framework"] == "PyTorch"
        assert evil["legal"] == "UNKNOWN"
        assert evil["license"] == "Unknown"
        assert evil["issue"] == "Pickle Bomb"

    def test_handles_missing_description_fields(self):
        sbom = {"components": [
            _component("partial.pt", "Risk: MEDIUM"),
        ]}
        findings = collect_findings(sbom)
        assert findings[0]["severity"] == "MEDIUM"
        assert findings[0]["framework"] == "?"

    def test_returns_empty_for_no_components(self):
        assert collect_findings({"components": []}) == []
        assert collect_findings({}) == []


# ---------------------------------------------------------------------------
# Severity rollups
# ---------------------------------------------------------------------------

class TestSeverityRollups:
    def test_max_severity_empty_is_clean(self):
        assert max_severity([]) == "CLEAN"

    def test_max_severity_picks_highest(self):
        findings = collect_findings(SBOM_MIXED)
        assert max_severity(findings) == "CRITICAL"

    def test_count_by_severity(self):
        findings = collect_findings(SBOM_MIXED)
        assert count_by_severity(findings, "CRITICAL") == 1
        assert count_by_severity(findings, "HIGH") == 1
        assert count_by_severity(findings, "MEDIUM") == 1
        assert count_by_severity(findings, "LOW") == 1
        assert count_by_severity(findings, "DOESNT_EXIST") == 0


# ---------------------------------------------------------------------------
# Markdown rendering — the most user-visible surface
# ---------------------------------------------------------------------------

class TestMarkdownRendering:
    def test_body_starts_with_marker(self):
        body = render_body(
            collect_findings(SBOM_MIXED),
            share_url=None,
            max_rows=10,
            target_directory="models/",
            total_components=4,
        )
        assert body.startswith(MARKER)
        # Marker must be on a line by itself so GitHub's renderer hides it.
        assert body.split("\n")[0] == MARKER

    def test_clean_body_skips_findings_table(self):
        body = render_body(
            collect_findings(SBOM_CLEAN),
            share_url=None,
            max_rows=10,
            target_directory="models/",
            total_components=1,
        )
        assert "No CRITICAL or HIGH risks" in body
        assert "| Risk |" not in body  # no findings table on clean output

    def test_findings_table_has_top_severity_first(self):
        body = render_body(
            collect_findings(SBOM_MIXED),
            share_url=None,
            max_rows=10,
            target_directory="models/",
            total_components=4,
        )
        # Find row positions — CRITICAL must precede HIGH must precede MEDIUM.
        crit_idx = body.find("CRITICAL")
        high_idx = body.find("HIGH")
        med_idx = body.find("MEDIUM")
        assert 0 < crit_idx < high_idx < med_idx

    def test_max_rows_truncates_long_lists(self):
        many = {"components": [
            _component(f"f{i}.pt", "Risk: HIGH | Framework: PyTorch | Legal: OK | License: MIT")
            for i in range(15)
        ]}
        body = render_body(
            collect_findings(many),
            share_url=None,
            max_rows=3,
            target_directory="models/",
            total_components=15,
        )
        # 3 visible rows + the overflow line.
        assert "+ 12 more findings" in body

    def test_share_url_embeds_with_ref_action(self):
        body = render_body(
            collect_findings(SBOM_CRITICAL),
            share_url="https://aisbom.io/viewer?h=Kx9pQ2v3mLnB",
            max_rows=10,
            target_directory="models/",
            total_components=2,
        )
        # Attribution tag is the wrapper's job (not _attribution_ref's, since
        # the wrapper is GitHub-specific). The Action always uses ref=action.
        assert "https://aisbom.io/viewer?h=Kx9pQ2v3mLnB&ref=action" in body

    def test_summary_counts_match_findings(self):
        body = render_body(
            collect_findings(SBOM_MIXED),
            share_url=None,
            max_rows=10,
            target_directory="models/",
            total_components=4,
        )
        assert "1 CRITICAL" in body
        assert "1 HIGH" in body
        assert "1 MEDIUM" in body
        assert "1 LOW" in body

    def test_footer_mentions_aisbom_with_ref_action(self):
        body = render_body(
            collect_findings(SBOM_CLEAN),
            share_url=None,
            max_rows=10,
            target_directory="models/",
            total_components=1,
        )
        assert "https://aisbom.io/?ref=action" in body


# ---------------------------------------------------------------------------
# Share URL parsing
# ---------------------------------------------------------------------------

class TestShareURLParsing:
    def test_extracts_plain_url(self):
        log = "Share Link Created: https://aisbom.io/viewer?h=Kx9pQ2v3mLnB"
        assert parse_share_url(log) == "https://aisbom.io/viewer?h=Kx9pQ2v3mLnB"

    def test_extracts_url_from_rich_output(self):
        # Rich emits ANSI codes when stdout is a TTY-ish target; we tee the
        # raw output so escape codes may surround the URL.
        log = (
            "\x1b[1;32m✔ Share Link Created:\x1b[0m "
            "\x1b[4;36mhttps://aisbom.io/viewer?h=abcDEF123_-x\x1b[0m\n"
        )
        assert parse_share_url(log) == "https://aisbom.io/viewer?h=abcDEF123_-x"

    def test_returns_none_when_share_was_skipped(self):
        log = "scan finished; no --share flag passed.\n"
        assert parse_share_url(log) is None

    def test_returns_first_url_when_log_contains_multiple(self):
        log = (
            "first: https://aisbom.io/viewer?h=AAAAAAAAAAAA\n"
            "second: https://aisbom.io/viewer?h=BBBBBBBBBBBB\n"
        )
        # First match wins; the Action only ever uploads one SBOM per run.
        assert parse_share_url(log) == "https://aisbom.io/viewer?h=AAAAAAAAAAAA"


# ---------------------------------------------------------------------------
# Comment idempotency — mock the github API
# ---------------------------------------------------------------------------

class TestCommentIdempotency:
    """Verifies the find-or-create logic in post_or_update_comment.

    PyGithub isn't available in CI by default, so each test patches
    `from github import Github` at the function level via `sys.modules`.
    """

    def _patched_github(self, comment_bodies: list[str]):
        """Stand up a mock github.Github tree that returns the given comments."""
        comments = []
        for body in comment_bodies:
            c = MagicMock()
            c.body = body
            comments.append(c)

        pr = MagicMock()
        pr.get_issue_comments.return_value = comments
        repo = MagicMock()
        repo.get_pull.return_value = pr
        gh = MagicMock()
        gh.get_repo.return_value = repo

        github_module = MagicMock()
        github_module.Github.return_value = gh
        return github_module, gh, repo, pr, comments

    def test_creates_when_no_existing_comment(self):
        github_module, gh, repo, pr, comments = self._patched_github([])
        with patch.dict(sys.modules, {"github": github_module}):
            action = post_or_update_comment("BODY", "token", "owner/repo", 42)
        assert action == "created"
        pr.create_issue_comment.assert_called_once_with("BODY")

    def test_updates_when_marker_comment_exists(self):
        github_module, gh, repo, pr, comments = self._patched_github([
            "unrelated comment",
            f"{MARKER}\n## previous run",
            "another unrelated",
        ])
        with patch.dict(sys.modules, {"github": github_module}):
            action = post_or_update_comment("NEW BODY", "token", "owner/repo", 42)
        assert action == "updated"
        # The marker-bearing comment must be the one edited.
        comments[1].edit.assert_called_once_with("NEW BODY")
        pr.create_issue_comment.assert_not_called()

    def test_does_not_hijack_unrelated_marker_lookalikes(self):
        """A comment containing the marker mid-body must NOT be claimed."""
        github_module, gh, repo, pr, comments = self._patched_github([
            f"FYI we use {MARKER} elsewhere",  # marker NOT at start of body
        ])
        with patch.dict(sys.modules, {"github": github_module}):
            action = post_or_update_comment("BODY", "token", "owner/repo", 42)
        assert action == "created"
        pr.create_issue_comment.assert_called_once()
        comments[0].edit.assert_not_called()
