#!/usr/bin/env python3
"""
Phase 4.5 — Post or update an idempotent PR comment with AIsbom findings.

Runs inside the Action Docker container as the second step of entrypoint.sh
(after `aisbom scan ... --share --share-yes`). Reads the rendered SBOM and
the scan log, builds a markdown comment, and either creates a new comment or
updates the existing one identified by the hidden marker.

Telemetry is fire-and-forget against api.aisbom.io/v1/telemetry and honors
AISBOM_NO_TELEMETRY just like the CLI. Never raises from telemetry; never
fails the workflow over a comment-posting hiccup that wasn't actionable.

Design doc: cloudcowork/PHASE_4_5_DESIGN.md.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any

# Hidden marker on the comment's first line. Lets re-runs of the Action find
# the previous comment and update it in place instead of stacking new ones.
# Same pattern used by Dependabot, Renovate, Codecov, etc.
MARKER = "<!-- aisbom-action -->"

TELEMETRY_ENDPOINT = "https://api.aisbom.io/v1/telemetry"
TELEMETRY_TIMEOUT_SEC = 3.0
ACTION_USER_AGENT = "aisbom-action/1.0"

# Match the share URL anywhere in scan log. Tolerates Rich ANSI codes and any
# surrounding chrome the CLI may render around the URL.
SHARE_URL_RE = re.compile(r"https://aisbom\.io/viewer\?h=[A-Za-z0-9_-]+")

# Severity ordering (higher number = higher risk). Used for sorting + ranking.
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}

# Risk icons in the table. Mirrors what aisbom scan prints to the terminal.
RISK_ICON = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "CLEAN": "🟢",
}

# Description-string parser. AIsbom emits CycloneDX descriptions as
#   "Risk: CRITICAL (Legacy Binary) | Framework: PyTorch | Legal: UNKNOWN | License: MIT"
# Mirrors the parser pattern from aisbom-ops/scripts/audit_hf_top_50.py.
DESCRIPTION_FIELDS_RE = re.compile(
    r"Risk:\s*(?P<risk>[^|]+?)"
    r"(?:\s*\|\s*Framework:\s*(?P<framework>[^|]+?))?"
    r"(?:\s*\|\s*Legal:\s*(?P<legal>[^|]+?))?"
    r"(?:\s*\|\s*License:\s*(?P<license>[^|]+?))?"
    r"\s*$"
)


# ---------------------------------------------------------------------------
# Findings extraction (pure functions, unit-testable)
# ---------------------------------------------------------------------------

def collect_findings(sbom: dict) -> list[dict]:
    """Walk a CycloneDX SBOM and return one record per model-artifact component.

    Library dependencies (type=library) are skipped — the PR comment is about
    the ML artifacts being scanned. Each returned dict has: name, severity,
    framework, legal, license, issue (short string for the table).
    """
    findings: list[dict] = []
    for c in sbom.get("components", []):
        # Only ML model components — skip pip libraries.
        if c.get("type") != "machine-learning-model":
            continue
        desc = c.get("description", "") or ""
        match = DESCRIPTION_FIELDS_RE.search(desc)
        risk_raw = match.group("risk").strip() if match and match.group("risk") else "UNKNOWN"
        # Normalize "CRITICAL (Legacy Binary)" → severity=CRITICAL, issue=Legacy Binary.
        severity, issue = _split_risk_label(risk_raw)
        findings.append({
            "name": c.get("name", "?"),
            "severity": severity,
            "framework": (match.group("framework").strip() if match and match.group("framework") else "?"),
            "legal": (match.group("legal").strip() if match and match.group("legal") else "?"),
            "license": (match.group("license").strip() if match and match.group("license") else "Unknown"),
            "issue": issue,
        })
    # Sort highest risk first so the table reads top-down.
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], -1), reverse=True)
    return findings


def _split_risk_label(raw: str) -> tuple[str, str]:
    """`CRITICAL (Legacy Binary)` → (`CRITICAL`, `Legacy Binary`)."""
    raw = raw.strip()
    m = re.match(r"([A-Z]+)\s*(?:\((.+)\))?", raw)
    if not m:
        return ("UNKNOWN", raw)
    severity = m.group(1)
    issue = m.group(2) or ""
    return (severity, issue)


def max_severity(findings: list[dict]) -> str:
    """Return the highest severity label across findings, or 'CLEAN' if empty."""
    if not findings:
        return "CLEAN"
    top = max(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], -1))
    return top["severity"]


def count_by_severity(findings: list[dict], severity: str) -> int:
    return sum(1 for f in findings if f["severity"] == severity)


def parse_share_url(scan_log_text: str) -> str | None:
    """Extract the aisbom.io viewer share URL from captured scan stdout.

    Returns None if no URL was printed (e.g. --share wasn't passed, or upload
    failed). The Action wrapper falls back to the SBOM-artifact-only comment
    in that case.
    """
    m = SHARE_URL_RE.search(scan_log_text)
    return m.group(0) if m else None


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def render_body(
    findings: list[dict],
    share_url: str | None,
    max_rows: int,
    target_directory: str,
    total_components: int,
) -> str:
    """Render the comment body. Always starts with MARKER on its own line.

    Thresholding rule: the alarming "Findings" table only appears when at
    least one finding is CRITICAL or HIGH. MEDIUM/LOW-only scans collapse
    to the green-checkmark "no CRITICAL or HIGH risks" view — bias for
    action over noise. The full severity distribution is still in the
    SBOM artifact for anyone who wants the long tail.
    """
    severity = max_severity(findings)
    if severity not in ("CRITICAL", "HIGH"):
        return _render_clean(share_url, target_directory, total_components)

    return _render_findings(
        findings=findings,
        share_url=share_url,
        max_rows=max_rows,
        target_directory=target_directory,
        total_components=total_components,
    )


def _render_clean(share_url: str | None, target_directory: str, total_components: int) -> str:
    lines = [
        MARKER,
        "## 🛡️ AIsbom Security Scan",
        "",
        f"✅ No CRITICAL or HIGH risks found in {total_components} scanned artifact(s).",
        "",
    ]
    if share_url:
        lines.append(f"[View full SBOM in viewer →]({share_url}&ref=action)")
        lines.append("")
    lines.append(
        f"<sub>📦 Generated by [AIsbom](https://aisbom.io/?ref=action) · "
        f"scanned `{target_directory}` · {total_components} artifact(s) total</sub>"
    )
    return "\n".join(lines)


def _render_findings(
    *,
    findings: list[dict],
    share_url: str | None,
    max_rows: int,
    target_directory: str,
    total_components: int,
) -> str:
    severity = max_severity(findings)
    n_crit = count_by_severity(findings, "CRITICAL")
    n_high = count_by_severity(findings, "HIGH")
    n_med = count_by_severity(findings, "MEDIUM")
    n_low = count_by_severity(findings, "LOW")

    summary_bits = []
    if n_crit:
        summary_bits.append(f"{n_crit} CRITICAL")
    if n_high:
        summary_bits.append(f"{n_high} HIGH")
    if n_med:
        summary_bits.append(f"{n_med} MEDIUM")
    if n_low:
        summary_bits.append(f"{n_low} LOW")
    summary = ", ".join(summary_bits) if summary_bits else "no severity-tagged findings"

    lines = [
        MARKER,
        "## 🛡️ AIsbom Security Scan",
        "",
        f"**Summary:** {summary} across {len(findings)} model artifact(s).",
        "",
        "### Findings",
        "",
        "| Risk | Artifact | Format | License | Issue |",
        "|------|----------|--------|---------|-------|",
    ]

    visible = findings[:max_rows]
    for f in visible:
        icon = RISK_ICON.get(f["severity"], "⚪")
        issue = f["issue"] or f["legal"] or ""
        lines.append(
            f"| {icon} {f['severity']} | `{f['name']}` | {f['framework']} | "
            f"{f['license']} | {issue} |"
        )

    hidden = len(findings) - len(visible)
    if hidden > 0:
        lines.append(f"| … | _+ {hidden} more findings — see full SBOM_ | | | |")

    lines.append("")
    if share_url:
        lines.append(f"[View full SBOM in viewer →]({share_url}&ref=action)")
        lines.append("")
    lines.append(
        f"<sub>📦 Generated by [AIsbom](https://aisbom.io/?ref=action) · "
        f"scanned `{target_directory}` · {total_components} artifact(s) total</sub>"
    )

    body = "\n".join(lines)
    # Guard against GitHub's 65,536 char comment cap.
    if len(body) > 65000:
        body = body[:65000] + "\n\n_…comment truncated; see full SBOM via the viewer link above._"
    return body


# ---------------------------------------------------------------------------
# GitHub comment posting (idempotent via marker)
# ---------------------------------------------------------------------------

def post_or_update_comment(body: str, token: str, repo: str, pr_number: int) -> str:
    """Find-or-create the comment. Returns 'created' or 'updated'.

    Uses PyGithub. Note: PullRequest.edit() doesn't trigger a notification
    on subsequent updates — exactly what we want for re-runs (the PR author
    gets notified once, then silent updates after).
    """
    from github import Github  # imported lazily so unit tests don't need PyGithub

    gh = Github(token)
    repo_obj = gh.get_repo(repo)
    pr = repo_obj.get_pull(pr_number)
    for c in pr.get_issue_comments():
        if c.body and c.body.startswith(MARKER):
            c.edit(body)
            return "updated"
    pr.create_issue_comment(body)
    return "created"


# ---------------------------------------------------------------------------
# Telemetry — fire-and-forget, never raises
# ---------------------------------------------------------------------------

def emit_telemetry(event: str, params: dict[str, str]) -> None:
    """POST a single event to api.aisbom.io. Silent on any failure.

    Honors AISBOM_NO_TELEMETRY (same lever as CLI/edge). Sends from the
    container, so it counts as `is_ci=true` automatically via GITHUB_ACTIONS
    on the Worker UA detection — no special tagging needed here.
    """
    if os.environ.get("AISBOM_NO_TELEMETRY"):
        return
    try:
        req = urllib.request.Request(
            TELEMETRY_ENDPOINT,
            data=json.dumps({"event": event, "params": params}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": ACTION_USER_AGENT,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TELEMETRY_TIMEOUT_SEC) as _resp:
            pass
    except (urllib.error.URLError, OSError, ValueError):
        # Never raise from telemetry. CI flakiness mustn't fail the workflow.
        return


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sbom", required=True, help="Path to the SBOM JSON file")
    p.add_argument("--scan-log", required=True, help="Path to captured scan stdout")
    p.add_argument("--max-rows", type=int, default=10)
    p.add_argument("--comment-on-clean", default="true",
                   help='"true" or "false" — post a comment when no findings')
    p.add_argument("--directory", default=".",
                   help="The scanned directory (shown in the comment footer)")
    return p.parse_args(argv)


def _resolve_pr_number_from_event() -> int | None:
    """GitHub passes the event payload via GITHUB_EVENT_PATH."""
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        return None
    try:
        with open(path) as fh:
            event = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    pr = event.get("pull_request") or {}
    n = pr.get("number")
    if isinstance(n, int):
        return n
    # Fallback for `issue_comment` events on PRs.
    issue = event.get("issue") or {}
    if isinstance(issue.get("pull_request"), dict):
        n = issue.get("number")
        if isinstance(n, int):
            return n
    return None


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # Load SBOM. Fail loud — entrypoint.sh shouldn't have called us if scan
    # didn't produce an SBOM, so a missing file is a genuine bug.
    with open(args.sbom) as fh:
        sbom = json.load(fh)
    findings = collect_findings(sbom)
    total_components = len(sbom.get("components", []))

    # Parse share URL from scan log (best-effort; missing = no link in comment).
    try:
        with open(args.scan_log) as fh:
            scan_log = fh.read()
    except OSError:
        scan_log = ""
    share_url = parse_share_url(scan_log)

    severity = max_severity(findings)
    is_clean = severity == "CLEAN"

    # Skip comment if user opted out of clean comments.
    if is_clean and args.comment_on_clean.lower() == "false":
        emit_telemetry("github_action_run", {
            "risk_level_max": "CLEAN",
            "is_clean": "true",
            "comment_created_or_updated": "skipped_clean",
        })
        print("[aisbom-action] Clean scan, comment skipped per comment-on-clean=false.")
        return 0

    # Resolve PR context. If we're not in a PR (push, schedule, etc.), do not
    # try to comment — still emit telemetry so the dashboards aren't blind.
    pr_number = _resolve_pr_number_from_event()
    token = os.environ.get("INPUT_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not (pr_number and token and repo):
        emit_telemetry("github_action_run", {
            "risk_level_max": severity,
            "findings_critical": str(count_by_severity(findings, "CRITICAL")),
            "findings_high": str(count_by_severity(findings, "HIGH")),
            "is_clean": "true" if is_clean else "false",
            "comment_created_or_updated": "no_pr_context",
        })
        print("[aisbom-action] Not in a PR context (or missing token/repo); "
              "SBOM artifact still produced, but no comment posted.")
        return 0

    body = render_body(
        findings=findings,
        share_url=share_url,
        max_rows=args.max_rows,
        target_directory=args.directory,
        total_components=total_components,
    )

    try:
        action_taken = post_or_update_comment(body, token, repo, pr_number)
    except Exception as e:  # PyGithub permission errors, network, etc.
        # Don't fail the user's CI over a permissions setup issue —
        # they'll see the error in the Actions log.
        emit_telemetry("github_action_run", {
            "risk_level_max": severity,
            "findings_critical": str(count_by_severity(findings, "CRITICAL")),
            "findings_high": str(count_by_severity(findings, "HIGH")),
            "is_clean": "true" if is_clean else "false",
            "comment_created_or_updated": "permission_denied",
            "error_type": type(e).__name__,
        })
        print(f"[aisbom-action] Could not post PR comment ({type(e).__name__}: {e}). "
              "Check the workflow has `pull-requests: write` permission. "
              "SBOM artifact was still produced. Continuing without failing the job.")
        return 0

    emit_telemetry("github_action_run", {
        "risk_level_max": severity,
        "findings_critical": str(count_by_severity(findings, "CRITICAL")),
        "findings_high": str(count_by_severity(findings, "HIGH")),
        "is_clean": "true" if is_clean else "false",
        "comment_created_or_updated": action_taken,
    })
    emit_telemetry("github_action_comment_posted", {
        "comment_action": action_taken,
        "risk_level_max": severity,
    })

    print(f"[aisbom-action] PR comment {action_taken}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
