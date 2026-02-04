# Dependabot Merge Instructions

These steps must be followed for every Dependabot PR. Reviewers/editors can update this file; always consult it before merging.

## Authorization & Policy
- Do not auto-merge without verification.
- Review the PR scope before running the workflow.
- Maintain coverage ≥85%.

## Process (Automated Workflow)
We have established an agentic workflow to handle these PRs securely and consistently.

1) **Identify PR ID** (e.g., 5).
2) **Run Agent Workflow**:
   - Locate `.agent/workflows/process_dependabot_pr.md`.
   - Run the steps defined there, replacing `[PR_ID]` with the actual ID.
   - The workflow handles:
     - Fetching the PR branch.
     - Installing dependencies.
     - Generating test artifacts.
     - Running full verification suite (tests + smoke tests).
     - Merging and pushing to `main`.
     - Verifying remote CI status.
3) **Manual Fallback**:
   - If the agent is unavailable, follow the script inside the workflow file manually.

## Notes
- Avoid scanning `.venv` to reduce noise.
- Markdown report `aisbom-report.md` is ignored by git.
