#!/bin/sh
# Phase 4.5 — AIsbom GitHub Action entrypoint.
#
# Orchestrates:
#   1. `aisbom scan` against the consumer's chosen directory, with --share
#      so we get a hosted viewer URL in the same step.
#   2. `post_comment.py` to render + post the PR comment idempotently.
#
# Inputs arrive as INPUT_* env vars per the action.yml inputs block.
# GITHUB_OUTPUT, GITHUB_EVENT_PATH, GITHUB_REPOSITORY are provided by the
# runner.
#
# Exit codes:
#   0 — Scan succeeded OR scan reported risks but fail-on-risk is false.
#   2 — Scan reported CRITICAL findings AND fail-on-risk is true (matches CLI).
#
# Comment-posting failures NEVER fail the job (they're surfaced as log
# messages so the user fixes their `permissions:` block, not the scan).

set -u

DIRECTORY="${INPUT_DIRECTORY:-.}"
OUTPUT_FILE="${INPUT_OUTPUT_FILE:-sbom.json}"
MAX_ROWS="${INPUT_MAX_ROWS:-10}"
COMMENT_ON_CLEAN="${INPUT_COMMENT_ON_CLEAN:-true}"
FAIL_ON_RISK="${INPUT_FAIL_ON_RISK:-true}"
SCAN_LOG="/tmp/aisbom-scan.log"

# Step 1 — Run the scan.
# `--share --share-yes` uploads the SBOM to aisbom.io and prints a viewer
# URL we can embed in the PR comment. Skipping the confirmation prompt is
# safe here because this is a CI context (the prompt would deadlock anyway).
# Tee stdout to both the runner's log and a file we can grep for the URL.
echo "::group::aisbom scan output"
aisbom scan "${DIRECTORY}" \
  --output "${OUTPUT_FILE}" \
  --share \
  --share-yes \
  2>&1 | tee "${SCAN_LOG}"
SCAN_EXIT=${PIPESTATUS:-$?}
echo "::endgroup::"

# Echo Action outputs that consumers can reference in subsequent steps.
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "sbom-path=${OUTPUT_FILE}" >> "${GITHUB_OUTPUT}"
    SHARE_URL=$(grep -oE 'https://aisbom\.io/viewer\?h=[A-Za-z0-9_-]+' "${SCAN_LOG}" | head -n1 || true)
    if [ -n "${SHARE_URL}" ]; then
        echo "share-url=${SHARE_URL}" >> "${GITHUB_OUTPUT}"
    fi
fi

# Step 2 — Post the PR comment. Only run if the scan actually produced
# an SBOM (so we don't try to render from a missing file on hard failures).
if [ -f "${OUTPUT_FILE}" ]; then
    python /aisbom-action/post_comment.py \
      --sbom "${OUTPUT_FILE}" \
      --scan-log "${SCAN_LOG}" \
      --max-rows "${MAX_ROWS}" \
      --comment-on-clean "${COMMENT_ON_CLEAN}" \
      --directory "${DIRECTORY}" \
      || echo "[aisbom-action] post_comment.py errored; SBOM artifact still produced."
else
    echo "[aisbom-action] No SBOM file at ${OUTPUT_FILE}; skipping PR comment."
fi

# Step 3 — Honor fail-on-risk: re-raise the CLI's exit code so the user's
# branch protection rules and required-checks gates behave correctly.
if [ "${FAIL_ON_RISK}" = "true" ] && [ "${SCAN_EXIT}" -eq 2 ]; then
    echo "[aisbom-action] CRITICAL risks detected; failing the job (fail-on-risk=true)."
    exit 2
fi

exit 0
