#!/bin/bash
# Phase 4.5 — AIsbom GitHub Action entrypoint.
#
# Inputs arrive as positional args (action.yml `args:` block), not env vars.
# This sidesteps GitHub's hyphen-preserving env-var naming for Docker actions,
# which POSIX shells can't reliably read. Argv order matches action.yml:
#
#   $1  directory            (default ".")
#   $2  output-file          (default "sbom.json")
#   $3  github-token         (required for PR comment; auto-defaults to
#                              ${{ github.token }} on the GitHub side)
#   $4  max-rows             (default "10")
#   $5  comment-on-clean     (default "true")
#   $6  fail-on-risk         (default "true")
#
# Bash (not POSIX sh) is required for the PIPESTATUS array — we need the
# scan's exit code, not tee's, to honor fail-on-risk correctly.
#
# Exit codes:
#   0 — Scan succeeded OR scan reported risks but fail-on-risk is false.
#   2 — Scan reported CRITICAL findings AND fail-on-risk is true.
#
# Comment-posting failures NEVER fail the job (logged but tolerated so the
# user fixes their `permissions:` block, not the scan).

set -u

DIRECTORY="${1:-.}"
OUTPUT_FILE="${2:-sbom.json}"
GH_TOKEN="${3:-}"
MAX_ROWS="${4:-10}"
COMMENT_ON_CLEAN="${5:-true}"
FAIL_ON_RISK="${6:-true}"

# Pass the token through to post_comment.py via a clean underscore-only env
# var. We never echo $GH_TOKEN — GitHub already masks it in the docker-run
# command log, but using a properly-named env var keeps secret hygiene easy.
export AISBOM_GITHUB_TOKEN="${GH_TOKEN}"

SCAN_LOG="/tmp/aisbom-scan.log"

# Step 1 — Run the scan. `--share --share-yes` uploads the SBOM and emits
# a viewer URL we can grep out for the PR comment.
echo "::group::aisbom scan output"
set -o pipefail
aisbom scan "${DIRECTORY}" \
  --output "${OUTPUT_FILE}" \
  --share \
  --share-yes \
  2>&1 | tee "${SCAN_LOG}"
SCAN_EXIT=${PIPESTATUS[0]}
set +o pipefail
echo "::endgroup::"

# Echo Action outputs so consumers can reference them in subsequent steps.
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
