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
#   $7  token                (optional — opt-in for platform upload)
#   $8  platform-url         (optional override; blank → default in helper)
#   $9  fail-on-platform-error  (default "false")
#   $10 share                (default "false" — opt-in hosted share link)
#   $11 fail-on-scan-error   (default "false" — becomes "true" at the next
#                              major release)
#
# Bash (not POSIX sh) is required for the PIPESTATUS array — we need the
# scan's exit code, not tee's, to honor fail-on-risk correctly.
#
# Exit codes:
#   0 — Scan succeeded, OR scan reported risks but fail-on-risk is false, OR
#       the scan errored but fail-on-scan-error is false (a warning
#       annotation is emitted instead).
#   1 — share: true was combined with AISBOM_OFFLINE (refused before
#       scanning), OR the scan exited with anything other than 0 or 2 AND
#       fail-on-scan-error is true.
#   2 — Scan reported CRITICAL findings AND fail-on-risk is true.
#   3 — Platform upload failed AND fail-on-platform-error is true.
#
# Precedence when several apply: 2, then 1, then 3. A dangerous model is the
# signal the user's required check should report first; a scan that could not
# read everything comes next; a failed upload is plumbing. The upload is
# attempted before every gate, so a CRITICAL repo still reaches the dashboard.
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
INPUT_TOKEN="${7:-}"
INPUT_PLATFORM_URL="${8:-}"
INPUT_FAIL_ON_PLATFORM_ERROR="${9:-false}"
INPUT_SHARE="${10:-false}"
INPUT_FAIL_ON_SCAN_ERROR="${11:-false}"

# Pass the token through to post_comment.py via a clean underscore-only env
# var. We never echo $GH_TOKEN — GitHub already masks it in the docker-run
# command log, but using a properly-named env var keeps secret hygiene easy.
export AISBOM_GITHUB_TOKEN="${GH_TOKEN}"

# Overridable so the regression suite can run this script without racing on a
# fixed /tmp path. Unset in the Docker image, which is the only place it runs
# for real.
SCAN_LOG="${AISBOM_SCAN_LOG:-/tmp/aisbom-scan.log}"

# Step 1 — Run the scan. Sharing is OPT-IN: `--share --share-yes` uploads the
# SBOM to aisbom.io and mints a publicly-readable 30-day viewer link, so it is
# only passed when the user explicitly sets `share: true`. Everything else the
# Action does — the SBOM artifact, the PR comment, fail-on-risk, the platform
# upload — renders from the local SBOM and works identically with sharing off.
# VEX is generated only when a platform token is set, i.e. when there is a
# hosted inventory to send it to. Exploitability statements are what the CRA
# and FDA §524B ask for most directly, and without them the inventory can show
# what a repo contains but never whether a finding is actually exploitable.
# Tying generation to the opt-in keeps the default run byte-identical: a user
# who has not connected a repo gets no extra files in their workspace and no
# extra work in their scan.
VEX_ARGS=()
if [ -n "${INPUT_TOKEN}" ]; then
    VEX_ARGS=(--vex)
fi

# `AISBOM_OFFLINE=1` in the step env forbids network access and `share: true`
# requires it, so the CLI refuses the pair with exit 1. That is a
# configuration mistake rather than a scan error, so it fails the job whatever
# `fail-on-scan-error` says, and before any scan runs.
if [ -n "${AISBOM_OFFLINE:-}" ] && [ "${INPUT_SHARE}" = "true" ]; then
    echo "[aisbom-action] share: true cannot be combined with AISBOM_OFFLINE: sharing uploads the SBOM to aisbom.io. Remove one of them."
    exit 1
fi

SHARE_ARGS=()
if [ "${INPUT_SHARE}" = "true" ]; then
    SHARE_ARGS=(--share --share-yes)
else
    # Deliberately scoped to the SBOM. Anonymous telemetry is default-on and
    # goes to api.aisbom.io, so a blanket "nothing is sent" would be false —
    # the exact kind of overclaim this input exists to correct.
    echo "[aisbom-action] Sharing is off (share: false, the default): the SBOM is not uploaded to aisbom.io and the share-url output will be empty. Set share: true to publish a hosted viewer link. (Anonymous telemetry is separate and still on; set AISBOM_NO_TELEMETRY=1 to disable it.)"
fi

# Remove this run's output paths before scanning. The comment and the upload
# below both key off "does the output file exist", so a file left by a
# previous step or committed to the repo would otherwise be commented on and
# uploaded as this run's result whenever the scan fails before writing. The
# VEX siblings go too, or stale exploitability statements could ride along
# with a fresh SBOM. Only the paths the scan itself writes are touched; the
# naming mirrors `vex_paths_for` in platform_upload.py.
OUTPUT_STEM="${OUTPUT_FILE%.json}"
rm -f -- "${OUTPUT_FILE}" "${OUTPUT_STEM}.openvex.json" "${OUTPUT_STEM}.vex.cdx.json"

echo "::group::aisbom scan output"
set -o pipefail
# `${SHARE_ARGS[@]+"${SHARE_ARGS[@]}"}` — expanding an empty array under
# `set -u` is an unbound-variable error on bash < 4.4; this form yields no
# words at all when the array is empty.
aisbom scan "${DIRECTORY}" \
  --output "${OUTPUT_FILE}" \
  ${VEX_ARGS[@]+"${VEX_ARGS[@]}"} \
  ${SHARE_ARGS[@]+"${SHARE_ARGS[@]}"} \
  2>&1 | tee "${SCAN_LOG}"
SCAN_EXIT=${PIPESTATUS[0]}
set +o pipefail
echo "::endgroup::"

# Echo Action outputs so consumers can reference them in subsequent steps.
# `share-url` is always written — empty when sharing is off — so consumers read
# an empty string rather than an unset output.
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "sbom-path=${OUTPUT_FILE}" >> "${GITHUB_OUTPUT}"
    SHARE_URL=""
    if [ "${INPUT_SHARE}" = "true" ]; then
        SHARE_URL=$(grep -oE 'https://aisbom\.io/viewer\?h=[A-Za-z0-9_-]+' "${SCAN_LOG}" | head -n1 || true)
    fi
    echo "share-url=${SHARE_URL}" >> "${GITHUB_OUTPUT}"
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
      --share-enabled "${INPUT_SHARE}" \
      || echo "[aisbom-action] post_comment.py errored; SBOM artifact still produced."
else
    echo "[aisbom-action] No SBOM file at ${OUTPUT_FILE}; skipping PR comment."
fi

# Step 3 — Optional platform upload. Silent skip when no token,
# preserving CLI-only behavior for the broad user base. Opted-in users see
# the loud log group emitted by platform_upload.py.
#
# This runs BEFORE the fail-on-risk gate below, and the order is load-bearing.
# `aisbom scan` exits 2 on a CRITICAL finding but still writes its SBOM and VEX
# documents; when the gate came first, a repo containing a genuinely dangerous
# artifact exited here and never uploaded — so the hosted inventory silently
# omitted exactly the repos that most needed to be in it, and the `affected`
# VEX statements (which only exist when there IS a critical finding) could
# never arrive. Uploading first costs nothing: the job's exit status is decided
# below either way.
PLATFORM_EXIT=0
if [ -n "${INPUT_TOKEN}" ] && [ -f "${OUTPUT_FILE}" ]; then
    FAIL_FLAG=""
    if [ "${INPUT_FAIL_ON_PLATFORM_ERROR}" = "true" ]; then
        FAIL_FLAG="--fail-on-error"
    fi
    # Use `--key=value` form (not space-separated) so argparse never confuses
    # a value that starts with `-` for another option flag. Platform-issued
    # tokens are base64url and ~1.5% of them legitimately start with `-`.
    python /aisbom-action/platform_upload.py \
      --sbom="${OUTPUT_FILE}" \
      --token="${INPUT_TOKEN}" \
      --platform-url="${INPUT_PLATFORM_URL}" \
      --trigger="${GITHUB_EVENT_NAME:-unknown}" \
      ${FAIL_FLAG} || PLATFORM_EXIT=$?
fi

if [ "${PLATFORM_EXIT}" -ne 0 ] && [ "${INPUT_FAIL_ON_PLATFORM_ERROR}" != "true" ]; then
    echo "[aisbom-action] Platform upload exited ${PLATFORM_EXIT}; tolerated (fail-on-platform-error=false)."
fi

# Step 4 — Honor fail-on-risk: re-raise the CLI's exit code so the user's
# branch protection rules and required-checks gates behave correctly.
#
# Deliberately ahead of the platform-error exit below: when a scan finds a
# CRITICAL artifact AND the upload failed, exit 2 is the more useful signal.
# The required check should report the dangerous model, not the plumbing.
if [ "${FAIL_ON_RISK}" = "true" ] && [ "${SCAN_EXIT}" -eq 2 ]; then
    echo "[aisbom-action] CRITICAL risks detected; failing the job (fail-on-risk=true)."
    exit 2
fi

# Step 5 — Scan errors. `aisbom scan` exits 1 when it could not do the whole
# job: a directory that doesn't exist, a file it couldn't parse, an unreadable
# model file such as a git-LFS pointer stub from a checkout without
# `git lfs pull`. Any exit other than 0 and 2 (a crash, a missing binary) is
# treated the same way. These used to end the job green with nothing said.
#
# Opt-in for now so no existing job changes result on a minor release; the
# default becomes "true" at the next major. Until then the warning annotation
# makes the failure visible on the run summary instead of silent.
if [ "${SCAN_EXIT}" -ne 0 ] && [ "${SCAN_EXIT}" -ne 2 ]; then
    if [ "${INPUT_FAIL_ON_SCAN_ERROR}" = "true" ]; then
        echo "::error title=aisbom scan error::aisbom scan exited ${SCAN_EXIT}: some files could not be scanned. See the scan output above. Failing the job (fail-on-scan-error=true)."
        exit 1
    fi
    echo "::warning title=aisbom scan error::aisbom scan exited ${SCAN_EXIT}: some files could not be scanned, so this run is not a clean result. See the scan output above. Set fail-on-scan-error: true to fail the job; it becomes the default in the next major release."
fi

# Honour fail-on-platform-error even when the helper exited before its own
# error-handling could fire (e.g. argparse usage error). Without this gate,
# the default `fail-on-platform-error: false` silently degraded into "fail
# the job on any helper crash", which contradicts the documented contract.
if [ "${PLATFORM_EXIT}" -ne 0 ] && [ "${INPUT_FAIL_ON_PLATFORM_ERROR}" = "true" ]; then
    exit "${PLATFORM_EXIT}"
fi

exit 0
