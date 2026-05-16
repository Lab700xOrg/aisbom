# LOCATION: ~/Projects/sbom/aisbom-cli/Dockerfile
#
# AIsbom GitHub Action image. Phase 4.5 expanded this from a bare CLI runner
# into a wrapper that also posts an idempotent PR comment with findings.
# See cloudcowork/PHASE_4_5_DESIGN.md for the architecture and rationale.

FROM python:3.11-slim

# Metadata for GitHub Marketplace
LABEL "com.github.actions.name"="AIsbom Security Scanner"
LABEL "com.github.actions.description"="Deep binary introspection for AI/ML models — pickle bombs, license risk, silent drift. Posts a PR comment with findings."
LABEL "com.github.actions.icon"="shield"
LABEL "com.github.actions.color"="purple"

# git is occasionally needed by pip / pre-built wheel resolution; keep the
# image lean by removing the apt lists after install.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Pin PyGithub at build time so consumers don't get surprised by upstream
# breaking changes when GitHub rebuilds the image for floating tag `@v1`.
RUN pip install --no-cache-dir aisbom-cli "PyGithub>=2.5,<3"

# Copy the Action wrapper (entrypoint + comment renderer). Kept separate
# from the aisbom Python package so we can iterate on PR-comment logic
# without cutting a new aisbom-cli release.
COPY action/ /aisbom-action/
RUN chmod +x /aisbom-action/entrypoint.sh

ENTRYPOINT ["/aisbom-action/entrypoint.sh"]
