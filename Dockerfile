# LOCATION: ~/Projects/sbom/aisbom-cli/Dockerfile

# Use a slim Python image to keep the download fast (Debian-based)
FROM python:3.11-slim

# Metadata for GitHub Marketplace
LABEL "com.github.actions.name"="AIsbom Security Scanner"
LABEL "com.github.actions.description"="Deep binary introspection for AI/ML models to detect Pickle bombs and malware."
LABEL "com.github.actions.icon"="shield"
LABEL "com.github.actions.color"="purple"

# Install git (sometimes needed by pip or dependencies)
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Install your tool directly from PyPI.
# This ensures the Action runs the stable version you just published.
RUN pip install --no-cache-dir aisbom-cli

# Set the entrypoint. When GitHub runs this Action, 
# it executes: aisbom <arguments provided in action.yml>
ENTRYPOINT ["aisbom"]