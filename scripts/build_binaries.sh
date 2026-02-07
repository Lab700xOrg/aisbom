#!/bin/bash
set -e

# Build the standalone binary for the current platform
echo "Building standalone binary for $(uname -s)..."

# Ensure output directory exists (PyInstaller creates dist/ by default but good to be explicit about cleanup if needed)
rm -rf dist/ build/

# Run PyInstaller
# --onefile: Create a single executable
# --name aisbom: Name the output binary 'aisbom' (or aisbom.exe on Windows)
# --clean: Clean PyInstaller cache
# --hidden-import: Explicitly import hidden dependencies
# --collect-all: Robustly collect all data/binaries for complex packages if needed (rich usually needs nothing, but just in case)
# but for now, simple hidden imports are usually enough.
# We need to make sure we import 'cyclonedx', 'rich', 'requests'.
# Also 'aisbom' package itself is the source.

poetry run pyinstaller \
    --onefile \
    --name aisbom \
    --clean \
    --hidden-import=cyclonedx \
    --collect-all=cyclonedx \
    --collect-all=license_expression \
    --collect-all=spdx_tools \
    --hidden-import=rich \
    --hidden-import=requests \
    run_aisbom.py

echo "Build complete. Binary is at dist/aisbom"
ls -lh dist/aisbom
