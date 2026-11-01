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
    --exclude-module=brotli \
    --exclude-module=_brotli \
    --exclude-module=brotlicffi \
    run_aisbom.py

# Keep brotli out of the binary. It arrives only through py7zr (used to build
# the 7z case of `bypass-scorecard`, which works fine without brotli), but
# urllib3 turns on brotli response decoding whenever brotli is importable. So
# bundling it would put a native decoder on the path of every remote scan for
# no benefit to users. Fail the build if it ever comes back.
FORBIDDEN='(^|[^A-Za-z0-9_])(_?brotli|brotlicffi)([^A-Za-z0-9_]|$)'
if poetry run pyi-archive_viewer --recursive --brief dist/aisbom | grep -E "$FORBIDDEN"; then
    echo "FAIL: brotli (listed above) was bundled into dist/aisbom" >&2
    exit 1
fi
echo "OK: brotli not bundled"

echo "Build complete. Binary is at dist/aisbom"
ls -lh dist/aisbom
