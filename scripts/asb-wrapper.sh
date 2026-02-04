#!/bin/bash
# Wrapper script for running commands inside 'amazing-sandbox' via uvx
# Usage: ./scripts/asb-wrapper.sh <command> [args...]

if [ -z "$1" ]; then
    echo "Usage: $0 <command> [args...]"
    echo "Example: $0 python scripts/safe_loader.py"
    exit 1
fi

# Use 'exec' to replace the shell process with uvx, passing all arguments along
echo "📦 Entering Sandbox..."
exec uvx --from amazing-sandbox asb run -- "$@"
