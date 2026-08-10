#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLKIT_DIR="${SECURITY_TOOLKIT_HOME:-$HOME/security-toolkit}"
DESTINATION="$TOOLKIT_DIR/orchestrator"

mkdir -p "$DESTINATION"
cp "$SOURCE_ROOT"/orchestrator/*.js "$DESTINATION"/
chmod u+x "$DESTINATION/cli.js"
echo "Installed Vibe Code Guard orchestration modules to $DESTINATION"
