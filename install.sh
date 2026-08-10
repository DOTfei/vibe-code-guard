#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${NODE:-node}" "$SOURCE_ROOT/bin/vibe-code-guard.js" install "$@"
