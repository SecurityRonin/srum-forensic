#!/usr/bin/env bash
# Ralph agent loop runner for srum-forensic (Rust workspace).
# Usage: bash scripts/ralph/runner.sh [--max-iterations N]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROMPT_FILE="$SCRIPT_DIR/prompt.md"
MAX_ITERATIONS="${1:-100}"

if [[ "${1:-}" == "--max-iterations" ]]; then
    MAX_ITERATIONS="$2"
fi

PROMPT=$(cat "$PROMPT_FILE")
RALPH_CMD="/ralph-loop:ralph-loop '$(printf '%s' "$PROMPT" | sed "s/'/'\\\\''/g")' --completion-promise 'FINISHED' --max-iterations $MAX_ITERATIONS"

echo "[ralph] Starting agent loop (max $MAX_ITERATIONS iterations)..."
echo "[ralph] Prompt: $PROMPT_FILE"
echo ""

claude --permission-mode bypassPermissions --verbose "$RALPH_CMD"
