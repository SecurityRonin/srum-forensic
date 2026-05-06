#!/usr/bin/env bash
# Run this script once after cloning to enable the repo's git hooks:
#
#   bash .githooks/install.sh
#
# This sets core.hooksPath to .githooks so Git uses the hooks in this
# repository instead of the default .git/hooks directory.

set -euo pipefail

git config core.hooksPath .githooks
echo "Git hooks installed: core.hooksPath = .githooks"
