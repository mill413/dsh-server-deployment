#!/usr/bin/env bash
# sudo entry for user management. Resolves the install root from this
# script's own location (issue #3), falling back to PATH node, so it works
# from any prefix or a plain git checkout.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then exec sudo "$0" "$@"; fi
base="$(cd "$(dirname "$0")/.." && pwd)"
node_bin="$base/runtime/bin/node"
[ -x "$node_bin" ] || node_bin="$(command -v node)"
[ -n "$node_bin" ] || { echo "error: node not found - install Node.js (or provide $base/runtime/bin/node)" >&2; exit 1; }
exec "$node_bin" "$base/gateway/userctl.js" "$@"