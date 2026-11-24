#!/usr/bin/env bash
# Run ecdsa-scan over the project in the working directory and print a
# CycloneDX 1.6 document on stdout, for tools/collect-cboms.py.
#
# ecdsa-scan has no CycloneDX output. Its --json report is kept, with the
# scanning machine's paths removed (strip.py), under $ECDSA_RAW_DIR, and
# converted by to_cbom.py, which maps only what the tool names: inventory
# algorithms and curves as algorithm components, inventory libraries as library
# components, each at the files the tool lists. ecdsa-scan gives no lines.
# Operations and defect findings name no algorithm and are not mapped.
#
# Environment: NODE_BIN (Node 20 or later), ECDSA_SCAN_JS (the package's
# src/index.js), ECDSA_RAW_DIR (where the stripped reports go).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if [ "${1:-}" = "--version" ]; then
    exec "$NODE_BIN" "$ECDSA_SCAN_JS" --version
fi
project="$(basename "$PWD")"
raw="$(mktemp)"
trap 'rm -f "$raw"' EXIT
status=0
"$NODE_BIN" "$ECDSA_SCAN_JS" scan . --json --no-color > "$raw" || status=$?
# ecdsa-scan exits 1 when a confirmed finding is present; that is a result.
if [ "$status" -gt 1 ]; then
    echo "ecdsa-scan exited $status" >&2
    exit "$status"
fi
python3 "$here/strip.py" "$raw" "$PWD" > "$ECDSA_RAW_DIR/$project.json"
python3 "$here/to_cbom.py" "$ECDSA_RAW_DIR/$project.json" /dev/stdout
