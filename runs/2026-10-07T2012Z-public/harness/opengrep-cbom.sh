#!/usr/bin/env bash
# Run Opengrep with the selected cryptography rules of the opengrep-rules
# snapshot over the project in the working directory; print CycloneDX 1.6.
# Each result becomes a component named by its rule id (last segment), at the
# file and line Opengrep reports. Files are scanned whether or not git ignores
# them, since the collector's export sits in an ignored directory.
# Env: OPENGREP_BIN, OPENGREP_RULES.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if [ "${1:-}" = "--version" ]; then echo "opengrep $("$OPENGREP_BIN" --version) rules opengrep-rules@f1d2b562 (rule content of 0f5a85ce, 2024-12-13)"; exit 0; fi
out="$(mktemp)"; trap 'rm -f "$out"' EXIT
"$OPENGREP_BIN" scan --config "$OPENGREP_RULES" --json --disable-version-check --quiet --no-git-ignore . > "$out"
python3 - "$out" "$here" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[2])
from cdx import bom, emit
d = json.load(open(sys.argv[1]))
s = [(r["check_id"].split(".")[-1], r["path"], r["start"]["line"]) for r in d["results"]]
emit(bom("opengrep", d.get("version", ""), s))
PY
