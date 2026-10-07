#!/usr/bin/env bash
# Run CodeQL's cryptographic inventory queries over the project in the working
# directory and print CycloneDX 1.6. Languages with an inventory query:
#   cpp, python: experimental/cryptography/inventory/new_models/AllCryptoAlgorithms.ql
#     ("Use of algorithm <name>" at each algorithm);
#   java: every experimental/quantum/InventorySlices/Known*Algorithm.ql
#     (the algorithm name column at each node or operation).
# Every such language present in the project is analysed; a project with none
# of them gets no document. Go, JavaScript and Rust have no inventory query.
# Databases are built with --build-mode=none. Env: CODEQL_BIN.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if [ "${1:-}" = "--version" ]; then "$CODEQL_BIN" version --format=terse; exit 0; fi
langs=()
find . -name '*.java' -print -quit | grep -q . && langs+=(java)
find . -name '*.py' -print -quit | grep -q . && langs+=(python)
find . \( -name '*.c' -o -name '*.h' \) -print -quit | grep -q . && langs+=(cpp)
[ ${#langs[@]} -eq 0 ] && { echo "codeql: no inventory query for this project's languages" >&2; exit 0; }
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
src="$PWD"
packs="$(dirname "$CODEQL_BIN")/qlpacks/codeql"
qdir() { ls -d "$packs/$1-queries"/*/ | head -1; }
for lang in "${langs[@]}"; do
    mkdir -p "$work/$lang"
    "$CODEQL_BIN" database create "$work/$lang/db" --language="$lang" --build-mode=none --source-root="$src" --overwrite --quiet >&2
    if [ "$lang" = java ]; then
        for q in "$(qdir java)"experimental/quantum/InventorySlices/Known*Algorithm.ql; do
            n=$(basename "$q" .ql)
            "$CODEQL_BIN" query run "$q" --database="$work/$lang/db" --output="$work/$lang/$n.bqrs" --quiet >&2
            "$CODEQL_BIN" bqrs decode "$work/$lang/$n.bqrs" --format=json --entities=url,string --output="$work/$lang/$n.json" >&2
        done
    else
        q="$(qdir $lang)experimental/cryptography/inventory/new_models/AllCryptoAlgorithms.ql"
        "$CODEQL_BIN" database analyze "$work/$lang/db" "$q" --format=sarif-latest --output="$work/$lang/out.sarif" --quiet >&2
    fi
done
python3 - "$work" "$src" "$here" "$("$CODEQL_BIN" version --format=terse)" <<'PY'
import glob, json, os, re, sys
work, src, here, version = sys.argv[1:5]
sys.path.insert(0, here)
from cdx import bom, emit
s = []
def rel(uri):
    p = re.sub(r"^file://", "", uri)
    return os.path.relpath(p, src) if p.startswith("/") else p
for f in glob.glob(os.path.join(work, "java", "Known*.json")):
    d = json.load(open(f))
    for row in d.get("#select", {}).get("tuples", []):
        ent, name = row[0], row[1]
        url = ent.get("url") if isinstance(ent, dict) else None
        if not url or not name:
            continue
        if isinstance(url, dict):
            if url.get("uri") and url.get("startLine"):
                s.append((str(name), rel(url["uri"]), int(url["startLine"])))
            continue
        m = re.match(r"file://(.*?):(\d+):", url)
        if m:
            s.append((str(name), rel(m.group(1)), int(m.group(2))))
for f in glob.glob(os.path.join(work, "*", "out.sarif")):
    d = json.load(open(f))
    for r in d["runs"][0].get("results", []):
        loc = r["locations"][0]["physicalLocation"]
        # One result may carry several algorithms, one "Use of algorithm" line each.
        for line in r["message"]["text"].splitlines():
            line = line.strip()
            if line.startswith("Use of algorithm "):
                s.append((line[len("Use of algorithm "):], rel(loc["artifactLocation"]["uri"]), loc.get("region", {}).get("startLine")))
emit(bom("codeql", version, s))
PY
