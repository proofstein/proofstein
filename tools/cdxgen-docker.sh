#!/usr/bin/env bash
# Run the pinned cdxgen image with the argument list the native binary takes.
#
# The image is the one runs/generators.json pins by digest, handed over by
# tools/collect-cboms.py in TOOL_IMAGE, so there is one pin and the manifest
# records the image it names. Run by hand, set TOOL_IMAGE to that value.
#
# The container sees the project at /src, so reported paths begin with /src/.
# The scorer resolves paths by longest matching suffix (METHODOLOGY.md 3.2).
set -euo pipefail

IMAGE="${TOOL_IMAGE:?TOOL_IMAGE is not set: give it the image runs/generators.json pins}"

out=""
proj=""
flags=()
while [ $# -gt 0 ]; do
    case "$1" in
        --version) exec docker run --rm "$IMAGE" --version ;;
        -o)        out="$2"; shift 2 ;;
        -*)        flags+=("$1"); shift ;;
        *)         proj="$1"; shift ;;
    esac
done

[ -n "$out" ]  || { echo "cdxgen-docker: no -o given" >&2; exit 2; }
[ -n "$proj" ] || { echo "cdxgen-docker: no project given" >&2; exit 2; }

outdir="$(cd "$(dirname "$out")" && pwd)"
projdir="$(cd "$proj" && pwd)"

exec docker run --rm \
    -u "$(id -u):$(id -g)" \
    -v "$projdir":/src:ro \
    -v "$outdir":/out \
    -e CDXGEN_DEBUG_MODE="${CDXGEN_DEBUG_MODE:-info}" \
    -e FETCH_LICENSE="${FETCH_LICENSE:-false}" \
    "$IMAGE" "${flags[@]}" -o "/out/$(basename "$out")" /src
