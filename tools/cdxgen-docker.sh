#!/usr/bin/env bash
# Run the pinned cdxgen image with the argument list the native binary takes.
#
# the 2026-07-27, 2026-07-28 and 2026-08-01 runs invoked cdxgen from a node_modules install. That build root
# no longer exists and this host has no Node toolchain, so the 2026-08-23 run invokes the
# official image at the same pinned version instead. The arguments are unchanged,
# which is what keeps cdxgen a control across runs.
#
# One observable difference, recorded because it is visible in the output: the
# container sees the project at /src, so reported paths are /src/... rather than
# an absolute host path. The scorer resolves paths by longest matching suffix
# (METHODOLOGY.md 3.2), so this changes nothing about matching.
set -euo pipefail

IMAGE="ghcr.io/cyclonedx/cdxgen:12.8.2"

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
