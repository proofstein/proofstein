#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
#
# Run cdxgen through tools/cdxgen-docker.sh with an output directory of its own
# per project. cdxgen 13 writes per-language atom and slice files beside its
# output, named by language rather than project, so a shared directory would let
# one project's files meet another's. Takes cdxgen-docker.sh's arguments; a flag
# with a value is written --flag=value.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../../.." && pwd)"
out=""; proj=""; flags=()
while [ $# -gt 0 ]; do
    case "$1" in
        --version) exec "$repo/tools/cdxgen-docker.sh" --version ;;
        -o)        out="$2"; shift 2 ;;
        -*)        flags+=("$1"); shift ;;
        *)         proj="$1"; shift ;;
    esac
done
[ -n "$out" ] && [ -n "$proj" ] || { echo "cdxgen-own-dir: need -o and a project" >&2; exit 2; }
dir="$(dirname "$out")/cdxgen-own-dir/$(basename "$proj")"
rm -rf "$dir"; mkdir -p "$dir"
"$repo/tools/cdxgen-docker.sh" "${flags[@]}" -o "$dir/bom.json" "$proj"
cp "$dir/bom.json" "$out"
