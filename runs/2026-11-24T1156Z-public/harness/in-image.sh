#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
#
# Run a generator inside the pinned corpus build image (tools/build.Dockerfile)
# instead of on the host:  in-image.sh <command> [args...]
#
# The project under inspection (the working directory), this repository and
# TOOLS_DIR, where the generators' binaries are, are mounted read-only at their
# own paths, so a path means the same inside the container as outside it.
# ECDSA_RAW_DIR, when set, is mounted writable. The image is TOOL_IMAGE, which
# the collector sets from the generator's `image`; HOME and TMPDIR are the
# container's own /tmp.
set -euo pipefail
IMAGE="${TOOL_IMAGE:?TOOL_IMAGE is not set: give it the image that generators.json pins for this run}"
TOOLS="${TOOLS_DIR:?TOOLS_DIR is not set: the directory holding the generator binaries}"
repo="$(cd "$(dirname "$0")/../../.." && pwd)"
cmd="$1"; shift
# A repository-relative script resolves against the repository, as the
# collector resolves the first element of an invocation.
case "$cmd" in /*) ;; *) [ -e "$repo/$cmd" ] && cmd="$repo/$cmd" ;; esac
args=(-v "$PWD:$PWD:ro" -v "$repo:$repo:ro" -v "$TOOLS:$TOOLS:ro" -w "$PWD" -e HOME=/tmp -e TMPDIR=/tmp)
[ -n "${ECDSA_RAW_DIR:-}" ] && args+=(-v "$ECDSA_RAW_DIR:$ECDSA_RAW_DIR")
for v in OPENGREP_BIN OPENGREP_RULES CODEQL_BIN NODE_BIN ECDSA_SCAN_JS ECDSA_RAW_DIR; do
    [ -n "${!v:-}" ] && args+=(-e "$v=${!v}")
done
exec docker run --rm -u "$(id -u):$(id -g)" "${args[@]}" "$IMAGE" "$cmd" "$@"
