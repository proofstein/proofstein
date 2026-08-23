#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
#
# Materialise each corpus project as a standalone git repository.
#
#   tools/publish-corpus.sh /path/to/output [ground-truth-dir]
#
# BF-CBOM targets a repository by git URL and clones it itself
# (JobInstruction.repo_info.git_url, cloned at common/utils.py:136 with
# --depth 1). The corpus lives inside this repository as plain directories --
# nesting real git repositories inside it would turn each into an unregistered
# gitlink -- so this script produces the clonable form on demand.
#
# The output repositories can be pushed to a forge, or handed to BF-CBOM
# directly as file:// URLs, which is enough for a local inspection.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${1:-}"
GT_DIR="${REPO_ROOT}/${2:-ground-truth}"

if [[ -z "${DEST}" ]]; then
    echo "usage: $0 <output-directory> [ground-truth-dir]" >&2
    exit 2
fi
if [[ ! -d "${GT_DIR}" ]]; then
    echo "no such ground-truth directory: ${GT_DIR}" >&2
    exit 1
fi

mkdir -p "${DEST}"
DEST="$(cd "${DEST}" && pwd)"

CORPUS_TAG="$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
COUNT=0

while IFS=$'\t' read -r NAME LANGUAGE CORPUS_PATH; do
    [[ -n "${NAME}" ]] || continue
    SRC="${REPO_ROOT}/${CORPUS_PATH}"
    OUT="${DEST}/${NAME}"

    if [[ ! -d "${SRC}" ]]; then
        echo "skipping ${NAME}: ${CORPUS_PATH} does not exist" >&2
        continue
    fi

    rm -rf "${OUT}"
    mkdir -p "${OUT}"

    # Copy the project without any build artifacts, so the published repo is
    # exactly what the ground truth describes.
    tar -C "${SRC}" \
        --exclude=target --exclude=node_modules --exclude=dist \
        --exclude=__pycache__ --exclude=.venv --exclude='*.o' --exclude='*.class' \
        -cf - . | tar -C "${OUT}" -xf -

    git -C "${OUT}" init -q -b main
    git -C "${OUT}" add -A
    git -C "${OUT}" \
        -c user.name="Proofstein" \
        -c user.email="proofstein@invalid" \
        commit -q -m "${NAME}: Proofstein corpus snapshot (${CORPUS_TAG})"

    printf '  %-18s %-12s %s\n' "${NAME}" "${LANGUAGE}" "file://${OUT}"
    COUNT=$((COUNT + 1))
done < <(
    python3 - "${GT_DIR}" <<'PY'
import json, pathlib, sys
for path in sorted(pathlib.Path(sys.argv[1]).glob("*.json")):
    d = json.loads(path.read_text())
    print(f"{d['project']}\t{d['language']}\t{d['corpus_path']}")
PY
)

echo
echo "published ${COUNT} repositories under ${DEST} (corpus ${CORPUS_TAG})"
echo "Use the file:// URLs above as BF-CBOM repository targets, or push them to a forge."
