#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
#
# Build every project in a corpus and report pass/fail per project.
#
#   tools/build-all.sh                      # the public corpus
#   tools/build-all.sh ground-truth-holdout # the generated holdout variants
#
# The corpus exists so that build-aware CBOM generators are not disadvantaged,
# which only holds if the projects actually build. This is the check for that,
# and for the holdout it is also the check that the rename and relocation
# transforms produced a program that still compiles.
#
# Projects are discovered from the ground-truth documents rather than hardcoded,
# so a holdout variant under a different name is picked up automatically.
#
# Build artifacts (cargo target dirs, the crate registry, node_modules, the
# Maven repo) are large and disposable, so they are kept outside the repo and
# off the root filesystem. Override PROOFSTEIN_BUILD_ROOT to relocate them.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GT_DIR="${REPO_ROOT}/${1:-ground-truth}"

if [[ ! -d "${GT_DIR}" ]]; then
    echo "no such ground-truth directory: ${GT_DIR}" >&2
    exit 1
fi

DEFAULT_BUILD_ROOT="${TMPDIR:-/tmp}/proofstein-build"
BUILD_ROOT="${PROOFSTEIN_BUILD_ROOT:-${DEFAULT_BUILD_ROOT}}"
# Rust: keep compiled artifacts and the crate registry off the repo filesystem.
#
# The target directory is namespaced per corpus. A holdout variant keeps the
# same crate name as the project it derives from, so sharing one target dir
# between the public corpus and a holdout run makes two different source trees
# compete for the same output path.
export CARGO_TARGET_DIR="${BUILD_ROOT}/cargo-target/$(basename "${GT_DIR}")"
export CARGO_HOME="${BUILD_ROOT}/cargo-home"

mkdir -p "${BUILD_ROOT}"/{cargo-home,m2,npm-cache,venvs} "${CARGO_TARGET_DIR}"
export PATH="${CARGO_HOME}/bin:${PATH}"

# wolfSSL is built from source rather than taken from a package manager.
#
# tinyattest's long-term seals use wc_XmssKey and wc_LmsKey. Both XMSS and LMS
# are opt-in at wolfSSL configure time, and the Conan Center recipe exposes no
# option for either: its surface is shared, fPIC, opensslextra, opensslall,
# sslv3, alpn, des3, tls13, certgen, dsa, ripemd, sessioncerts, sni, testcert,
# with_curl, with_quic, with_experimental and with_rpk. There is no package
# route to a wolfSSL that can build this project, so the dependency is pinned
# and built here instead.
#
# 5.9.1 rather than an earlier release: it ships LMS and XMSS as native
# wolfCrypt implementations. Earlier versions integrated external reference code
# and could not reliably enable both schemes in one build, which this project
# needs.
WOLFSSL_VERSION="5.9.1"
WOLFSSL_PREFIX="${BUILD_ROOT}/wolfssl-${WOLFSSL_VERSION}"

ensure_wolfssl() {
    if [[ -e "${WOLFSSL_PREFIX}/lib/libwolfssl.so" || -e "${WOLFSSL_PREFIX}/lib/libwolfssl.a" ]]; then
        return 0
    fi

    echo "building wolfSSL ${WOLFSSL_VERSION} (XMSS + LMS) into ${WOLFSSL_PREFIX}"
    local src="${BUILD_ROOT}/wolfssl-src-${WOLFSSL_VERSION}"
    local tarball="${BUILD_ROOT}/wolfssl-${WOLFSSL_VERSION}.tar.gz"
    local url="https://github.com/wolfSSL/wolfssl/archive/refs/tags/v${WOLFSSL_VERSION}-stable.tar.gz"

    rm -rf "${src}"
    mkdir -p "${src}"
    curl -fsSL "${url}" -o "${tarball}" || { echo "wolfSSL download failed: ${url}" >&2; return 1; }
    tar -xzf "${tarball}" -C "${src}" --strip-components=1 || return 1

    (
        cd "${src}" || exit 1
        # The GitHub source archive ships no configure script.
        [[ -x ./configure ]] || ./autogen.sh || exit 1
        ./configure --prefix="${WOLFSSL_PREFIX}" --enable-xmss --enable-lms || exit 1
        make -j"$(nproc 2>/dev/null || echo 2)" || exit 1
        make install || exit 1
    ) || { echo "wolfSSL build failed" >&2; return 1; }
}

MVN_FLAGS=(-B -q "-Dmaven.repo.local=${BUILD_ROOT}/m2")
export NPM_CONFIG_CACHE="${BUILD_ROOT}/npm-cache"

# Maven needs a JDK, not a JRE.
if [[ -z "${JAVA_HOME:-}" || ! -x "${JAVA_HOME}/bin/javac" ]]; then
    for candidate in /usr/lib/jvm/*/bin/javac; do
        [[ -x "${candidate}" ]] || continue
        JAVA_HOME="$(dirname "$(dirname "${candidate}")")"
        export JAVA_HOME
        break
    done
fi

build_go() { go build ./... && go vet ./...; }
build_c() {
    ensure_wolfssl || return 1
    export CPPFLAGS="-I${WOLFSSL_PREFIX}/include ${CPPFLAGS:-}"
    export LDFLAGS="-L${WOLFSSL_PREFIX}/lib ${LDFLAGS:-}"
    export LD_LIBRARY_PATH="${WOLFSSL_PREFIX}/lib:${LD_LIBRARY_PATH:-}"
    make clean >/dev/null 2>&1
    make && make check
}
build_rust() { cargo build --locked && cargo run --locked --quiet; }
build_java() { mvn "${MVN_FLAGS[@]}" package && mvn "${MVN_FLAGS[@]}" exec:java; }
build_javascript() {
    if [[ -f package-lock.json ]]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi \
        && npm run build \
        && node dist/index.js --config "$(ls config/*.yaml | head -1)"
}
build_python() {
    local venv="${BUILD_ROOT}/venvs/$(basename "${PWD}")"
    local package
    package="$(find src -maxdepth 2 -name daemon.py -printf '%h\n' | head -1 | xargs -r basename)"
    [[ -n "${package}" ]] || { echo "no daemon.py under src/" >&2; return 1; }

    python3 -m venv "${venv}" >/dev/null 2>&1 || true
    "${venv}/bin/pip" install -q --disable-pip-version-check -r requirements.txt \
        && "${venv}/bin/pip" install -q --disable-pip-version-check -e . \
        && "${venv}/bin/python" -m "${package}.daemon" --config "$(ls config/*.yaml | head -1)"
}

echo "build root: ${BUILD_ROOT}"
echo "ground truth: ${GT_DIR}"
echo "JAVA_HOME:  ${JAVA_HOME:-<unset>}"

PASS=0
FAIL=0
declare -a RESULTS=()

while IFS=$'\t' read -r NAME LANGUAGE CORPUS_PATH; do
    [[ -n "${NAME}" ]] || continue
    DIR="${REPO_ROOT}/${CORPUS_PATH}"
    LABEL="${LANGUAGE}/${NAME}"
    printf '\n\033[1m=== %s ===\033[0m\n' "${LABEL}"

    if [[ ! -d "${DIR}" ]]; then
        RESULTS+=("MISSING  ${LABEL}")
        FAIL=$((FAIL + 1))
        continue
    fi

    BUILDER="build_${LANGUAGE}"
    if ! declare -F "${BUILDER}" >/dev/null; then
        RESULTS+=("SKIPPED  ${LABEL} (no builder for ${LANGUAGE})")
        continue
    fi

    if (cd "${DIR}" && "${BUILDER}"); then
        RESULTS+=("ok       ${LABEL}")
        PASS=$((PASS + 1))
    else
        RESULTS+=("FAILED   ${LABEL}")
        FAIL=$((FAIL + 1))
    fi
done < <(
    python3 - "${GT_DIR}" <<'PY'
import json, pathlib, sys
for path in sorted(pathlib.Path(sys.argv[1]).glob("*.json")):
    d = json.loads(path.read_text())
    print(f"{d['project']}\t{d['language']}\t{d['corpus_path']}")
PY
)

printf '\n\033[1m=== summary ===\033[0m\n'
for line in "${RESULTS[@]}"; do
    printf '  %s\n' "${line}"
done
printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
printf 'artifacts under %s (%s)\n' "${BUILD_ROOT}" "$(du -sh "${BUILD_ROOT}" 2>/dev/null | cut -f1)"

[[ "${FAIL}" -eq 0 ]]
