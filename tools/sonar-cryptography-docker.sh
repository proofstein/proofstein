#!/usr/bin/env bash
# Run the PQCA sonar-cryptography plugin over a corpus project and emit its CBOM.
#
#   tools/sonar-cryptography-docker.sh up                      # boot the server
#   tools/sonar-cryptography-docker.sh -o <out.json> <project>  # scan one project
#   tools/sonar-cryptography-docker.sh down                    # stop and remove
#   tools/sonar-cryptography-docker.sh --version
#
# The scan form takes the same arguments as tools/cdxgen-docker.sh, so
# runs/generators.json invokes every harness the same way.
#
# Unlike cdxgen and pqprobe-static this generator is not a binary: it is a
# SonarQube plugin, so a scan needs a server with the plugin installed and a
# scanner client pointed at it.
#
# **Boot is its own step.** SonarQube with a 51 MB plugin takes minutes to reach
# UP, and folding that into the first scan puts a long unbounded wait inside a
# call the caller expects to be short. `up` polls until the server answers UP and
# has no timeout of its own; a caller that wants to bound it should bound `up`,
# not a scan. A scan against a server that is not up fails immediately and says
# so, rather than waiting.
#
# What `up` does, in order:
#
#   1. fetches the pinned plugin jar into a cache directory and verifies its
#      SHA-256 against the digest below;
#   2. starts the pinned SonarQube image with that jar mounted as an extension;
#   3. polls /api/system/status until it reports UP;
#   4. completes SonarQube's forced first-login password change, so that no step
#      here needs the web UI;
#   5. activates the plugin's Inventory rules.
#
# Step 5 is not optional and is the difference between a score and a zero. The
# plugin registers one rule per language, sonar-{java,python,go}-crypto:Inventory,
# and ships all three switched **off**: they are in no quality profile, including
# Sonar way. A sensor only runs checks that are active, so on a stock server the
# crypto sensor examines nothing, the post-job finds no assets, and the scan ends
# with "No cryptography assets were detected. CBOM will not be generated." and
# EXECUTION SUCCESS. Nothing in that output looks like a misconfiguration, which
# is exactly why this step is spelled out here: the failure is silent and reads
# as a tool that found nothing.
#
# Java is scanned without sonar.java.binaries, so the analyser logs a warning
# about less precise results. Measured on ledger-svc, compiling the project and
# supplying binaries and the BouncyCastle jar changed nothing: 27 components and
# the same 15 distinct (algorithm, file) pairs either way. The corpus is
# therefore scanned as it sits in the repository, unbuilt, like every other
# generator here.
#
# A scan copies the project into a writable work directory, because the plugin
# writes cbom.json into the directory it scans and the corpus is read-only
# everywhere else. The corpus is never modified.
#
# SonarQube is pinned at 26.8. Plugin 1.6.1 links against
# org.sonar.api.config.PropertyDefinition$ConfigScope, which 10.7 does not carry:
# the server starts, the plugin fails to load with NoClassDefFoundError, and
# SonarQube stops itself during background initialisation. The plugin's README
# still claims 9.9 and later, which is stale for this release.
#
# Scope, stated because it bounds every score this tool can earn: the engine
# reads **Java, Python and Go** (and C#, in development upstream). Assets in C,
# JavaScript and Rust are outside what it parses at all, so its ceiling on this
# corpus is the assets in those three languages, not 124.
set -euo pipefail

SONAR_IMAGE="sonarqube:26.8.0.126808-community"
SCANNER_IMAGE="sonarsource/sonar-scanner-cli:12.1.0.3233_8.0.1"
PLUGIN_VERSION="1.6.1"
PLUGIN_URL="https://github.com/cbomkit/sonar-cryptography/releases/download/${PLUGIN_VERSION}/sonar-cryptography-plugin-${PLUGIN_VERSION}.jar"

# Digest of the published 1.6.1 asset, confirmed by re-fetching the release and
# comparing against the cached copy. A jar that does not match this is not the
# plugin this harness pins, and the run stops.
PLUGIN_SHA256="de2f21ea06740441e81ecae03b2e3ac743b79dcf87e5a6563c99989a8ba03b33"

CACHE="${PROOFSTEIN_BUILD_ROOT:-${TMPDIR:-/tmp}/proofstein-build}/sonar"
CONTAINER="proofstein-sonarqube"
NETWORK="proofstein-sonar-net"

# Scan-container only. This server holds no source beyond a throwaway copy of the
# corpus, is not reachable off this host, and is destroyed by `down`. It is a
# fixed literal so the harness needs no secret handling; do not reuse it.
#
# It carries an uppercase letter and a digit because SonarQube 26.8 enforces
# complexity on change_password and rejects anything simpler.
ADMIN_PASS="Proofstein-scan-only-1"

JAR="$CACHE/plugins/sonar-cryptography-plugin-${PLUGIN_VERSION}.jar"

#: Whichever admin credential this server actually accepts, resolved once.
#: Some SonarQube versions force a password change on first use and some do not,
#: so the harness asks rather than assuming. /api/authentication/validate is not
#: usable for this: it answers 200 with {"valid":false} for a bad credential.
CRED=""

resolve_cred() {
    [ -n "$CRED" ] && return 0
    local probe
    for probe in "admin:${ADMIN_PASS}" "admin:admin"; do
        if [ "$(curl -s -o /dev/null -w '%{http_code}' -u "$probe" \
                -X POST "http://localhost:9000/api/user_tokens/revoke?name=proofstein-probe")" != "401" ]; then
            CRED="$probe"
            return 0
        fi
    done
    echo "sonar: no working admin credential" >&2
    exit 1
}

api() { resolve_cred; curl -fsS -u "$CRED" "$@"; }

fetch_plugin() {
    mkdir -p "$CACHE/plugins" "$CACHE/work"
    if [ ! -f "$JAR" ]; then
        echo "sonar: fetching plugin ${PLUGIN_VERSION}" >&2
        curl -fsSL "$PLUGIN_URL" -o "$JAR.tmp"
        mv "$JAR.tmp" "$JAR"
    fi
    echo "${PLUGIN_SHA256}  ${JAR}" | sha256sum -c - >/dev/null \
        || { echo "sonar: plugin digest does not match the pinned release" >&2; exit 1; }
}

server_up() {
    [ "$(curl -fsS http://localhost:9000/api/system/status 2>/dev/null |
         sed -n 's/.*"status":"\([A-Z]*\)".*/\1/p')" = "UP" ]
}

cmd_up() {
    fetch_plugin
    if server_up; then echo "sonar: already up" >&2; ensure_profiles; return 0; fi

    docker network inspect "$NETWORK" >/dev/null 2>&1 || docker network create "$NETWORK" >/dev/null
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    echo "sonar: starting ${SONAR_IMAGE} with plugin ${PLUGIN_VERSION}" >&2
    docker run -d --name "$CONTAINER" --network "$NETWORK" \
        -p 9000:9000 \
        -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
        -v "$JAR":/opt/sonarqube/extensions/plugins/sonar-cryptography-plugin.jar:ro \
        "$SONAR_IMAGE" >/dev/null

    # No timeout here by design. Boot is slow and variable; a caller that needs a
    # bound should impose it on this step, where a partial wait is visible.
    local waited=0
    until server_up; do
        if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
            echo "sonar: container exited during boot" >&2
            docker logs --tail 40 "$CONTAINER" >&2
            exit 1
        fi
        sleep 5
        waited=$((waited + 5))
        [ $((waited % 60)) -eq 0 ] && echo "sonar: still booting (${waited}s)" >&2
    done
    echo "sonar: up after ${waited}s" >&2

    # Best effort: a version that forces a change needs this, and one that does
    # not will reject it harmlessly. resolve_cred works out which happened.
    curl -fsS -u admin:admin -X POST \
        "http://localhost:9000/api/users/change_password?login=admin&previousPassword=admin&password=${ADMIN_PASS}" \
        >/dev/null 2>&1 || true

    ensure_profiles
}

#: Put each language's Inventory rule into a profile and make it the default.
#: Idempotent: create and activate both no-op on a server that already has them.
#: Only the Inventory rule is activated. The plugin also ships NoMD5use rules,
#: which raise issues rather than contributing to the CBOM, and this harness
#: scores CBOMs.
ensure_profiles() {
    local pair lang rule key
    for pair in "java:sonar-java-crypto:Inventory" \
                "py:sonar-python-crypto:Inventory" \
                "go:sonar-go-crypto:Inventory"; do
        lang="${pair%%:*}"; rule="${pair#*:}"
        api -X POST "http://localhost:9000/api/qualityprofiles/create?language=${lang}&name=proofstein-crypto" \
            >/dev/null 2>&1 || true
        key="$(api "http://localhost:9000/api/qualityprofiles/search?language=${lang}" |
               sed -n 's/.*"key":"\([^"]*\)","name":"proofstein-crypto".*/\1/p')"
        [ -n "$key" ] || { echo "sonar: no proofstein-crypto profile for ${lang}" >&2; exit 1; }
        api -X POST "http://localhost:9000/api/qualityprofiles/activate_rule" \
            --data-urlencode "key=$key" --data-urlencode "rule=$rule" >/dev/null
        api -X POST "http://localhost:9000/api/qualityprofiles/set_default?language=${lang}&qualityProfile=proofstein-crypto" \
            >/dev/null

        # Confirm rather than assume: an activate that silently did nothing would
        # otherwise surface as a tool that found no cryptography.
        api "http://localhost:9000/api/rules/show?key=${rule}&actives=true" |
            grep -q '"actives":\[{' \
            || { echo "sonar: ${rule} is still not active" >&2; exit 1; }
    done
    echo "sonar: Inventory rules active for java, py, go" >&2
}

cmd_down() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
    echo "sonar: stopped" >&2
}

cmd_scan() {
    local out="$1" proj="$2"
    server_up || { echo "sonar: server is not up; run '$0 up' first" >&2; exit 1; }

    # Refuse to scan against a server whose Inventory rules are off. That scan
    # would succeed and report nothing, which is indistinguishable from a tool
    # that genuinely found nothing.
    api "http://localhost:9000/api/rules/show?key=sonar-java-crypto:Inventory&actives=true" |
        grep -q '"actives":\[{' \
        || { echo "sonar: Inventory rules are not active; run '$0 up' first" >&2; exit 1; }

    local key work
    key="$(basename "$proj")"
    api -X POST "http://localhost:9000/api/projects/create?name=${key}&project=${key}" >/dev/null 2>&1 || true
    api -X POST "http://localhost:9000/api/user_tokens/revoke?name=${key}" >/dev/null 2>&1 || true
    local token
    token="$(api -X POST "http://localhost:9000/api/user_tokens/generate?name=${key}" |
             sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
    [ -n "$token" ] || { echo "sonar: could not mint a token for ${key}" >&2; exit 1; }

    work="$CACHE/work/$key"
    rm -rf "$work"; mkdir -p "$work"
    cp -r "$proj/." "$work/"

    docker run --rm --network "$NETWORK" \
        -u "$(id -u):$(id -g)" \
        -e SONAR_HOST_URL="http://${CONTAINER}:9000" \
        -e SONAR_TOKEN="$token" \
        -v "$work":/usr/src \
        "$SCANNER_IMAGE" \
        -Dsonar.projectKey="$key" \
        -Dsonar.sources=. \
        -Dsonar.scm.disabled=true \
        -Dsonar.cryptoScanner.cbom=cbom >&2

    [ -f "$work/cbom.json" ] || { echo "sonar: no cbom.json produced for ${key}" >&2; exit 1; }
    mkdir -p "$(dirname "$out")"
    cp "$work/cbom.json" "$out"
}

case "${1:-}" in
    up)        cmd_up; exit 0 ;;
    down)      cmd_down; exit 0 ;;
    --version) echo "sonar-cryptography ${PLUGIN_VERSION} on ${SONAR_IMAGE}"; exit 0 ;;
esac

out=""
proj=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -*) shift ;;
        *)  proj="$1"; shift ;;
    esac
done
[ -n "$out" ]  || { echo "sonar-cryptography-docker: no -o given" >&2; exit 2; }
[ -n "$proj" ] || { echo "sonar-cryptography-docker: no project given" >&2; exit 2; }
cmd_scan "$out" "$proj"
