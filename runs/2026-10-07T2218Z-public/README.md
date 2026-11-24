# 2026-10-07T2218Z, public corpus

|  |  |
|---|---|
| date | 2026-10-07T22:18:23Z |
| corpus commit | `92435d1`, tree clean |
| assets | 124 |

## How each tool was run

**cdxgen 12.8.2** writes CycloneDX itself. `tools/cdxgen-docker.sh --json-pretty --include-crypto -o <output> <project>` runs it in the image `ghcr.io/cyclonedx/cdxgen:12.8.2`. It records source files in `properties[].SrcFile`, without line numbers.

**pqprobe 3.8.2** writes CycloneDX itself: `pqprobe --output cbom scan .` from the project root, exit 1 accepted. The manifest records the binary's sha256.

**cryptoscan 1.4.0** (release tarball, checksum verified) writes CycloneDX itself: `cryptoscan scan . --format cbom --no-color`, exit 1 accepted, and again with `--include-quantum-safe`. By default it omits the findings it classes as quantum-safe, AES and the SHA-2 family among them.

**cbomkit-theia 1.1.2** (built from source) writes CycloneDX itself: `cbomkit-theia dir .`. It reads certificates, keys, `java.security` and OpenSSL configuration, and no source code.

**Opengrep 1.30.1** has no CycloneDX output. `harness/opengrep-cbom.sh` runs it with the 100 rules of the archived opengrep-rules set whose metadata names a cryptographic CWE (`harness/select_rules.py`), rule set sha256/16 `58291c511806239d`, and writes one component per result, named after its rule, at the reported file and line. The rules are not committed here.

**CodeQL 2.27.1** (bundle, checksum verified) has no CycloneDX output. `harness/codeql-cbom.sh` builds a database with `--build-mode=none` for each language of a project that has an inventory query, and writes one component per result, named after its algorithm, at its location. The queries are `experimental/cryptography/inventory/new_models/AllCryptoAlgorithms.ql` for C/C++ and Python, and every `experimental/quantum/InventorySlices/Known*Algorithm.ql` for Java. `sealbox` and `session-broker` contain none of these languages and have no document.

## Scores

| tool | scored assets | detection rate | claim precision | false positives |
|---|---|---|---|---|
| cdxgen 12.8.2 | 124 | 5% (6/124) | 20% (4/20) | 0 |
| pqprobe 3.8.2 | 124 | 96% (119/124) | 61% (125/204) | 0 |
| cryptoscan 1.4.0, `--include-quantum-safe` | 124 | 57% (71/124) | 35% (69/199) | 5 |
| cryptoscan 1.4.0 | 124 | 41% (51/124) | 29% (50/171) | 5 |
| CodeQL 2.27.1 | 86 | 14% (12/86) | 44% (12/27) | 1 |
| cbomkit-theia 1.1.2 | 124 | 14% (17/124) | 75% (33/44) | 0 |
| Opengrep 1.30.1 | 124 | 0% (0/124) | 0% (0/4) | 0 |

Full tables in `results/results.md`.

## By language

| language | cdxgen 12.8.2 | pqprobe 3.8.2 | cryptoscan 1.4.0, `--include-quantum-safe` | cryptoscan 1.4.0 | CodeQL 2.27.1 | cbomkit-theia 1.1.2 | Opengrep 1.30.1 |
|---|---|---|---|---|---|---|---|
| c | 0% (0/19) | 95% (18/19) | 42% (8/19) | 37% (7/19) | 0% (0/19) | 16% (3/19) | 0% (0/19) |
| go | 0% (0/19) | 100% (19/19) | 63% (12/19) | 32% (6/19) | 0% (0/19) | 16% (3/19) | 0% (0/19) |
| java | 8% (2/25) | 96% (24/25) | 64% (16/25) | 52% (13/25) | 28% (7/25) | 8% (2/25) | 0% (0/25) |
| javascript | 15% (3/20) | 95% (19/20) | 55% (11/20) | 40% (8/20) | -- | 15% (3/20) | 0% (0/20) |
| python | 4% (1/23) | 96% (22/23) | 61% (14/23) | 43% (10/23) | 22% (5/23) | 13% (3/23) | 0% (0/23) |
| rust | 0% (0/18) | 94% (17/18) | 56% (10/18) | 39% (7/18) | -- | 17% (3/18) | 0% (0/18) |

## False positives

cdxgen 12.8.2, pqprobe 3.8.2, cbomkit-theia 1.1.2 and Opengrep 1.30.1: none.

cryptoscan 1.4.0, in both modes: five phantom algorithms.

* `FN-DSA` in `beacon-relay/ops/health/api.py`, a negative case (METHODOLOGY.md §4)
* `LMS` at `session-broker/src/lms.ts:49`, a negative case (METHODOLOGY.md §4)
* `FN-DSA` at `session-broker/src/attest.ts:41`
* `DH` at `beacon-relay/deploy/nginx.conf:23`
* `Weak Certificate Signature (SHA-1)` at `ledger-svc/deploy/jvm.options:13`

CodeQL 2.27.1: one phantom algorithm, `DSA` at
`ledger-svc/src/main/java/io/proofstein/ledger/crypto/BlockSeal.java:39`.

40 of 40 documents were schema-valid. No document pointed at a file outside its project.
