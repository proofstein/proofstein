# 2026-11-24T1156Z, public corpus

|  |  |
|---|---|
| date | 2026-11-24T11:57:03Z |
| corpus commit | `f366ff5`, tree clean |
| assets | 131 |

## How each tool was run

Both corpora were built with `tools/build-all.sh` in the image of `tools/build.Dockerfile` (image id `sha256:3d16c8bfbf683df091999be2894de91ff1d561a285a16da96f8d15d6ec3b4864`), 6 of 6 projects each. The generators other than cdxgen ran in that image through `harness/in-image.sh`, which mounts the project, this repository and the tool binaries read-only. cdxgen ran from its own images through `tools/cdxgen-docker.sh`.

**cdxgen 12.8.2** writes CycloneDX itself: `tools/cdxgen-docker.sh --json-pretty --include-crypto -o <output> <project>`, in `ghcr.io/cyclonedx/cdxgen@sha256:d2a9f784c6d3d71a9d143dd69e6ca43fdb340282b1e43d1b99ad07e9321a4783`. It records source files in `properties[].SrcFile`, without line numbers.

**cdxgen 13.8.0** writes CycloneDX itself, with the arguments of cdxgen 12.8.2 and `--spec-version=1.6`, in `ghcr.io/cdxgen/cdxgen@sha256:2bbfeffaa64801cac126e60441acaf8ceedd8eb939b32c3dad15519dce3ef5c6`, through `harness/cdxgen-own-dir.sh`, which gives each project its own output directory.

**pqprobe 5.1.2** writes CycloneDX itself: `pqprobe --output cbom scan .` from the project root, exit 1 accepted.

**cryptoscan 1.5.0** (release tarball, checksum verified) writes CycloneDX itself: `cryptoscan scan . --format cbom --no-color`, exit 1 accepted, and again with `--include-quantum-safe`. By default it omits the findings it classes as quantum-safe, AES and the SHA-2 family among them.

**cbomkit-theia 1.1.2** (built in the build image) writes CycloneDX itself: `cbomkit-theia dir .`. It reads certificates, keys, `java.security` and OpenSSL configuration, and no source code.

**Opengrep 2.0.0** (`opengrep_linux_x86`, cosign signature verified) has no CycloneDX output. `harness/opengrep-cbom.sh` runs it with the 100 rules of the archived opengrep-rules set whose metadata names a cryptographic CWE (`harness/select_rules.py`), rule set digest `f98b5696b0867c1f` (`harness/ruleset-digest.sh`), and writes one component per result, named after its rule, at the reported file and line. The rules are not committed here.

**CodeQL 2.27.5** (bundle, checksum verified) has no CycloneDX output. `harness/codeql-cbom.sh` builds a database with `--build-mode=none` for each language of a project that has an inventory query, and writes one component per result, named after its algorithm, at its location. The queries are `experimental/cryptography/inventory/new_models/AllCryptoAlgorithms.ql` for C/C++ and Python, and every `experimental/quantum/InventorySlices/Known*Algorithm.ql` for Java. `sealbox` and `session-broker` contain none of these languages and have no document.

## Scores

| tool | scored assets | detection rate | claim precision | false positives |
|---|---|---|---|---|
| cdxgen 12.8.2 | 131 | 5% (6/131) | 20% (4/20) | 0 |
| cdxgen 13.8.0 | 131 | 8% (11/131) | 36% (9/25) | 0 |
| pqprobe 5.1.2 | 131 | 96% (126/131) | 67% (144/215) | 0 |
| cryptoscan 1.5.0, `--include-quantum-safe` | 131 | 56% (74/131) | 35% (74/209) | 6 |
| cryptoscan 1.5.0 | 131 | 41% (54/131) | 31% (54/177) | 6 |
| CodeQL 2.27.5 | 90 | 19% (17/90) | 42% (17/40) | 1 |
| cbomkit-theia 1.1.2 | 131 | 13% (17/131) | 75% (33/44) | 0 |
| Opengrep 2.0.0 | 131 | 0% (0/131) | 0% (0/4) | 0 |

Full tables in `results/results.md`.

## By language

| language | cdxgen 12.8.2 | cdxgen 13.8.0 | pqprobe 5.1.2 | cryptoscan 1.5.0, `--include-quantum-safe` | cryptoscan 1.5.0 | CodeQL 2.27.5 | cbomkit-theia 1.1.2 | Opengrep 2.0.0 |
|---|---|---|---|---|---|---|---|---|
| c | 0% (0/23) | 4% (1/23) | 96% (22/23) | 43% (10/23) | 39% (9/23) | 22% (5/23) | 13% (3/23) | 0% (0/23) |
| go | 0% (0/19) | 5% (1/19) | 100% (19/19) | 63% (12/19) | 32% (6/19) | 0% (0/19) | 16% (3/19) | 0% (0/19) |
| java | 8% (2/25) | 8% (2/25) | 96% (24/25) | 64% (16/25) | 52% (13/25) | 28% (7/25) | 8% (2/25) | 0% (0/25) |
| javascript | 13% (3/23) | 17% (4/23) | 96% (22/23) | 52% (12/23) | 39% (9/23) | -- | 13% (3/23) | 0% (0/23) |
| python | 4% (1/23) | 9% (2/23) | 96% (22/23) | 61% (14/23) | 43% (10/23) | 22% (5/23) | 13% (3/23) | 0% (0/23) |
| rust | 0% (0/18) | 6% (1/18) | 94% (17/18) | 56% (10/18) | 39% (7/18) | -- | 17% (3/18) | 0% (0/18) |

## False positives

cdxgen 12.8.2, cdxgen 13.8.0, pqprobe 5.1.2, cbomkit-theia 1.1.2 and Opengrep 2.0.0: none.

cryptoscan 1.5.0, in both modes: six phantom algorithms.

* `FN-DSA` in `beacon-relay/ops/health/api.py`, a negative case (METHODOLOGY.md §4)
* `LMS` at `session-broker/src/lms.ts:49`, a negative case (METHODOLOGY.md §4)
* `FN-DSA` at `session-broker/src/attest.ts:41`
* `DH` at `beacon-relay/deploy/nginx.conf:23`
* `Weak Certificate Signature (SHA-1)` at `ledger-svc/deploy/jvm.options:13`
* `bcrypt` at `tinyattest/src/win_cng.c:15`

CodeQL 2.27.5: one phantom algorithm, `DSA` at
`ledger-svc/src/main/java/io/proofstein/ledger/crypto/BlockSeal.java:38`.

46 of 46 documents were schema-valid. No document pointed at a file outside its project.
