# 2026-10-07T2012Z, public corpus

| | |
|---|---|
| corpus commit | `635f455`, tree clean |
| assets | 124 |
| rule | detection is **file + algorithm + layer**; the line is recorded and reported, never scored (METHODOLOGY.md §3.3) |
| judgement tables | as of docs/pending-review.md entry 17 |
| cdxgen | 12.8.2, the control, held at the same version across every run |
| pqprobe-static | 3.8.1 |
| cryptoscan | 1.4.0 (CSNP), scored twice: defaults, and `--include-quantum-safe` |
| cbomkit-theia | v1.1.2 (`dcd95ac`), built from source |
| Opengrep | 1.30.1, with the cryptography rules of the opengrep-rules snapshot of 2024-12-13 |
| CodeQL | 2.27.1 bundle, inventory queries only |

## Scores

| tool | scored assets | all | claim precision | false positives |
|---|---|---|---|---|
| cdxgen 12.8.2 | 124 | 5% (6/124) | 20% (4/20) | 0 |
| pqprobe-static 3.8.1 | 124 | 96% (119/124) | 61% (126/206) | 1 |
| cryptoscan 1.4.0, `--include-quantum-safe` | 124 | 57% (71/124) | 35% (69/199) | 5 |
| cryptoscan 1.4.0, defaults | 124 | 41% (51/124) | 29% (50/171) | 5 |
| CodeQL 2.27.1 | 86 | 14% (12/86) | 44% (12/27) | 1 |
| cbomkit-theia v1.1.2 | 124 | 14% (17/124) | 77% (34/44) | 0 |
| Opengrep 1.30.1 | 124 | 0% (0/124) | 0% (0/4) | 0 |

Full tables in `results/results.md`.

| language | cdxgen | pqprobe-static | cryptoscan (quantum-safe) | cryptoscan | CodeQL | cbomkit-theia | Opengrep |
|---|---|---|---|---|---|---|---|
| c | 0% (0/19) | 95% (18/19) | 42% (8/19) | 37% (7/19) | 0% (0/19) | 16% (3/19) | 0% (0/19) |
| go | 0% (0/19) | 100% (19/19) | 63% (12/19) | 32% (6/19) | 0% (0/19) | 16% (3/19) | 0% (0/19) |
| java | 8% (2/25) | 96% (24/25) | 64% (16/25) | 52% (13/25) | 28% (7/25) | 8% (2/25) | 0% (0/25) |
| javascript | 15% (3/20) | 95% (19/20) | 55% (11/20) | 40% (8/20) | -- | 15% (3/20) | 0% (0/20) |
| python | 4% (1/23) | 96% (22/23) | 61% (14/23) | 43% (10/23) | 22% (5/23) | 13% (3/23) | 0% (0/23) |
| rust | 0% (0/18) | 94% (17/18) | 56% (10/18) | 39% (7/18) | -- | 17% (3/18) | 0% (0/18) |

## How each tool was run

**cryptoscan** writes CycloneDX itself, with file and line on every occurrence.
By default it withholds the findings it classes as quantum-safe, AES and the SHA-2
family among them; `--include-quantum-safe` reports them too. It exits 1 when it
reports a critical finding, after writing the full document, so 1 is accepted
alongside 0.

**cbomkit-theia** writes CycloneDX itself, at file level. It reads certificates,
keys, `java.security` and OpenSSL configuration and no source code, so layer 6
is the whole of what it can find, and it finds all of it.

**Opengrep** has no CycloneDX output. `harness/opengrep-cbom.sh` runs it with
the 100 rules of the opengrep-rules snapshot whose metadata names a cryptographic
CWE (`harness/select_rules.py` lists them), and names each result's component
after its rule, at the file and line reported. The snapshot's rule content is
that of commit `0f5a85ce` (2024-12-13), the last before the upstream rules licence
changed; the rule set's digest is in `manifest.json`. The rules are LGPL-2.1 with
the Commons Clause and are not committed here. They are weak-cryptography rules,
and this corpus plants inventory rather than weaknesses: its only matches are
`gcm-detection` at the AES-256-GCM plants in `ledger-svc`, and a mode name does not
credit a cipher (docs/pending-review.md entry 16).

**CodeQL** has no CycloneDX output. `harness/codeql-cbom.sh` builds a database with
`--build-mode=none` for every language in a project that has an inventory query,
and maps each result's algorithm name to a component at its location:

* C/C++ and Python: `experimental/cryptography/inventory/new_models/AllCryptoAlgorithms.ql`;
* Java: every `experimental/quantum/InventorySlices/Known*Algorithm.ql`.

Go, JavaScript and Rust have no inventory query. `sealbox` and `session-broker`
produce no document and are not scored as zero, which is why 86 assets are in
scope rather than 124. `beacon-relay` is scored, because it carries a Python
module beside its Go source, and its Go plants are outside what the queries
read. C is scored unbuilt, like every generator here; the queries find nothing
in `tinyattest` without its headers, and a traced build was not available where
this run was collected. CodeQL's terms permit analysis of a codebase released
under an OSI-approved licence, which this repository is.

## False positives

cdxgen and cbomkit-theia were charged none.

pqprobe-static was charged one: `Falcon-512` at `session-broker/src/attest.ts:41`,
a configuration value naming a scheme the project does not implement.

cryptoscan was charged five in either mode. Two are the negative cases:
`FN-DSA` in `beacon-relay/ops/health/api.py`, a web-framework module
(docs/pending-review.md entry 9), and `LMS` in `session-broker/src/lms.ts`, a
learning-management client (entry 11). One is `FN-DSA` at
`session-broker/src/attest.ts:41`, the line pqprobe-static is charged for. The
other two are `DH` at `beacon-relay/deploy/nginx.conf:23`, read from the
`ECDHE-` of an elliptic-curve suite, and `Weak Certificate Signature (SHA-1)` at
`ledger-svc/deploy/jvm.options:13`, a line that disables SSLv3, TLS 1.0 and
1.1, RC4, DES and MD5withRSA and names no SHA-1.

CodeQL was charged one: `DSA` at `ledger-svc/.../BlockSeal.java:39`, where the
plants are ML-DSA and SLH-DSA.

All documents were schema-valid, and none pointed at a file that is not in the
project.

## Not in this run

The holdout was not run.
