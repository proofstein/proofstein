# 2026-10-07T2016Z, ecdsa-scan, public corpus

**On file, not in the comparison table.** This run records how ecdsa-scan does
on Proofstein so the question has a measured answer. If its figures are ever
placed beside the other generators, the section below goes with them.

| | |
|---|---|
| corpus commit | `fd134c7fd0ccfc9096842fac46db78e7fc7fd76b`, tree clean |
| assets | 124 |
| rule | detection is **file + algorithm + layer** (METHODOLOGY.md §3.3) |
| ecdsa-scan | 0.1.1 from npm, tarball `sha512-g2CwpG1YMSXtVfvg0W8D9WW3wnrkYeDTsnuxpYxGvGWFFF3Rj/ca9WsQ06lIglKiZDPn/Wd9v1h4133tx4ua6Q==`; it reports its own version as 0.1.0 |
| runtime | Node v22.23.3 |
| licence | MIT |

## What the tool measures, and why it is not in the comparison table

ecdsa-scan is a defect scanner for code that creates and checks digital
signatures. Its fourteen rules look for JWT algorithm confusion, tokens decoded
without verification, weak or caller-supplied nonces, hand-built `r‖s`
encodings, missing low-S normalisation, private keys in source and in the tree,
variable-time comparison of signatures, discarded verification results, SHA-1
and MD5 in signing paths, unvalidated public-key points and disabled
certificate verification. A fifteenth collector lists the libraries,
algorithms, curves and signing operations each file touches, which the tool
describes as the seed of a CBOM.

Proofstein plants cryptographic assets, not defects. The only part of
ecdsa-scan this corpus can score is that collector, so a row in the comparison
table would measure something the tool does not claim to do, and none of the
rules it is built around. That is the reason it is kept out of the table, not
its result.

## How it was scored

ecdsa-scan has no CycloneDX output. `converter/ecdsa-scan-cbom.sh` runs it with
`--json` over each project and `converter/to_cbom.py` converts the report,
mapping only what the tool names:

* inventory algorithms and curves become algorithm components;
* inventory libraries become library components;
* each at the files the tool lists. ecdsa-scan gives no line numbers.

Operations and defect findings name no algorithm and are not mapped. The
scorer, the corpus and the ground truth are unchanged. The run was collected by
`tools/collect-cboms.py` with `generators.json` in this directory, so it is not
in `runs/generators.json` and later runs do not pick it up.

Two cuts are reported besides the full corpus, defined in `converter/cuts.py`:

* **its languages**: the projects in the source languages ecdsa-scan reads,
  Go, JavaScript and Python (62 assets);
* **signature assets**: the planted algorithm assets of signature schemes,
  ECDSA, Ed25519, RSA, RS256, ML-DSA, SLH-DSA, Falcon, LMS and XMSS (45 assets,
  19 of them in its languages).

`results-signature/` scores the same reports with every component dropped
except signature algorithms and their curves (`to_cbom.py --signature-only`),
so its precision counts signature claims only.

## Results

| cut | recall | claim precision | component precision |
|---|---|---|---|
| full corpus | 10% (13/124) | 100% (14/14) | 91% (10/11) |
| its languages | 21% (13/62) | 100% (14/14) | 91% (10/11) |
| signature assets | 16% (7/45) | 100% (8/8) | 88% (7/8) |
| signature assets, its languages | 37% (7/19) | 100% (8/8) | 88% (7/8) |

The signature rows take recall from `results/` and precision from
`results-signature/`. No false positives, phantom algorithms or unmatched
reports were recorded in either.

It found direct and aliased-import uses in the three projects in its
languages: ECDSA and Ed25519 in all three, SHA-256 in all three, and RSA in
`vaultkeeper` through its `RSA-PSS` name. Leaving its curves out of the
conversion lowers full-corpus recall to 11/124, because its `P-256` reports are
credited against ECDSA-P256 plants.

### Negative cases

`beacon-relay`'s Falcon web-framework module and `session-broker`'s
learning-management client drew no claims. That silence does not test it: it
has no vocabulary for Falcon or LMS at all. It does not read
`ledger-svc/deploy/jvm.options`.

## What it cannot see

* **Languages.** It reads JavaScript, TypeScript, Python and Go source, and key
  files. The C, Java and Rust projects produce an empty inventory.
* **Configuration and manifests.** None are read, so layer 4 and layer 5 are
  zero, including 0/21 config assets in its own languages.
* **Vocabulary.** It has no name for RSA on its own, only `RS256`, `PS256` and
  `RSA-PSS`, so `rsa.GenerateKey` in Go and `generateKeyPairSync('rsa')` in
  TypeScript are missed although it lists `crypto/rsa` as a library. It has no
  post-quantum signature names, so ML-DSA, SLH-DSA and Falcon are missed in its
  own languages. Symmetric ciphers and KEMs are outside its scope: none of the
  19 AES-256-GCM or 13 ML-KEM plants.
* **Key and certificate files.** Its private-key rules locate 12 of the 17
  layer-6 files by path, but name no key algorithm, so none can be credited. It
  does not read certificates.
* **Indirection.** Layer 3 is zero.
* **Evidence.** Its inventory is per file, with no lines.

## Licence and provenance

The package's `LICENSE` is the MIT licence and contains no benchmarking or
publication clause; nor does its README. On 2026-10-07, ecdsa.com had no terms
or privacy page (`/terms`, `/legal`, `/terms-of-service` and `/privacy` answered
404, and the site links to none), and the repository named in `package.json`
answered 404. The npm maintainer account is `zerg2026`.

`raw/` holds each project's `--json` report with the scanning machine's paths
removed by `converter/strip.py`: the `root` and `absolutePath` fields are
dropped. Nothing else is changed.

## Files

* `generators.json`: the definition this run was collected with.
* `manifest.json`: written by `tools/collect-cboms.py`.
* `converter/`: the wrapper, the path stripper, the converter and the cut script.
* `raw/`: ecdsa-scan's reports, stripped.
* `cboms/`, `results/`: the converted documents and their scores.
* `cboms-signature/`, `results-signature/`: the signature-only cut.

## Reproducing

```bash
export NODE_BIN=/path/to/node                 # 20 or later
export NODE_VERSION=$("$NODE_BIN" --version)
export ECDSA_SCAN_JS=/path/to/ecdsa-scan-0.1.1/package/src/index.js
export ECDSA_RAW_DIR=$PWD/<run>/raw
R=runs/2026-10-07T2016Z-ecdsa-scan
tools/collect-cboms.py --config $R/generators.json --out <run>
./score.py --cboms <run>/cboms --manifest <run>/manifest.json --out <run>/results
python3 $R/converter/cuts.py <run>/results/results.json
```
