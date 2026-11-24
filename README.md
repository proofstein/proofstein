# Proofstein

Proofstein is meant to be a simple test of how much of the cryptography in a 
codebase a post-quantum inventory tool actually inventories. "Proof is in 
the stein" as the people testing for gold used to say. 

It contains six small programs for testing, one each in C, Go, Java, 
JavaScript, Python and Rust. Between them they use cryptography a known 
amount, and exactly where. Some sit in plain sight, as a direct call to an 
encryption function. Others are tucked away: behind a wrapper, chosen in a 
config file, or only listed as a dependency.

Run any tool over the six test programs, feed the tool results to the scorer, 
and see what the tool found and what it didn't, by language and method hidden.

## Check a tool

**1. Set up.**

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

**2. Run your tool over each of the six programs**, saving one CycloneDX 1.6
CBOM file per program:

| program | where it is | language |
|---|---|---|
| `tinyattest` | `corpus/c/tinyattest` | C |
| `beacon-relay` | `corpus/go/beacon-relay` | Go |
| `ledger-svc` | `corpus/java/ledger-svc` | Java |
| `session-broker` | `corpus/javascript/session-broker` | JavaScript/TypeScript |
| `vaultkeeper` | `corpus/python/vaultkeeper` | Python |
| `sealbox` | `corpus/rust/sealbox` | Rust |

Put all six files in one folder and name them `<program>__<tool>.json`, with
two underscores in the middle. For example: `sealbox__mytool.json`.

**3. Score.**

```bash
.venv/bin/python score.py --cboms my-cboms/ --out my-results/
```

`my-results/results.md` shows:

- how much the tool found in each language
- how much it found at each kind of hiding place
- how much of what it reported was credited
- how often it reported something that isn't there

The scorer needs no network, no Docker and nothing running in the background.

A report finds a planted asset when it names a compatible algorithm in the file
where the asset is planted. The line it reports is shown and not scored. The
rules are in [METHODOLOGY.md](METHODOLOGY.md), §1 to §4.

To run the tests: `.venv/bin/python -m unittest discover -s tests`.

## Runs

Each run directory holds its README, manifest and results; a public run also
holds the CBOMs the tools wrote. Public and holdout results are reported
separately (METHODOLOGY.md §6).

| run | date | kind | assets | tool | detection rate |
|---|---|---|---|---|---|
| [2026-11-24T1156Z-public](runs/2026-11-24T1156Z-public/) | 2026-11-24 | public | 131 | cdxgen 12.8.2 | 5% (6/131) |
|  |  |  |  | cdxgen 13.8.0 | 8% (11/131) |
|  |  |  |  | pqprobe 5.1.2 | 96% (126/131) |
|  |  |  |  | cryptoscan 1.5.0, `--include-quantum-safe` | 56% (74/131) |
|  |  |  |  | cryptoscan 1.5.0 | 41% (54/131) |
|  |  |  |  | CodeQL 2.27.5 | 19% (17/90) |
|  |  |  |  | cbomkit-theia 1.1.2 | 13% (17/131) |
|  |  |  |  | Opengrep 2.0.0 | 0% (0/131) |
| [2026-11-24T1156Z-holdout](runs/2026-11-24T1156Z-holdout/) | 2026-11-24 | holdout | 131 | cdxgen 12.8.2 | 5% (6/131) |
|  |  |  |  | pqprobe 5.1.2 | 96% (126/131) |
| [2026-11-24T1156Z-ecdsa-scan](runs/2026-11-24T1156Z-ecdsa-scan/) | 2026-11-24 | ecdsa-scan, outside the main table | 131 | ecdsa-scan 0.1.1 | 12% (16/131) |
| [2026-10-22T1007Z-holdout](runs/2026-10-22T1007Z-holdout/) | 2026-10-22 | holdout | 124 | cdxgen 12.8.2 | 5% (6/124) |
|  |  |  |  | pqprobe 4.0.2 | 96% (119/124) |
| [2026-10-22T1005Z-public](runs/2026-10-22T1005Z-public/) | 2026-10-22 | public | 124 | cdxgen 12.8.2 | 5% (6/124) |
|  |  |  |  | pqprobe 4.0.2 | 96% (119/124) |
| [2026-10-07T2249Z-holdout](runs/2026-10-07T2249Z-holdout/) | 2026-10-07 | holdout | 124 | cdxgen 12.8.2 | 5% (6/124) |
|  |  |  |  | pqprobe 3.8.2 | 96% (119/124) |
| [2026-10-07T2218Z-public](runs/2026-10-07T2218Z-public/) | 2026-10-07 | public | 124 | cdxgen 12.8.2 | 5% (6/124) |
|  |  |  |  | pqprobe 3.8.2 | 96% (119/124) |
|  |  |  |  | cryptoscan 1.4.0, `--include-quantum-safe` | 57% (71/124) |
|  |  |  |  | cryptoscan 1.4.0 | 41% (51/124) |
|  |  |  |  | CodeQL 2.27.1 | 14% (12/86) |
|  |  |  |  | cbomkit-theia 1.1.2 | 14% (17/124) |
|  |  |  |  | Opengrep 1.30.1 | 0% (0/124) |
| [2026-10-07T2016Z-ecdsa-scan](runs/2026-10-07T2016Z-ecdsa-scan/) | 2026-10-07 | ecdsa-scan, outside the main table | 124 | ecdsa-scan 0.1.1 | 10% (13/124) |
| [2026-08-23T1519Z-public](runs/2026-08-23T1519Z-public/) | 2026-08-23 | public | 124 | cdxgen 12.8.2 | 5% (6/124) |
|  |  |  |  | pqprobe 3.6.0 | 96% (119/124) |
| [2026-08-23T1519Z-holdout](runs/2026-08-23T1519Z-holdout/) | 2026-08-23 | holdout | 124 | cdxgen 12.8.2 | 5% (6/124) |
|  |  |  |  | pqprobe 3.6.0 | 96% (119/124) |

## Maintainer

Proofstein is maintained by Ottenheimer GmbH, which also makes pqprobe,
one of the scored tools. The tests and rules that apply to every tool are in
[METHODOLOGY.md §9](METHODOLOGY.md#9-maintenance).

## Licence

Apache 2.0, in [LICENSE](LICENSE).
