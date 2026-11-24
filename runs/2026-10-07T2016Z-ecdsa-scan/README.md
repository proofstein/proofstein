# 2026-10-07T2016Z, ecdsa-scan, public corpus

|  |  |
|---|---|
| date | 2026-10-07T20:16:56Z |
| corpus commit | `fd134c7`, tree clean |
| assets | 124 |
| kind | ecdsa-scan, scored outside the main table |

## How each tool was run

**ecdsa-scan 0.1.1** (npm tarball `sha512-g2CwpG1YMSXtVfvg0W8D9WW3wnrkYeDTsnuxpYxGvGWFFF3Rj/ca9WsQ06lIglKiZDPn/Wd9v1h4133tx4ua6Q==`, Node v22.23.3) has no CycloneDX output. `converter/ecdsa-scan-cbom.sh` runs it with `--json` over each project, and `converter/to_cbom.py` writes its inventory algorithms and curves as algorithm components and its inventory libraries as library components, at the files it lists, without lines. Its operations and defect findings name no algorithm and are not converted. `raw/` holds the `--json` reports with the `root` and `absolutePath` fields removed by `converter/strip.py`.

`cboms-signature/` holds the same reports converted with `to_cbom.py --signature-only`, which keeps signature algorithms and their curves only; `results-signature/` scores them.

`converter/cuts.py` computes the cuts in the score table: **its languages** are the projects in Go, JavaScript and Python (62 assets); **signature assets** are the planted ECDSA, Ed25519, RSA, RS256, ML-DSA, SLH-DSA, Falcon, LMS and XMSS algorithm assets (45, 19 of them in its languages). The signature rows take recall from `results/` and precision from `results-signature/`.

## Scores

| cut | detection rate | claim precision | component precision | false positives |
|---|---|---|---|---|
| full corpus | 10% (13/124) | 100% (14/14) | 91% (10/11) | 0 |
| its languages | 21% (13/62) | 100% (14/14) | 91% (10/11) | 0 |
| signature assets | 16% (7/45) | 100% (8/8) | 88% (7/8) | 0 |
| signature assets, its languages | 37% (7/19) | 100% (8/8) | 88% (7/8) | 0 |

Full tables in `results/results.md`.

## By language

| language | ecdsa-scan 0.1.1 |
|---|---|
| c | 0% (0/19) |
| go | 21% (4/19) |
| java | 0% (0/25) |
| javascript | 20% (4/20) |
| python | 22% (5/23) |
| rust | 0% (0/18) |

## False positives

None, in `results/` and in `results-signature/`.

6 of 6 documents were schema-valid. No document pointed at a file outside its project.
