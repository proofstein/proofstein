# 2026-11-24T1156Z, ecdsa-scan, public corpus

|  |  |
|---|---|
| date | 2026-11-24T11:59:58Z |
| corpus commit | `f366ff5`, tree clean |
| assets | 131 |
| kind | ecdsa-scan, scored outside the main table |

## How each tool was run

**ecdsa-scan 0.1.1** (npm tarball `sha512-g2CwpG1YMSXtVfvg0W8D9WW3wnrkYeDTsnuxpYxGvGWFFF3Rj/ca9WsQ06lIglKiZDPn/Wd9v1h4133tx4ua6Q==`, Node v20.19.2) has no CycloneDX output. `converter/ecdsa-scan-cbom.sh` runs it with `--json` over each project in the build image of `tools/build.Dockerfile` (`converter/in-image.sh`), and `converter/to_cbom.py` writes its inventory algorithms and curves as algorithm components and its inventory libraries as library components, at the files it lists, without lines. Its operations and defect findings name no algorithm and are not converted. `raw/` holds the `--json` reports with the `root` and `absolutePath` fields removed by `converter/strip.py`.

`cboms-signature/` holds the same reports converted with `to_cbom.py --signature-only`, which keeps signature algorithms and their curves only; `results-signature/` scores them.

`converter/cuts.py` computes the cuts in the score table: **its languages** are the projects in Go, JavaScript and Python (65 assets); **signature assets** are the planted ECDSA, Ed25519, RSA, RS256, RSASSA-PSS, ML-DSA, SLH-DSA, Falcon, LMS and XMSS algorithm assets (47, 21 of them in its languages). The signature rows take recall from `results/` and precision from `results-signature/`.

## Scores

| cut | detection rate | claim precision | component precision | false positives |
|---|---|---|---|---|
| full corpus | 12% (16/131) | 89% (17/19) | 92% (12/13) | 0 |
| its languages | 25% (16/65) | 89% (17/19) | 92% (12/13) | 0 |
| signature assets | 19% (9/47) | 100% (11/11) | 90% (9/10) | 0 |
| signature assets, its languages | 43% (9/21) | 100% (11/11) | 90% (9/10) | 0 |

Full tables in `results/results.md`.

## By language

| language | ecdsa-scan 0.1.1 |
|---|---|
| c | 0% (0/23) |
| go | 21% (4/19) |
| java | 0% (0/25) |
| javascript | 30% (7/23) |
| python | 22% (5/23) |
| rust | 0% (0/18) |

## False positives

None, in `results/` and in `results-signature/`.

6 of 6 documents were schema-valid. No document pointed at a file outside its project.
