# 2026-10-22T1005Z, public corpus

pqprobe-static 4.0.2 against the control. The other generators of the
2026-10-07T2218Z run were not re-run: nothing about them changed, and that run
remains the complete multi-tool table.

| | |
|---|---|
| corpus commit | `c071f75`, tree clean |
| assets | 124 |
| rule | detection is **file + algorithm + layer**; the line is recorded and reported, never scored (METHODOLOGY.md §3.3) |
| judgement tables | as of docs/pending-review.md entry 18 |
| cdxgen | 12.8.2, the control, held at the same version across every run |
| pqprobe-static | 4.0.2, commit `51119c4`, built from the `v4.0.2` tag |

## Scores

| tool | scored assets | all | claim precision | false positives |
|---|---|---|---|---|
| cdxgen 12.8.2 | 124 | 5% (6/124) | 20% (4/20) | 0 |
| pqprobe-static 4.0.2 | 124 | 96% (119/124) | 68% (131/193) | 0 |

Full tables in `results/results.md`.

| language | cdxgen | pqprobe-static |
|---|---|---|
| c | 0% (0/19) | 95% (18/19) |
| go | 0% (0/19) | 100% (19/19) |
| java | 8% (2/25) | 96% (24/25) |
| javascript | 15% (3/20) | 95% (19/20) |
| python | 4% (1/23) | 96% (22/23) |
| rust | 0% (0/18) | 94% (17/18) |

## Against 3.8.2

Detection is unchanged cell for cell from `runs/2026-10-07T2218Z-public/`: 119
of 124, the same five misses, the layer-3 AES-GCM wrappers in five of the six
languages. Claim precision moves from 62% (126/204) to 68% (131/193): eleven
fewer claims and five more credited. That is the change in what an occurrence
is since 3.8.2. A comment that names an algorithm no longer gives a line, and a
bare name in code locates once per file when the file has no call site for
that family, so the claims that were never at a plant are gone and the ones
that are sit on the call. The tool's `cryptoFunctions` now state what each call
site was seen to do rather than what the algorithm can do; the scorer does not
read that field.

## How each tool was run

**cdxgen** writes CycloneDX itself and is invoked through the pinned image, as in
every run.

**pqprobe-static** writes CycloneDX itself: `pqprobe-static --output cbom scan .`
from the project root, exit 1 accepted as "findings present". The binary path
came from `PQPROBE_STATIC_BIN`; the manifest records the resolved path and its
sha256.

## False positives

Neither tool was charged any. pqprobe-static has three unmatched reports, at
real locations with no planted asset, uncharged under the corpus rule; cdxgen
has two. All documents were schema-valid, and none pointed at a file that is not
in the project.

## Not in this run

cryptoscan, cbomkit-theia, Opengrep and CodeQL: see 2026-10-07T2218Z.
