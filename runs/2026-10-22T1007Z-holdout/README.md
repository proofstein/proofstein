# 2026-10-22T1007Z, holdout

Holdout companion to `runs/2026-10-22T1005Z-public/`. **Fresh seed, not published.**

| | |
|---|---|
| corpus commit | `c071f75`, tree clean (templates the variants derive from) |
| assets | 124 |
| rule | detection is **file + algorithm + layer** (METHODOLOGY.md §3.3) |
| judgement tables | as of docs/pending-review.md entry 18 |
| cdxgen | 12.8.2, by the pinned image digest |
| pqprobe-static | 4.0.2, commit `51119c4` |

## Scores

| tool | holdout 2026-10-07T2249Z | holdout 2026-10-22T1007Z |
|---|---|---|
| cdxgen 12.8.2 | 5% (6/124) | 5% (6/124) |
| pqprobe-static | 96% (119/124), 3.8.2 | 96% (119/124), 4.0.2 |

| tool | claim precision | false positives |
|---|---|---|
| cdxgen 12.8.2 | 20% (4/20) | 0 |
| pqprobe-static 4.0.2 | 68% (131/193) | 0 |

Identical to the public companion for both tools: the detection tables match
cell for cell, by language and by layer, and pqprobe-static misses the same five
plants, the layer-3 AES-GCM wrappers. It made 193 evidence claims here and 193
on the public corpus, with 131 credited on each, so its claim precision reads
68% on both.

## What this run checks

pqprobe-static 4.0.2 carries rules written after its maintainer saw a scored
result on an external evaluation corpus: call sites now carry the operation
performed, a JCA call whose algorithm is an identifier is a call site, and an
occurrence is a line of use rather than a line that names an algorithm. This run
is the check on those rules: on variants with names, file locations, line
numbers and configuration the rules were not written against, the tool scores
what it scores on the public corpus, with no false positive.

What this may be cited *as* is bounded by
[docs/pending-review.md](../../docs/pending-review.md) entry 7, which is open.
This is a blind holdout, fresh unpublished seed and withheld documents.

## Build

Build verification (METHODOLOGY.md §8 step 4) was not performed, as for the
public companion; both generators scored here read source without building it.

## Seed and CBOMs

The seed was passed explicitly on the command line, is held by the maintainer,
and appears nowhere in this repository: not in this manifest, not in the
generated ground truth, which is gitignored and was removed from the working tree
after the run. It is **not** any template default in `corpus-src/*/proofstein.json`.

The CBOMs are withheld under METHODOLOGY.md §6 and archived privately. Their
SHA-256 digests are committed in `manifest.json`, so a reviewer can re-score
unaltered documents against a commitment fixed before anyone could check it.
`tools/withhold-cboms.py --verify` confirms an archive against them.
