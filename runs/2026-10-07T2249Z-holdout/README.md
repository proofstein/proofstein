# 2026-10-07T2249Z, holdout

Holdout companion to `runs/2026-10-07T2218Z-public/`. **Fresh seed, not published.**

| | |
|---|---|
| corpus commit | `57324cd`, tree clean (templates the variants derive from) |
| assets | 124 |
| rule | detection is **file + algorithm + layer** (METHODOLOGY.md §3.3) |
| judgement tables | as of docs/pending-review.md entry 17 |
| cdxgen | 12.8.2 |
| pqprobe-static | 3.8.2 |

## Scores

| tool | holdout 2026-08-23T1519Z | holdout 2026-10-07T2249Z |
|---|---|---|
| cdxgen 12.8.2 | 5% (6/124) | 5% (6/124) |
| pqprobe-static | 96% (119/124), 3.6.0 | 96% (119/124), 3.8.2 |

| tool | claim precision | false positives |
|---|---|---|
| cdxgen 12.8.2 | 20% (4/20) | 0 |
| pqprobe-static 3.8.2 | 62% (126/203) | 0 |

Identical to the public companion for both tools: the detection tables match
cell for cell, by language and by layer, and pqprobe-static misses the same five
plants, the layer-3 AES-GCM wrappers. It made 203 evidence claims here against
204 on the public corpus, with the same 126 credited, so its claim precision
reads 62% on both.

The 2026-08-23T1519Z column is scored under the judgement tables of 2026-08-23,
on variants of the corpus as it stood then. Its documents are withheld, so it
has not been scored under entries 14 to 17.

## What this run checks

pqprobe-static 3.8.2 carries a rule written by Proofstein's maintainer after
seeing pqprobe-static's result on the public corpus (docs/pending-review.md
entry 18). This run is the check on that rule: on variants with names, file
locations, line numbers and configuration the rule was not written against, the
tool scores what it scores on the public corpus, with no false positive.

What this may be cited *as* is bounded by
[docs/pending-review.md](../../docs/pending-review.md) entry 7, which is open.
This is a blind holdout, fresh unpublished seed and withheld documents, so it is
not excluded from generalisation claims the way an exposed one is.

## Build

Build verification (METHODOLOGY.md §8 step 4) was not performed. Neither corpus
builds where this run was collected, which holds for its public companion too,
and both generators scored here read source without building it.

## Seed and CBOMs

The seed was passed explicitly on the command line, is held by the maintainer,
and appears nowhere in this repository: not in this manifest, not in the
generated ground truth, which is gitignored and was removed from the working tree
after the run. It is **not** any template default in `corpus-src/*/proofstein.json`.

The CBOMs are withheld under METHODOLOGY.md §6 and archived privately. Their
SHA-256 digests are committed in `manifest.json`, so a reviewer can re-score
unaltered documents against a commitment fixed before anyone could check it.
`tools/withhold-cboms.py --verify` confirms an archive against them.
