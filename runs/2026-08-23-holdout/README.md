# 2026-08-23, holdout

Holdout companion to `runs/2026-08-23-public/`. **Fresh seed, not published.**

| | |
|---|---|
| corpus commit | `4497df4e34fe422aee686a94d99f605330bab2e4` (templates the variants derive from) |
| assets | 124 |
| rule | detection is **file + algorithm + layer** (METHODOLOGY.md §3.3) |
| cdxgen | 12.8.2 |
| pqprobe-static | 3.5.0 |

## Scores

| tool | all |
|---|---|
| cdxgen 12.8.2 | 5% (6/124) |
| pqprobe-static 3.5.0 | 90% (111/124) |

Identical to the public corpus in both tools, in every layer and every project.

## Seed and CBOMs

The seed was passed explicitly on the command line, is held by the maintainer,
and appears nowhere in this repository, not in this manifest, not in the
generated ground truth, which is gitignored. It is **not** any template default
in `corpus-src/*/proofstein.json`; those are spent values that
`generate-holdout.py` falls back to when no `--seed` is given.

**Disclosure:** this run's seed appeared in a private session transcript held by
the maintainer. It is not in this repository and the holdout's claims stand, the
documents were withheld before the seed was ever written down, and the digests
below fix them. Seeds rotate per run regardless, so it cannot affect a later one.

The CBOMs are withheld under METHODOLOGY.md §6 and archived privately. Their
twelve SHA-256 digests are committed in `manifest.json`, so a reviewer can
re-score unaltered documents against a commitment fixed before anyone could
check it. `tools/withhold-cboms.py --verify` confirms an archive against them.

## What this run supports

An identical public and holdout score is a robustness result: the transforms
change line numbers, symbol names, file locations and config ordering, and
neither tool's score moved.

What it may be cited *as* is bounded by
[docs/pending-review.md entry 7](../../docs/pending-review.md), which is open.
This run is a blind holdout, fresh unpublished seed, withheld documents, so
unlike the 2026-07-28 run it is not excluded from generalisation claims. Entry 7 remains
the record of where that line is drawn and who drew it.
