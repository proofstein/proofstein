# 2026-08-23T1519Z, holdout

Holdout companion to `runs/2026-08-23T1519Z-public/`. **Fresh seed, not published.**

| | |
|---|---|
| corpus commit | `49c979d3e8a3b0f7ef063ea89d61cea5c30ea889` (templates the variants derive from) |
| assets | 124 |
| rule | detection is **file + algorithm + layer** (METHODOLOGY.md §3.3) |
| cdxgen | 12.8.2 |
| pqprobe-static | 3.6.0 |

## Scores

| tool | scored assets | all |
|---|---|---|
| cdxgen 12.8.2 | 124 | 5% (6/124) |
| pqprobe-static 3.6.0 | 124 | 96% (119/124) |

Identical to the public corpus scored under the same tables, for both tools. The
detection tables match cell for cell, by language and by layer.

One figure did move. pqprobe-static made 204 evidence claims here against 205 on
the public corpus, so under the same tables its component precision reads 73%
rather than 72%. Its recall, its per-layer rates and its claim precision are
unchanged. One claim
fewer on a relocated file is the size of difference the transforms produce; it is
recorded here rather than rounded away, because a holdout that is only ever
reported as "identical" is not being read closely enough to be worth running.

These figures are scored under the judgement tables of 2026-08-23. The run's
documents are withheld, so it has not been scored under entries 14 to 16, as
its public companion has.

## Seed and CBOMs

The seed was passed explicitly on the command line, is held by the maintainer,
and appears nowhere in this repository: not in this manifest, not in the
generated ground truth, which is gitignored and deleted after the run. It is
**not** any template default in `corpus-src/*/proofstein.json`; those are spent
values that `generate-holdout.py` falls back to when no `--seed` is given.

The CBOMs are withheld under METHODOLOGY.md §6 and archived privately. Their
SHA-256 digests are committed in `manifest.json`, so a reviewer can re-score
unaltered documents against a commitment fixed before anyone could check it.
`tools/withhold-cboms.py --verify` confirms an archive against them.

## What this run supports

An identical public and holdout score is a robustness result: the transforms
change line numbers, symbol names, file locations and config ordering, and no
tool's score moved.

What this may be cited *as* is bounded by
[docs/pending-review.md](../../docs/pending-review.md) entry 7, which is open.
This is a blind holdout, fresh unpublished seed and withheld documents, so it is
not excluded from generalisation claims the way an exposed one is.
