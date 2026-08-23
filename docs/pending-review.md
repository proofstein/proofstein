# Governance ledger

**Archived run material.** Entries below cite scoring runs from 2026-07-27,
2026-07-28 and 2026-08-01. Those run directories are not in this repository:
they were scored under earlier rules and against earlier corpus states, and the
tree carries one run at a time. They are archived outside it with a SHA-256
manifest, and their effect tables are reproduced inline in the entries that
depend on them, so no entry needs the removed directory to be readable.


Every judgement call that could move a score, recorded so a reviewer can read the
decisions without reading the diffs. Proofstein is maintained by a party that
also ships a scored tool; this file is where that conflict is made legible.

**Review model.** External review is invited. The Software Engineering Group at
the University of Bern may be the right place to start, though no approach has
been made yet. Entries marked OPEN are
what a reviewer is asked to decide; entries marked CLOSED record a decision
already taken and the evidence for it.

| # | Status | Subject |
| --- | --- | --- |
| 1 | CLOSED | Structure version numbers read as key sizes |
| 2 | CLOSED | Detection is file + algorithm + layer; line is not scored |
| 3 | CLOSED | Dependency components ingested for layer five |
| 4 | OPEN | Ground truth expected a key algorithm behind password encryption |
| 5 | CLOSED | Layer-1 accepted-location marker, now inert |
| 6 | CLOSED | Superseded by entry 8 |
| 7 | OPEN | What a published run may be cited as evidence of |
| 8 | CLOSED | Allowance scoping; charges the maintainer's own tool |
| 9 | OPEN | Falcon negative case: placement and instrument |
| 10 | OPEN | XMSS and LMS plants: build route |
| 11 | OPEN | LMS negative case: placement and instrument |
| 12 | OPEN | ML-DSA, SLH-DSA and Falcon plants |

Entries 9 and 11 raise the same question and should be reviewed together.

## 1. Structure version numbers read as key sizes (CLOSED, `3e72e73`)

**Prompted by:** pqprobe-static, whose PKCS#8 and PKCS#12 names carry format
version digits.

The parameter-contradiction rule treated any digit in an algorithm name as a
size claim, so `RSA private key (PKCS#8)` was read as contradicting a planted
RSA-2048, denying a correct detection and charging a false positive for the same
component.

**Effect:** raises pqprobe-static. cdxgen supplies no line numbers for the
affected assets and cannot score either way, so the change benefits one tool in
practice while being uniform by construction.

## 2. Detection is file + algorithm + layer (CLOSED)

**Resolved: a detection is file + algorithm + layer. The line is recorded and
reported, never scored.** METHODOLOGY §3.3 states the rule; `proofstein/scoring.py`
implements it.

The original question: pqprobe-static reports the planted ML-KEM asset at its
import statement, eleven lines above the planted call site, and file-and-line
matching scored it missed. Should an import location satisfy a call-site plant?

The rationale is one sentence: **an import and the call site it enables assert
the same inventory fact.** A CBOM answers "which algorithms does this file use".
A generator that names the right algorithm in the right file has answered it, and
scoring it as a miss measured reporting granularity rather than detection.

The argument recorded against, that accepting imports collapses L1 toward L2,
is answered by the layer half of the rule rather than by the line. Layers stay
distinct because a dependency component may satisfy only a layer-5 plant, and
because every layer's plant must still be lexically identifiable on its own line,
which `tests/test_corpus_integrity.py` enforces.

**This raises the maintainer's own tool's score, and the numbers are published
with the change rather than after it.** The re-score and its causes are in the
run notes alongside this entry. Three of the six gains are the maintainer's tool;
the rule is uniform and applies to every generator scored since.

**Effect on the other tool, measured on identical documents.** The re-score above
covers pqprobe-static. cdxgen's effect was established later, and separately,
because it is the tool the rule change turns out to matter most for.

The 2026-08-23 run's six cdxgen documents, scored twice against the same 124-asset ground
truth with nothing changed but the rule:

| rule | cdxgen |
| --- | --- |
| file + line + algorithm (the 2026-07-27, 2026-07-28 and 2026-08-01 runs) | 0/124 |
| file + algorithm + layer (current) | **6/124** |

cdxgen emits no line numbers, so requiring the line was the whole of its zero.
This is a controlled measurement, not an inference: same generator, same pinned
version, same corpus, same documents on disk.

**A prediction recorded here because it was wrong.** When this rule was settled,
the maintainer wrote in the repository README that cdxgen's zero would survive
the change, on the reasoning that no cdxgen component resolves to a planted file.
That was asserted without running cdxgen and it is false: `properties[].SrcFile`
resolves for six assets across java, javascript and python. The claim stood in
the README until the 2026-08-23 run measured it. It is recorded because the failure mode is
the one this ledger exists to catch: a maintainer reasoning about a competing
tool's score instead of measuring it, in the direction that flattered their own.

**The guardrail it could have cost, and did not.** Removing the line from
detection also removed it from what made a *claim* correct, which would have let
a generator spray forty lines per file and be credited for all forty.
`tests/test_scoring.py::test_shotgun_packed_into_few_components_still_loses`
caught exactly that when the rule was first applied. A credited claim is now one
`(component, file)` pair while the denominator still counts every distinct
`(component, file, line)` claim, so the shotgun is credited once and charged
thirty-nine times. Claim precision prices guessing as well after the change as
before it.

Entry 5 was entangled with this one and should be re-read against the settled
rule.

## 3. Dependency components ingested for layer five (CLOSED)

**Prompted by:** pqprobe-static, whose own trace contradicted its score. It
emitted `library` components for dependencies it had genuinely found, and layer
five read 0/7 anyway.

`is_crypto_component` admitted a component only if its type was
`cryptographic-asset` or it carried `cryptoProperties`. CycloneDX models a
dependency as a `library` component with neither, so every correct layer-five
answer was discarded before matching. Demonstrated by hand-writing the document
a correct tool should emit for `ledger-svc`'s planted dependency: it scored
0/1, and changing one field to mislabel it as a cryptographic asset scored 1/1.
The scorer was measuring vocabulary compliance, and it paid for the wrong answer.

`library` and `framework` components without `cryptoProperties` are now ingested
as dependency-kind: eligible to satisfy a layer-five plant, and excluded from
crypto-claim accounting in both directions, so an SBOM listing eighty packages
gains no crypto claims and is charged no phantom algorithms for them. A
component that declares `cryptoProperties` is a crypto claim whatever its type,
so relabelling cannot buy exemption.

**Effect, measured on both stored runs before this was committed:**

| run | tool | overall | layer 5 | crypto claims | false positives |
| --- | --- | --- | --- | --- | --- |
| one | cdxgen | 0/108 → 0/108 | 0/7 → 0/7 | 22 → 22 | 0 → 0 |
| one | pqprobe-static | 20/108 → 20/108 | 0/7 → 0/7 | 43 → 43 | 0 → 0 |
| two | cdxgen | 0/108 → 0/108 | 0/7 → 0/7 | 22 → 22 | 0 → 0 |
| two | pqprobe-static | 49/108 → 54/108 | **0/7 → 5/7** | 78 → 78 | 0 → 0 |

**This raises the maintainer's own tool and nothing else, and the reason is not
the one predicted.** The expectation when the change was proposed was that
cdxgen would gain layer five, since it emits far more `library` components than
pqprobe-static does. It gains nothing, because its dependency components carry
almost no location evidence: 0 of 82 in `sealbox`, 1 of 8 in `session-broker`,
0 of the rest. A layer-five plant is matched on manifest file and line, and
cdxgen does not say where it found a dependency.

That is a capability difference rather than a labelling one, which is the
distinction the fix was meant to expose. A reviewer should nonetheless treat
"uniform by construction, benefits one tool in practice" as the recurring shape
of these three entries, and weigh it accordingly.

**Residual, on the tool side not the scorer:** pqprobe-static still misses two
of seven. `ledger-svc/pom.xml:26` because Maven splits `groupId` and
`artifactId` across lines and its line-attribution searches for the composite
identity as a literal substring, then discards findings with no line.
`tinyattest/conanfile.txt:5` because Conan is not a recognised manifest format
at all. Both are pqprobe defects and are not addressed here.

## 4. Ground-truth erratum: the PKCS#12 keystore asked an unanswerable question (OPEN)

**Category:** ground truth, not scorer. Nothing in `proofstein/` changed.

**Prompted by:** pqprobe-static reporting `PKCS#12 keystore` at the keystore
file, with the right asset type and a line number, and scoring as a miss.

The layer-6 keystore asset expected the algorithm of the key *inside* the
container, `ECDSA-P256`. The inner key sits behind PKCS#12 password-based
encryption. No static scanner can name it without the password, so the
expectation was unanswerable by construction: a tool could identify the file,
the container format and the asset type correctly and still be scored wrong.
That is a defect in the ground truth, not a detection failure.

The askable asset is the container. `java-l6-keystore` now expects `PKCS#12`
at that file as `related-crypto-material`; the inner-key expectation is removed
from the denominator. The asset count is unchanged at 108: the container
remains one scorable asset, it is simply now asked a question that has an
answer.

**Uniform application:** any tool that identifies the container scores it.
There is no keystore-specific code path; the change is one field in
`corpus-src/java/ledger-svc/proofstein.json`, from which
`ground-truth/ledger-svc.json` and the holdout equivalent are regenerated.

**Effect, measured across both stored runs and the holdout:**

| run | tool | overall | layer 6 | other layers | FP |
| --- | --- | --- | --- | --- | --- |
| one | cdxgen | 0/108 → 0/108 | 0/17 → 0/17 | unchanged | 0 → 0 |
| one | pqprobe-static | 20/108 → 20/108 | 6/17 → 6/17 | unchanged | 0 → 0 |
| two public | cdxgen | 0/108 → 0/108 | 0/17 → 0/17 | unchanged | 0 → 0 |
| two public | pqprobe-static | 54/108 → **55/108** | **16/17 → 17/17** | unchanged | 0 → 0 |
| two holdout | cdxgen | 0/108 → 0/108 | 0/17 → 0/17 | unchanged | 0 → 0 |
| two holdout | pqprobe-static | 54/108 → **55/108** | **16/17 → 17/17** | unchanged | 0 → 0 |

**This raises the maintainer's own tool's layer-6 row and nothing else.**
Two rows moved out of six; no layer other than 6 changed in any row.

cdxgen gains nothing, and the reason is worth stating because it is not
labelling. cdxgen *does* report the keystore file, as `certificate`, in both
runs, but with no line number, as with every component it emits, so it cannot
satisfy a file-and-line rule regardless of what the expectation says.
pqprobe-static's run-one build did not report the container at all; only the
e4cbaf5 build does, which is why the 2026-07-27 run is unmoved for both tools.

**Residuals a reviewer should weigh.** Naming the expectation `PKCS#12` inherits
two matcher behaviours that were not introduced here and are not fixed here,
because both would require changing `_TOKEN_ALIASES` or `_FAMILY_MARKERS`, which
§9.1 puts behind review:

* `PKCS#8` satisfies a `PKCS#12` expectation. Neither name carries a family, so
  matching falls back to token intersection and they share the bare `PKCS`
  token. A tool reporting a PKCS#8 key at the keystore file would be credited.
* `PFX`, the other standard name for the same container, does *not* satisfy it.
  A tool using that spelling is penalised for the spelling.

Neither is live today, since the only tool reaching that file with a line number
names the container correctly, but both are the naming-convention failure the
methodology says it exists to avoid, and both point at the same missing family
marker.

## 5. A layer-1 accepted-location marker is inert (CLOSED)

**Resolved by entry 2, not by a decision about this marker.**

The entry recorded that `sealbox/src/identity.rs` carries a `+rust-l1-ed25519`
accepted-location marker on an import line, for a **layer 1** asset whose plant
is the call site 18 lines below, the only layer-1 asset with one. Its neighbour
`rust-l1-ecdsa` has no marker, so of two algorithms both reported at their import
lines, one was credited and one was not. The entry declined to correct it because
the substantive question was the same as entry 2, and deciding it here would have
decided entry 2 by the back door.

Entry 2 is now settled the other way round: **a detection is file + algorithm +
layer, and the line is not scored.** Accepted-location markers exist to widen
*line* matching, so the exemption this marker granted is now the uniform rule.
The asymmetry it recorded is gone, not because the marker was corrected, but
because its neighbour got the same treatment.

**Verified rather than argued.** Removing the marker and re-scoring changes
nothing: 111/124 with it, 111/124 without, zero false positives either way. Under
the old rule the same removal cost one asset in every stored run.

### Status of all twelve markers

Not removed. A marker whose accepted location is in the same file as its plant is
now inert, and ten of the twelve are. Deleting inert annotations would be churn
that changes no score and loses the record of why each was added.

**Two are still live**, and should not be removed: `beacon-relay/go-l3-wrapper`
and `tinyattest/c-l3-wrapper` accept a location in a *different file* from their
plant, so they widen which file counts, which file-level matching does not
subsume. Both are layer-3 wrappers, which is the documented purpose of the
marker.

Anyone reading a same-file marker should now read it as a historical note about
where the asset can also be observed, not as an active exemption.

### Correction to the entry-2 re-score note

The run notes for the entry-2 change list `rust-l1-ecdsa` among the four assets
gained, with the cause given as a line agreeing at one occurrence while the name
agreed at another. That describes the `located` diagnostic, not the cause. The
cause is the one this entry documents: `pqprobe-static` reports ECDSA-P256 at its
import line, and under file-level matching that report now counts. It is the
asset this entry was written about.

## 6. A corpus-wide allowance absolved five fabricated findings (CLOSED, 2026-08-01)

**Prompted by:** the 2026-08-01 run, comparing the 2026-07-28 run's precision column against run
two's own CBOMs.

**Closed by entry 8.** The cause named in the original text of this entry was
wrong: it attributed the absolution to the `unmatched` rule. The `unmatched`
rule was not reached. The body below is the corrected mechanism; the effect and
the discovery are as first recorded.

The 2026-07-28 run charged `pqprobe-static` zero false positives. The same documents
carried five high-severity `DES` findings across four projects, every one of
them a substring match on the word "decides" in a config-file comment. The
corpus contains no DES. `pqprobe-static` exits non-zero on high severity, so
each of these failed a build over a prose comment. v3.1.0 emits none of them,
having fixed it as a vendor-side defect, which is how it was found.

The absolution came from `KNOWN_UNPLANTED` in `score.py`. `DES` is listed there,
justified by `ledger-svc/deploy/jvm.options`, which names it as a *disabled*
algorithm. The list carried no scope, so the entry applied to all six projects.
Every DES claim was therefore credible by construction, the phantom-algorithm
check never fired, and the reports fell through to `unmatched`, where they were
displayed and not charged.

The distinction matters for what gets fixed. The `unmatched` rule is sound. The
defect was an allowance written for one file and applied to a corpus, in a table
that was not listed as a judgement table and whose effect is invisible by
construction: an over-broad entry produces no entry in any column, only an
absence in one.

Fixed in entry 8, which records the per-run effect.

## 7. An exposed holdout, and what it may still be cited for (OPEN)

**Prompted by:** the 2026-08-01 run, deciding whether to commit its own holdout CBOMs.

METHODOLOGY.md §6 limits published holdout material to the scores and the
transform description. The 2026-07-28 holdout published more than that: its
README records the seed `20260728`, and its `cboms/` directory was committed,
carrying 76 matched source lines across 53 of the variants' file paths. The
inputs are regenerable from the seed and partly readable from the documents.
That run is not a blind holdout.

The 2026-08-01 run withholds its CBOMs instead, archiving them privately and committing
their SHA-256 digests in the manifest (`tools/withhold-cboms.py`), so that a
reviewer can verify and re-score them while the public holds a commitment fixed
before anyone could check it.

Three decisions. The third is open.

1. *Do not delete the 2026-07-28 run's material.* Deletion does not unpublish it: it is in
   git history and in every clone. **Decided.**

2. *Mark it.* Done, in that run's README and in the 2026-08-01 run's. **Decided.**

3. *Decide what an exposed holdout may still be cited for.* The 2026-07-28 run's holdout
   scored exactly what its public corpus scored, in every layer and every
   project. That is still a real measurement of robustness to layout, naming and
   line-number changes, because the transforms were applied whether or not their
   derivation was later published. What it cannot support is the claim the
   holdout exists to support (that the tool did not learn *this* corpus)
   because a tool author with the seed could regenerate the variants.

   The 2026-08-01 run's position is that the 2026-07-28 run's holdout is **excluded from cross-run
   generalisation claims** and retained as a robustness measurement. That line is
   drawn by the maintainer, about a run of the maintainer's own tool, and
   discards a favourable result. A reviewer may hold that an exposed holdout
   supports nothing at all, or that it supports more than this. **Undecided
   pending review.**

**Effect on published scores: none.** No score in any run changes. What changes
is what the 2026-07-27, 2026-07-28 and 2026-08-01 runs may be cited as evidence *of*, which is not
something the results tables record and is exactly why it is written down here.

## 8. Substring matching in the scorer, and an unscoped allowance (CLOSED, 2026-08-03)

**Category:** scorer and judgement table. **Closes entry 6.**

**Prompted by:** external tool output. `pqprobe-static` v3.1.0's release notes
reported fixing a substring match that read the letters `des` inside "decides",
"nodes", "provides" and "description". Checking whether Proofstein had caught it
established that it had not, and that Proofstein had the same class of defect in
its own matcher.

### Two defects, one class

**The allowance.** `KNOWN_UNPLANTED` lists algorithms that exist in the corpus
without being planted, so that reporting one is not charged. `DES`, `RC4`, `MD5`
and `SSLv3` are on that list because `ledger-svc/deploy/jvm.options` names them
as disabled algorithms. The list carried no scope, so the entry earned by one
file in one project forgave those names anywhere in any project. This is what
absolved the 2026-07-28 run's five fabricated DES findings, not the `unmatched` rule named
in entry 6.

Entries are now scoped to the project and file that justify them. A tool
reporting the disabled list at `jvm.options` is still not charged. A tool
reporting DES in a Rust comment is. A report carrying no resolvable location
keeps the allowance, because failing to say where is already measured in the
evidence table and should not be priced twice.

**The matcher.** Family markers were matched as substrings of the
separator-stripped name, which is what makes `ML-KEM-768` and `MLKEM768` the same
thing and what also made `universal-hash` contain RSA, `Caesar` contain AES,
`peer-mtls-key.pem` contain TLS, `SHA-384` contain SHA-3, and every `ECDSA`
report also claim DSA. Markers are now anchored to token boundaries. Weak
ciphers whose names are ordinary words are matched only as complete tokens.

`SSL` became a family distinct from `TLS` in the same change: without it, a
report of `SSLv3` carried no family, so claiming it where none exists could not
be charged, and the compatibility check fell through to bare token overlap where
`SSLv3` and a planted `TLSv1.3` match on the shared `3`.

### Effect

All five stored scorings re-run against their stored CBOMs. The 2026-08-01 run's holdout
was re-scored from the private archive after `tools/withhold-cboms.py --verify`
confirmed all twelve documents against their committed digests.

| run | tool | recall | false positives | name-only |
| --- | ---- | ------ | --------------- | --------- |
| one | cdxgen | 0/108 → 0/108 | 0 → 0 | 26 → 25 |
| one | pqprobe-static | 20/108 → 20/108 | 0 → 0 | 65 → 65 |
| two public | cdxgen | 0/108 → 0/108 | 0 → 0 | 26 → 25 |
| two public | pqprobe-static | 55/108 → 55/108 | **0 → 4** | 101 → 101 |
| two holdout | cdxgen | 0/108 → 0/108 | 0 → 0 | 26 → 25 |
| two holdout | pqprobe-static | 55/108 → 55/108 | **0 → 4** | 101 → 101 |
| three public | cdxgen | 0/108 → 0/108 | 0 → 0 | 26 → 25 |
| three public | pqprobe-static | 91/108 → 91/108 | 0 → 0 | 106 → 106 |
| three holdout | cdxgen | 0/108 → 0/108 | 0 → 0 | 26 → 25 |
| three holdout | pqprobe-static | 91/108 → 91/108 | 0 → 0 | 106 → 106 |

**Recall is unchanged in every run, every layer and both tools.** No detection
was gained or lost. The false-positive column moves in the 2026-07-28 run only, and the
only other movement is one cdxgen name-only diagnostic per run, a spurious
family match removed.

**Four false positives, five findings.** The false-positive column counts
components, not occurrences. The 2026-07-28 run's four charged components carry five DES
occurrences between them, because `vaultkeeper` reported one component at two
locations. Both numbers are correct and they count different things.

### Direction

This is the first entry in this list whose correction charges the maintainer's
own tool rather than crediting it: `pqprobe-static` goes from a clean sheet to
four false positives in the 2026-07-28 run, and `cdxgen` is unaffected in every column but
one diagnostic. It was applied rather than queued because the corrected numbers
are the true ones under the rule the benchmark already published, and leaving a
known false clean sheet in place would have been the larger error.

What remains for review is the judgement, not the arithmetic: whether scoping an
allowance to a file is the right shape, whether `_WHOLE_TOKEN_ONLY` holds the
right names, and whether `SSL` should be a family. All three are now listed in
METHODOLOGY §9.1 and carry digests in the run manifest.

### Residual

`score.py::project_file_index` returns an empty file list when a project's
`corpus_path` does not resolve, and scoring proceeds. A holdout scored against a
ground truth whose corpus is not on disk therefore reports 0/108 with a full set
of phantom locations rather than failing. This was hit while re-scoring the 2026-07-28 run's
holdout and diagnosed from the shape of the result. Not fixed here; it is a
usability defect in the scorer's error handling, not a judgement call, and it
belongs in a change of its own.

## 9. Falcon negative case in `vaultkeeper` (OPEN)

**Prompted by:** `pqprobe-static`, whose bare `falcon` token reported a
post-quantum signature scheme for a Python web framework.

### What was added

`corpus/python/vaultkeeper/src/vaultkeeper/api.py`, a Falcon health and
readiness API for the daemon, and `falcon==4.3.1` in `requirements.txt`. The
module performs, selects and configures no cryptography, and **carries no
ground-truth entry by design**.

No new mechanism was needed. Under METHODOLOGY §4 a component claiming an
algorithm family that appears nowhere in the project's ground truth and holds no
`KNOWN_UNPLANTED` allowance is charged as a **phantom algorithm**, regardless of
location. Falcon appears nowhere in `vaultkeeper`'s ground truth. A generator
reporting an FN-DSA or Falcon asset in this file is therefore charged, and one
that stays silent is not credited either: the file simply produces nothing.

`asset_count` and `layer_counts` are unchanged, because nothing was planted.

### Why the corpus rather than the tool's own tests

`pqprobe-static` already had a unit test asserting the same thing, and a unit
test the maintainer writes against the maintainer's tool is not independent
evidence. Putting the case in the corpus means every scored generator meets it
on the same terms, and the charge is levied by the published rule rather than by
the tool's own author.

The token was withdrawn from source scanning before this entry was written, so
the trap is currently unsprung for `pqprobe-static`. That is the intended
end state, not an argument against the case: the case is what keeps it withdrawn,
and what will charge any generator that adopts the same shortcut.

### Direction

This addition can only lower a score, never raise one: there is no plant to
find, so no tool can gain from it. Like entry 8, it charges the maintainer's tool
rather than crediting it: `pqprobe-static` would have taken a phantom-algorithm
charge here in the state it was in when the case was written.

That direction is why it was applied rather than queued. What remains for review
is narrower than the usual §9.1 question, and is stated here rather than assumed:

1. Whether a negative case belongs in a project that also carries plants, or in
   a project of its own. Mixing them means a generator that fails on `api.py`
   loses points in a project it may otherwise score well on, which is arguably
   the point and arguably a confound.
2. Whether `falcon` should be added to `KNOWN_UNPLANTED` **scoped to this file**
   instead, which would make the file uninformative rather than charged. The
   argument for: the phantom-algorithm rule exists to catch fabricated families,
   and a name collision is not a fabrication. The argument against: the
   inventory consumer cannot tell the difference, and an inventory that reports
   post-quantum capability where there is none is wrong in the direction that
   matters most.

Entry 2 should be read alongside this one. Both turn on how much context a
report needs before it is allowed to assert an algorithm.

## 10. XMSS and LMS/HSS plants in `ledger-svc` and `tinyattest` (OPEN)

**Prompted by:** an audit against `veorq/awesome-post-quantum`, which found that
the corpus tests exactly one post-quantum algorithm. Every post-quantum plant was
ML-KEM. There was no signature plant of any kind, so no score from this benchmark
said anything about post-quantum signatures in either direction.

### What was added

Six assets across two projects, two languages and three layers. The scheme in
each case is stateful hash-based, so the plants are realistic in the role those
schemes actually hold: long-lived seals over records that outlive any rotatable
key.

| Asset | Layer | Where |
| --- | --- | --- |
| `java-l1-xmss` | 1 | Bouncy Castle `KeyPairGenerator.getInstance("XMSS", "BC")` |
| `java-l2-lms` | 2 | `lms_sha256_n32_h10` via a static import of `LMSigParameters` |
| `java-l4-prop-audit-seal` | 4 | `ledger.crypto.audit-seal=XMSS-SHA2_10_256` |
| `c-l1-xmss` | 1 | wolfSSL `wc_XmssKey_SetParamStr`, `XMSS-SHA2_10_256` |
| `c-l1-lms` | 1 | wolfSSL `wc_LmsKey_SetParameters`, two-level `SHA256_M32_H10` |
| `c-l4-conf-record-seal` | 4 | `record_seal = LMS_SHA256_M32_H10` |

`ledger-svc` also gains a documentation claim in its README naming XMSS and
HSS/LMS. That is not an indexed asset, since there is no documentation layer, but
because both families are now planted in that project, a generator reporting them
from the README is *unmatched and uncharged* rather than charged as a phantom.

`asset_count` and `layer_counts` are updated in both ground-truth files.

### Direction

This raises no score by itself and lowers none. It tests a capability that was
previously untested, and the direction it moves any given tool depends entirely
on that tool.

For the maintainer's own tool the honest statement is that it detected neither
family when these plants were written, so the plants were authored against
reference and library documentation rather than against what the scanner already
found. The scanner rules came second and are constrained by the corpus, not the
reverse.

### Dependency route: Conan rejected, source build pinned

METHODOLOGY §6 requires that a variant which does not compile is not published.
The Java plants need no new dependency: `bcprov-jdk18on 1.79` already ships
`org.bouncycastle.pqc.crypto.xmss` and `.lms`, and the project already depends on
it.

The C plant needs wolfSSL, and **the package-manager route is closed.** Both XMSS
and LMS are opt-in at wolfSSL configure time, and the Conan Center recipe exposes
no option for either. Its entire option surface is `shared`, `fPIC`,
`opensslextra`, `opensslall`, `sslv3`, `alpn`, `des3`, `tls13`, `certgen`, `dsa`,
`ripemd`, `sessioncerts`, `sni`, `testcert`, `with_curl`, `with_quic`,
`with_experimental`, `with_rpk`. No combination of those produces a wolfSSL that
can build this project, so the precondition as first written could not be met.

A second obstacle ruled out the version originally pinned: with wolfSSL 5.7.x
enabling LMS and XMSS together was reported not to work, and `tinyattest` needs
both schemes in one binary.

**Resolved by dropping Conan for this dependency and building from source.**
`tools/build-all.sh` now fetches and builds wolfSSL **5.9.1** with
`./configure --enable-xmss --enable-lms`, caches it under the build root, and
points `CPPFLAGS`, `LDFLAGS` and `LD_LIBRARY_PATH` at the result.
`conanfile.txt` no longer mentions wolfSSL, and `tinyattest`'s Makefile honours
`LDFLAGS` so the harness can direct the link. 5.9.1 ships LMS and XMSS as native
wolfCrypt implementations rather than integrations of external reference code,
which is what makes enabling both in one build dependable.

The alternative, rewriting the case against Cisco hash-sigs or xmss-reference,
was rejected. It would replace `wc_XmssKey` and `wc_LmsKey` with
reference-implementation spellings and lose the mainstream-library evidence,
which is the thing this case exists to test.

### Build and API verified end to end against v5.9.1-stable

The recipe in `tools/build-all.sh` is confirmed working as written: `autogen.sh`,
then `./configure --enable-xmss --enable-lms`, both reporting yes including the
wolfCrypt implementations, a successful build, and **both schemes coexisting in
one library**: the 5.7.x restriction that ruled out the original pin is gone in
5.9.1. `tinyattest` compiles, links and runs to rc=0 against the built library.

The host requirement is therefore verified rather than guessed: **autoconf,
automake and libtool must be present**, because the GitHub source archive ships
no `configure`.

**Do not "simplify" this to CMake.** `WOLFSSL_XMSS` exists as a CMake option in
5.9.1 but is never wired through to the compile definitions: enabling it produces
an `options.h` with XMSS commented out. It is a dead option, and a build switched
to CMake would lose XMSS silently while appearing to ask for it. This is worth
reporting upstream.

Two corrections to `src/seal_longterm.c` came out of the validation.

**Export functions.** `wc_LmsKey_ExportPub` and `wc_XmssKey_ExportPub` are
key-to-key copies, `wc_LmsKey_ExportPub(LmsKey *keyDst, const LmsKey *keySrc)`,
not buffer serialisers. The file called them with a buffer and a length pointer,
which is `wc_LmsKey_ExportPubRaw` / `wc_XmssKey_ExportPubRaw`. Both call sites now
use the `Raw` form, and the length round-trips through a `word32` local instead of
casting the caller's `size_t *`, which is a different width on a 64-bit target.

**Includes.** `LmsKey` and `XmssKey` are forward declarations in the public
`lms.h` and `xmss.h`; the struct definitions live in `wc_lms.h` and `wc_xmss.h`.
Both keys are stack-allocated, so the implementation headers are required, and
they are what wolfSSL's own tests and benchmarks include. Confirmed as written:
`WC_LMS_PARM_L2_H10_W8` (`lms.h:104`, value 19),
`wc_LmsKey_SetLmsParm(LmsKey *, enum wc_LmsParm)` and
`wc_XmssKey_SetParamStr(XmssKey *, const char *)`.

### What the include change did to detection, and why it is asymmetric

Measured rather than assumed, because the question is the one entry 2 turns on.

Adding `wc_xmss.h` produces **one extra XMSS occurrence** at the include line.
Adding `wc_lms.h` produces **no LMS finding at all**, only the library reference
that every wolfSSL include line already produced.

The asymmetry is the token design working as intended. `xmss` is a bare token, so
it matches an include path. `lms` is not, and the anchored forms (`wclmskey`,
`wclmsparm`, the parameter sets) do not match `wc_lms.h`, because the header
stem is `wclms` and the token is `wclmskey`.

Nothing about ground truth follows from this. The extra XMSS occurrence attaches
to a component that is already planted in this project, so it is unmatched and
uncharged under METHODOLOGY §4, not a phantom. Entry 2 stays untouched: the
question there is whether an import location may *satisfy* a call-site plant, and
here the call-site occurrences are present regardless.

`c-l1-xmss` moved to line 28 and `c-l1-lms` to line 87 as the includes and the
export corrections shifted the file. No token changed and the score is unchanged
at 85% (97/114) with zero false positives.

## 11. LMS negative case in `session-broker` (OPEN)

**Prompted by:** the same audit, pre-emptively rather than after a failure.

`corpus/javascript/session-broker/src/lms.ts` is a learning-management roster
client. It performs, selects and configures no cryptography and **carries no
ground-truth entry by design**. The abbreviation it is named for collides with
the signature scheme planted in entry 10.

The mechanism is the one entry 9 established, and needs nothing new: under
METHODOLOGY §4 a component claiming a family absent from the project's ground
truth is charged as a phantom algorithm. Neither hash-based family is planted in
`session-broker`, so a generator reporting one from this file is charged.

`settings.ts` gains two roster fields and `broker.yaml` a `roster` block, so the
module is reached by the same configuration path as the rest of the project
rather than being an orphan file.

### Why this one is pre-emptive

Entry 9 was written after a false positive was observed. This one is written
before, because the collision is predictable from the name alone: `lms` is three
letters, it is a common abbreviation, and any scanner that adds a bare token for
it will match `RHSSO`-shaped identifiers and learning-management code
indiscriminately. The case exists so that the benchmark, not the tool's author,
is what decides whether a bare token is acceptable.

### Direction

Can only lower a score, never raise one: there is no plant to find. Consistent
with entries 8 and 9.

What remains for review is the same question entry 9 raises and does not settle:
whether a negative case belongs in a project that also carries plants, and
whether a scoped `KNOWN_UNPLANTED` allowance would be the better instrument for a
pure name collision. The two entries should be reviewed together.

## 12. ML-DSA, SLH-DSA and Falcon plants (OPEN)

**Prompted by:** the coverage audit, which found the corpus tested one
post-quantum algorithm. Entry 10 added stateful hash-based signatures; this adds
the three stateless post-quantum signature schemes.

Ten assets. Every family reaches at least two languages and two layers:

| Family | Languages | Layers |
| --- | --- | --- |
| ML-DSA | java, javascript, rust | 1, 4, 5 |
| SLH-DSA | java, javascript, python | 2, 4 |
| Falcon | c, java, python | 1, 4 |

Spellings come from Bouncy Castle (`MLDSAParameterSpec`, `SPHINCSPlusParameterSpec`,
`FalconParameterSpec`), `@noble/post-quantum` (`ml_dsa65`, `slh_dsa_sha2_128f`),
the liboqs Python binding (`oqs.Signature("Falcon-1024")`), oqs-provider
(`falcon512` as a config value) and RustCrypto (`ml-dsa` as a declared crate).

**Falcon plants use parameter-set spellings only**: `falcon_512`, `Falcon-1024`,
`falcon512`. The bare-token withdrawal from entry 9 stands; nothing here depends
on it being reversed.

### Direction

Two of the ten were missed on the first scoring run, and both were real gaps the
plants exposed rather than plant errors: SLH-DSA parameter sets were not accepted
as configuration values, and no RustCrypto post-quantum crate was in the
dependency knowledge base. Both were fixed in the scanner, not in the corpus.

That is the intended direction of travel for this entry: the plants were written
from library documentation before the rules existed, so what they measured was
the tool's coverage rather than the author's memory of it.

## 13. Activating sonar-cryptography's rules before scoring it (OPEN)

### The decision

The PQCA `sonar-cryptography` plugin is scored with its three Inventory rules
switched on. That is a configuration change made by the party that also ships
one of the scored tools, in favour of a competitor, and it is recorded here
because a reader is entitled to check that it was not the reverse.

### Why it is needed

The plugin registers one rule per supported language:
`sonar-java-crypto:Inventory`, `sonar-python-crypto:Inventory` and
`sonar-go-crypto:Inventory`. All three ship inactive. They are in no quality
profile, including Sonar way, and SonarQube only runs checks that are active in
the profile applied to the project.

On a stock server the consequence is not an error. The crypto sensor loads and
logs `Sonar Cryptography initialized in context (SONARQUBE)`, the analysis runs,
the post-job runs, and the scan ends:

```
INFO  Executing post-job 'Output generation'
INFO  No cryptography assets were detected. CBOM will not be generated.
INFO  EXECUTION SUCCESS
```

No file is written and the run reports success. Scored as-is, the tool takes a
zero on every language, and nothing in its output distinguishes that zero from a
tool that genuinely found nothing. It was reached first on this corpus, on Java
and on Python, before the cause was found.

`tools/sonar-cryptography-docker.sh` therefore creates a `proofstein-crypto`
profile per language, activates the Inventory rule in it, sets it as the default,
and then reads the rule back to confirm activation. A scan against a server
whose rules are off is refused rather than run, because that scan would succeed
and report nothing.

Only `Inventory` is activated. The plugin also ships `JavaNoMD5use` and
`PythonNoMD5use`, which raise issues rather than contributing to the CBOM.

### Java bytecode

Java is scanned without `sonar.java.binaries`, which makes the analyser warn
about less precise results. The warning was tested rather than assumed:
`ledger-svc` was compiled in a container, and rescanned with `sonar.java.binaries`
pointing at `target/classes` and `sonar.java.libraries` at the resolved
BouncyCastle 1.79 jar.

The result was identical: 27 components and the same 15 distinct
(algorithm, file) pairs, with no name appearing in one run and not the other. The
corpus is therefore scanned unbuilt, as the other two generators scan it.

That is a measurement on this corpus, not a general claim about the plugin. A
project whose cryptography is reached through deeper type inference could well
differ, and anyone rerunning this should re-measure rather than inherit the
conclusion.

### What would change the entry

Upstream putting Inventory into Sonar way, or shipping a profile that contains
it, would make the activation step redundant and this entry historical.
