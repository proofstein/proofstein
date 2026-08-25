# Methodology

How Proofstein decides whether a CBOM generator found something, and how the
quarterly runs are conducted.

This document is the contract. If a rule here and the code disagree, that is a
bug in one of them; the tests in `tests/` are what keep them together.

---

## 1. What is being measured

A cryptographic asset is **detected** when a generator's CBOM contains a
component that

1. carries evidence pointing at the **file** the asset was planted in, **and**
2. carries a **line number** agreeing with the planted line within the
   tolerance, **and**
3. names an algorithm **compatible** with the planted one.

All three are required. The rule exists because the alternative does not
measure anything: every project in this corpus contains AES-GCM, RSA, SHA-256
and Ed25519, so a generator that emits those four names unconditionally would
score well on any name-matching benchmark while having read nothing.

`results.md` shows what the weaker rules would have claimed, in a table headed
"What weaker matching rules would have claimed". The gap between the first and
last column of that table is the amount of credit a name-only benchmark hands
out for free.

### Not measured, deliberately

* **Whether the generator ran.** A (project, tool) pair absent from the input
  is excluded from every table, not scored as zero. Reporting a tool that was
  never run as having missed everything would be a fabrication.
* **Speed, memory, image size.** BF-CBOM and CBOMbench already record runtime.
* **Whether the *right* CycloneDX asset type was used.** Recorded in the JSON
  output per asset, but not part of the detection rule.

---

## 2. The six layers

Every corpus project plants assets in all six. The layers are the point of the
corpus: they separate a generator that pattern-matches call sites from one that
follows indirection.

| Layer | What it plants | What it distinguishes |
| ----- | -------------- | --------------------- |
| 1 | Direct crypto API call sites | Baseline. A generator that misses these misses everything. |
| 2 | Aliased imports (`import hashlib as digestlib`, `use sha2::Sha256 as ContentHash`, a static import, a `#define`) | Whether identification survives renaming. |
| 3 | Wrapper functions reached through a constructor table | Whether the generator follows indirection or only matches library symbols at the call site. |
| 4 | Config-driven selection (YAML, nginx, JVM properties, Helm values, TOML, `.conf`) | Whether anything outside source files is read at all. |
| 5 | Crypto in a declared dependency that no shipped code calls | Whether the dependency surface is inventoried, and whether the generator can say so without claiming a call site. |
| 6 | Key, certificate and keystore files | Whether non-source artifacts are inventoried. |

Layer 5 is the one to read carefully. The dependency is declared and never
called, so a generator that reports it *with a call-site location* has
hallucinated; one that reports it against the manifest line has it right.

---

## 3. Matching rules in detail

### 3.1 Location

Evidence is read from a fixed set of shapes, applied to **every** tool:

* `evidence.occurrences[].location` and `.line`: the shape the CycloneDX 1.6
  schema defines (`location` is required, `line` is optional).
* `properties[]` entries whose name, after stripping any namespace prefix, is
  one of `SrcFile`, `sourceFile`, `source_file`, `location`, `filePath`,
  `file_path`, `file`, `path`, with the line taken from `line`, `lineNumber`,
  `line_number`, `startLine`, `start_line`.

The second shape exists because cdxgen records the source file in
`properties[].SrcFile` and emits no line number
(observed in BF-CBOM's own `tests/bisq_cdxgen.json`, not a fixture here).
Reading only the spec shape would score that generator at zero for a reason
unrelated to whether it found the asset. Reading both, for everyone, measures
the thing intended.

A generator supplying a file but no line still cannot be credited with a
detection, because there is nothing to check. That outcome is visible in two
places: the `with line` column of the evidence-quality table, and the
`file only` column of the weaker-rules table.

### 3.2 Paths

Reported paths are normalised (separators, leading `./`) and then resolved
against the project's real file list by **longest matching suffix**. A suffix
that matches more than one file is not a resolution.

This exists because BF-CBOM workers clone into a temporary directory
(`common/utils.py:136`), so a generator reporting absolute paths is reporting
paths that cannot match anything literally. The resolution is applied to every
tool. It is a real generosity, and it is why the evidence table reports
`unresolvable paths`: a path that still does not resolve is counted, and if it
is a component's only evidence, it is charged as a phantom location.

### 3.3 Lines are reported, not scored

**A detection is file + algorithm + layer.** The line a generator reports is
recorded, shown in the `file+line, any name` column of the weaker-rules table,
and never part of whether an asset counts as found.

The reason is one sentence: an import and the call site it enables assert the
same inventory fact. A generator that reports ML-KEM at the import statement
eleven lines above the call has answered the question the inventory asks (which
algorithms does this file use) and scoring it as a miss measured reporting
granularity rather than detection. This resolves `docs/pending-review.md` entry 2,
which held the strict reading pending review.

`--line-tolerance` still exists and still defaults to **±2**. It decides the
reported `located` figure, so a run can still show how precisely a generator
places its evidence, and generators that disagree about whether a multi-line
statement is reported at its first or last line are not distinguished by it.

Claim precision is unaffected by the change, deliberately. A credited claim is
one `(component, file)` pair, while the denominator counts every distinct
`(component, file, line)` claim made. A generator naming one algorithm at forty
lines of one file is credited with the one claim it got right and charged for the
thirty-nine guesses, so the shotgun defence in §5 survives a rule that no longer
scores lines.

### 3.3a Accepted-location markers

A plant may declare additional locations where its evidence is accepted, written
`//@PS +<id>` in the template. Under file-level matching most of these no longer
do anything: an alternative location in the same file as the plant is already
covered, and ten of the twelve markers in the corpus are of that kind. They are
kept as a record of where an asset can also be observed, not as active
exemptions.

**Two are still load-bearing, and both are layer-3 wrappers.** A wrapper's caller
frequently sits in a *different file* from the wrapper body, and a marker is the
only thing that makes evidence in that other file count. `beacon-relay`'s
`go-l3-wrapper` and `tinyattest`'s `c-l3-wrapper` each accept a cross-file
location. Widening which file counts is the sole remaining scoring function of
this mechanism.

### 3.4 Algorithms

Names are reduced to token sets with separators removed, so `SHA-256`,
`SHA256` and `sha_256` are the same thing, as are `ML-KEM-768` and `MLKEM768`.

Removing separators is what makes hyphenation irrelevant, and it also removes the
boundaries that distinguish an algorithm name from an ordinary word. Those
boundaries are carried alongside and re-imposed: a family is found only where its
marker begins at a token boundary, or immediately after a digit. The digit case
is what keeps hybrid names such as `x25519mlkem768` working. A marker ending in a
digit may not be followed by another digit, so `SHA-3` is not found inside
`SHA-384`. Without these rules `universal-hash` contains RSA, `Caesar` contains
AES, and every `ECDSA` report also claims DSA.

Weak ciphers whose names are ordinary English words (`DES`, `SEED`, `IDEA`,
`RC2`, `RC4`, `CAST5`, `Camellia`) are matched only as complete tokens, and only
where every other token in the name is a size, a mode qualifier or narration.
`SEED-128-CBC` claims the family; `seed_material` and `seedRandom` do not. The
list is `_WHOLE_TOKEN_ONLY` in `proofstein/matching.py`.

Then:

* A **less specific** report is credited: a planted `AES-256-GCM` is found by a
  report of `AES`. The generator identified the right primitive.
* A **different family** is never credited: `RSA` does not find `AES-256-GCM`.
* A **contradictory parameter within the same family** is not credited:
  `AES-128-GCM` does not find `AES-256-GCM`, and `ML-KEM-512` does not find
  `ML-KEM-768`.
* Algorithms may be identified by OID. `cryptoProperties.oid` is mapped through
  a published table (`proofstein/cbom.py`, `OID_ALGORITHMS`), because cbomkit
  routinely leaves `name` as an opaque `key@<uuid>` and identifies the algorithm
  only by OID.
* Opaque identifiers (`key@<uuid>`, `crypto/certificate/foo.gpg@sha256:...`) and
  placeholder values (`other`, `unknown`, `generic`, `unspecified`) never match
  anything. `other` is a real cbomkit output value; treating it as a wildcard
  would credit it against every plant.

### 3.5 Accepted alternative locations

Some assets carry `accept_locations` in the ground truth: additional places a
generator may legitimately attribute the asset to. An aliased import may be
attributed to the import line or the call line; a wrapper-mediated algorithm may
be attributed to the wrapper body or to the caller. Both are defensible, and
scoring a tool down for picking the other one would measure convention rather
than detection. Accepted locations are part of the published ground truth and
apply to every tool.

---

## 4. False positives

Two categories are charged, and both are unambiguous:

* **Phantom location**: every location the component reports fails to resolve
  to a file in the project.
* **Phantom algorithm**: the component **claims an algorithm family**, and that
  family appears nowhere in the project's ground truth and is not covered by a
  `KNOWN_UNPLANTED` allowance in `score.py` that reaches this project and file.
  Claiming an absent family is a fabrication wherever it is reported, so this is
  charged regardless of location.

  An allowance reaches only as far as what justifies it. `DES`, `RC4`, `MD5` and
  `SSLv3` are allowed at `ledger-svc/deploy/jvm.options`, which names them as
  disabled algorithms, and are charged everywhere else. A report carrying no
  resolvable location keeps the allowance, because failing to say where is
  already reported in the evidence table and is not charged twice. Until
  2026-08-03 these four entries had no scope, which is recorded in
  `docs/pending-review.md` entries 6 and 8.

A component that names no algorithm family at all is **never** charged as a
phantom algorithm. cdxgen names key-file components after the file, as
`relay-key.pem` with `assetType: certificate`, which is a correct report of a real
layer-6 asset, since the algorithm cannot be known without parsing the key. In
the 2026-07-27 run, ten of eighteen false positives charged against cdxgen were of
exactly this kind: an error invented by the scorer, not made by the generator.
Such a component is uninformative rather than false, and the evidence-quality
table already reports that.

Everything else that matched no plant is reported as **unmatched (uncharged)**
and is not held against the tool.

The reason for that restraint: **the corpus ground truth is complete for
planted assets, but not exhaustive of every cryptographic construct in the
tree.** A CSPRNG call, an HMAC, a base64 helper are real and carry no
ground-truth entry. Charging a generator for finding one would penalise a
correct result. `KNOWN_UNPLANTED` names the constructs that are present but
unplanted, so that the phantom-algorithm check stays meaningful rather than
forgiving everything.

This is a known limitation, stated rather than hidden: **Proofstein measures
recall against a known set of plants and a narrow, high-confidence notion of
false positive. It is not a precision benchmark against a fully enumerated
corpus.**

### Precision

Detection rate alone is gameable: a generator claiming every algorithm at every
line of every file would be credited with finding everything. `results.md`
therefore reports precision in two forms.

**Component precision**: components credited over components reported.

**Claim precision**: distinct evidence claims credited over distinct evidence
claims made, where a claim is one `(component, file, line)` triple.

Claim precision is the real check, and component precision alone is not enough.
That was found in review rather than by design: an attacker who packs the
guessing into a *small number of components*, each carrying an occurrence for
every line of every file, keeps every component matching something. Such a
document scored **full recall at 80% component precision with zero false
positives**. Pricing each claim instead drops it to **2.2%**, because it made
7670 claims to earn 19.

Duplicate evidence for one site is deduplicated before counting, so a generator
reporting the same location three times is not treated as having made two wrong
claims.

An honest generator makes roughly one claim per site it found, so its two
precision figures sit close together. A wide gap between them is the signature
of guessing. Both attacks and the honest counterpart are pinned in
`tests/test_scoring.py`:
`test_shotgun_earns_recall_but_loses_precision`,
`test_shotgun_packed_into_few_components_still_loses`,
`test_honest_report_scores_well_on_both_precisions` and
`test_repeated_evidence_for_one_plant_is_not_punished`.

### The line tolerance is a diagnostic, not a dial

`--line-tolerance` no longer affects any score, since §3.3 removed the line from
what a detection requires. It sets the `located` column only. Any value wider
than the default still prints a warning to stderr and is recorded in the header
of both output files, so a run that widened it is identifiable; published runs
use the default.

What stops "file + algorithm" from degenerating into free recall is not the
tolerance. It is claim precision, which prices every distinct
`(component, file, line)` claim while crediting one per `(component, file)`.

---

## 5. Schema validity

Every CBOM is validated against the official CycloneDX 1.6 JSON schema,
vendored unmodified under `schemas/` so scoring needs no network:

* `bom-1.6.schema.json`
* `spdx.schema.json`, `jsf-0.82.schema.json` (its two `$ref` targets)

Validation is reported per tool as a pass rate. It does not affect the detection
rate: a generator that finds everything and emits a schema-invalid document has
still found everything, and a reader should be able to see both facts
separately.

`samples/invalid/` holds three fixtures that must fail: a document missing
`specVersion` with an invalid component type, a non-BOM JSON document, and a
truncated file. `tests/test_schema.py` asserts they are rejected and that a
valid document is accepted, so the validator cannot silently degrade into
approving everything.

---

## 6. Public corpus and holdout

**The two are scored separately and never averaged.**

The public corpus is in the repository: the projects, the plants and the answers
are all published. That is what makes it useful as a development target and what
makes it, over time, a poor measure of generalisation. A tool that improves on
it may have got better at finding cryptography, or may have been tuned to find
*this* cryptography.

The holdout is generated from the same templates by transforms that change the
surface a tool matches on while leaving the cryptography identical:

* a header block shifts every line number,
* wrapper functions, types and import aliases are renamed,
* files move within their package,
* config keys are reordered and, where declared, an algorithm is swapped for a
  different member of its family (`ML-KEM-768` → `ML-KEM-1024`).

Ground truth for a variant is **recomputed from the transformed templates by the
same annotation parser**, never adjusted by hand, so it cannot drift.

`tools/build-all.sh ground-truth-holdout` builds every variant. A variant that
does not compile is not a valid case and is not published.

**A large gap between public and holdout scores for the same tool is the finding
the holdout exists to produce.** It should be reported, not smoothed over.

Holdout inputs are regenerated with a fresh seed before each quarterly run and
are not published with the results. Published holdout material is limited to the
scores, the transform description, and a digest of the generators' output.

**A holdout run's CBOMs are withheld, not committed.** A CBOM carries the file
paths, line numbers and often the matched source lines of what it scanned, so
committing one republishes much of what the seed protects. The documents are
archived privately and their SHA-256 digests are recorded in the run manifest by
`tools/withhold-cboms.py`, which also verifies an archive against them. A
reviewer can confirm the scores against unaltered documents without receiving
the seed.

This rule postdates the 2026-07-28 run, whose holdout published both its seed and its
CBOMs. That run is marked as exposed in its own README and is excluded from
cross-run generalisation claims; see `docs/pending-review.md` entry 7.

---

## 7. Corpus transport

BF-CBOM workers clone the repositories they inspect
(`common/utils.py:136`, `--depth 1`, public URLs only), so orchestrating a run
through it requires the six corpus projects to exist as reachable git URLs. Two
ways work: `file://` remotes produced by `tools/publish-corpus.sh`, or private
repositories under a `proofstein` organisation.

### Generators scan a pristine export, never the working tree

`tools/collect-cboms.py` exports each project with `git archive HEAD` and runs
the generator against that copy.

This is not fastidiousness. Building the corpus leaves `dist/`, `node_modules/`,
`target/` and object files behind, and a generator pointed at that tree reports
cryptography inside compiled output, genuinely present but at paths the ground
truth says nothing about. In the 2026-07-27 run this produced three false positives
charged against cdxgen for correctly finding Ed25519, RSA and SHA-256 in
`dist/identity.js`, the compiled form of a file whose sources are planted.

Exporting from HEAD also matches the intended runner: BF-CBOM workers
`git clone --depth 1` and therefore always see a clean tree
(`common/utils.py:136`). A direct run that scanned a dirty tree would not be
measuring the same thing as an orchestrated one.

**The 2026-07-27 run uses the scorer's raw-directory path**, with each generator invoked
directly against that export and its CycloneDX collected per the filename
convention in the README. That is the lower-friction route and it removes the
runner from the critical path of the first result: a transport problem cannot be
mistaken for a detection problem, and the numbers do not depend on standing up
Redis, Docker and six worker images first.

**The BF-CBOM path is proven separately, once, as an integration test rather
than as the scoring vehicle.** Publish the corpus, point an inspection at the
`file://` URLs, export the bundle, and confirm `./score.py --bundle` produces
the same per-asset verdicts as the raw-directory run over the same generators.
That establishes the two input paths agree; after that, either can carry a
quarterly run.

Both paths are already exercised by tests over a bundle in BF-CBOM's exact
layout (`tests/test_inputs.py`), and both were confirmed to produce identical
scores over the same documents.

---

## 8. Quarterly run procedure

1. **Pin the corpus.** Tag the repository. Every results file records the corpus
   version in its header; a run whose header says `-dirty` is not publishable.

2. **Pin the tools.** Record each generator's exact version and image digest.
   For BF-CBOM-orchestrated runs, record the BF-CBOM version (`VERSION`) and the
   inspection id. For standalone runs, record the CLI invocation verbatim.

3. **Regenerate the holdout** with a new seed:
   `tools/generate-holdout.py --seed <n>`. Record the seed privately; do not
   publish it with the results.

4. **Verify both corpora build.** `tools/build-all.sh` and
   `tools/build-all.sh ground-truth-holdout`. A project that does not build is
   withdrawn from that run, and the withdrawal is recorded.

5. **Run the generators** against both corpora. Either orchestrate through
   BF-CBOM or run each tool directly and collect CycloneDX per the filename
   convention in the README.

6. **Score both, separately:**
   ```
   ./score.py --cboms  runs/<date>/public/  --out results/<date>-public/
   ./score.py --bundle runs/<date>/holdout-bundle.zip --out results/<date>-holdout/
   ```

7. **Publish** `results.md` and `results.json` for both, with a run manifest
   recording corpus tag, tool versions and digests, line tolerance, and which
   (project, tool) pairs were not run and why.

8. **Notify scored vendors** before publication, with their own per-asset
   results, and record any correction. A vendor disputing a result should be
   able to reproduce it from the published artifacts; if they cannot, that is a
   bug in Proofstein.

---

## 9. Conflict of interest

Proofstein is maintained by Ottenheimer GmbH, which also maintains
`pqprobe-static`, a tool in scope for scoring. The safeguards are structural
rather than promissory:

* **No tool-specific logic.** No module on the scoring path may contain a vendor
  name in executable code.
  `tests/test_no_tool_specific_logic.py` parses each of those modules and fails
  the build if a vendor name appears in any identifier or non-docstring string
  literal. Vendor names in docstrings and comments are allowed and encouraged:
  the reason a given evidence shape is supported is exactly that some real
  generator emits it, and that reasoning should be written down.
* **Score is invariant under tool name.**
  `tests/test_scoring.py::test_tool_name_does_not_affect_score` scores the same
  document under several tool names, including `pqprobe-static`, and asserts the
  result never moves.
* **No normalisation privileges.** Every accommodation in §3 (the
  `properties[]` location shape, absolute-path resolution, the OID table, the
  line tolerance, less-specific algorithm names) is documented here, applied to
  every tool, and covered by a test. `pqprobe-static` in particular receives no
  format handling of its own: any conversion from its native output into
  CycloneDX happens in the worker shim, outside this repository, exactly as
  cryptobom-forge converts CodeQL SARIF inside its own worker.
* **Scored, not exempt.** `pqprobe-static` appears in published results on the
  same terms as every other tool, including where it does badly.

A reader who does not trust the maintainer should be able to check every claim
above by running `python3 -m unittest discover -s tests` and reading the
diff-able ground truth. That is the intended posture.

### 9.1 Governance of the judgement tables

Four tables encode judgement rather than fact, and are the residual risk the
structural safeguards above do not remove:

| Table | Location | What it decides |
| ----- | -------- | --------------- |
| `OID_ALGORITHMS` | `proofstein/cbom.py` | which OID means which algorithm |
| `LOCATION_PROPERTY_NAMES`, `LINE_PROPERTY_NAMES` | `proofstein/cbom.py` | which `properties[]` entries count as evidence |
| `_TOKEN_ALIASES`, `_FAMILY_MARKERS`, `_WHOLE_TOKEN_ONLY` | `proofstein/matching.py` | which algorithm spellings mean the same thing, and which names are matched only as complete tokens |
| `KNOWN_UNPLANTED` | `score.py` | which absent algorithms go uncharged, and where |

`KNOWN_UNPLANTED` was added to this list on 2026-08-03, after a corpus-wide
entry was found to have absolved five fabricated findings in the 2026-07-28 run. It decides
what is *not* charged, which makes an over-broad entry invisible in exactly the
way a wrong entry in the other tables is not: nothing appears in any column.
Entries are scoped to the project and file that justify them.

Each entry is defensible on its own. Collectively they are choices made by a
party that also ships a scored tool, and a single well-chosen addition could
favour one generator without any vendor name ever appearing in the code. The
answer to that is procedural, not technical:

**The rule, in force from the first published run:**

1. **Changes only by pull request.** No entry is added, altered or removed
   outside a reviewed PR against the public repository. This holds for the
   maintainer as much as for anyone else.
2. **A PR touching a table must say which generator prompted it**, and must not
   be merged in the same PR as a scoring run.
3. **Uniform application.** An entry admitted for one generator is admitted for
   all. There is no mechanism to scope one to a tool, and
   `tests/test_no_tool_specific_logic.py` fails the build if one is introduced.
4. **Every entry is covered by the invariance test automatically.**
   `tests/test_table_governance.py` iterates over the tables themselves rather
   than over a fixed list of cases, scoring a document that exercises each entry
   under six tool names, including `pqprobe-static`, and asserting the result
   never moves. An entry added tomorrow is covered by the same assertions with
   no test change required, and an entry that behaves differently per tool fails
   the moment it is added.
5. **No alias may collapse distinct families.** Enforced by
   `test_no_alias_collapses_distinct_families`, which is the failure mode most
   likely to arrive with a well-meaning addition and the one that would inflate
   every tool's score at once.
6. **Additions between quarterly runs are listed in the run manifest**, so a
   score change caused by a table change is attributable rather than invisible.

**Co-maintainership of these tables is offered to the SEG group at the
University of Bern**, as maintainers of BF-CBOM and CBOMbench and as a party
with no stake in any scored generator. The offer is specifically scoped to the
three tables above: review rights over the entries that encode judgement, which
is the part of Proofstein a conflicted maintainer could most plausibly bend. A
shared table is the only actual cure for a maintainer's judgement being the
single point of trust; the tests above are what make the sharing enforceable
rather than nominal.
