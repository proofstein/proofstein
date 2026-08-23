# Cold review

A skeptical pass over the whole repository, conducted as if by someone who did
not build it. Six questions were asked. Every one produced at least one defect;
all are fixed, and each fix has a test that fails without it.

Findings are listed worst-first within each section. Nothing here is
hypothetical, every defect was reproduced before it was fixed.

---

## 1. Can the scorer inflate any tool's rate?

### 1.1 Precision was gameable by packing guesses into few components (fixed)

The original precision metric was *components credited / components reported*,
on the reasoning that a generator claiming everything would earn thousands of
uncredited components.

It does not, if the attacker packs the guessing into a handful of components.
Ten components, one per planted algorithm, each carrying an occurrence for
every line of every file, were scored against `beacon-relay`:

```
recall = 19/19 (100%)   component precision = 80%   false positives = 0
```

Full marks for a document that read nothing. Every component matched something,
so component precision stayed high and no phantom was charged.

**Fix:** added **claim precision**, distinct credited `(component, file, line)`
claims over distinct claims made. The same attack now scores **2.2%**: it made
7670 claims to earn 19. An honest document scores 100% on both.
`results.md` reports both, and a wide gap between them is documented as the
signature of guessing.

Regression: `test_shotgun_packed_into_few_components_still_loses`.

### 1.2 Deduplicating claims punished honest repetition (fixed)

The first version of claim precision counted raw occurrence entries, so a
generator reporting one true site three times scored 33%. Repetition is not
guessing. Claims are now deduplicated per component before counting.

Regression: `test_repeated_evidence_for_one_plant_is_not_punished`.

### 1.3 `--line-tolerance` could be widened silently (fixed)

A large tolerance turns "file and line" back into "file". The flag remains for
diagnostics, but any value above the default now warns on stderr and is recorded
in the header of both output files.

### 1.4 Attacks that were already handled

Confirmed working before review, retained as tests: correct algorithm names with
no evidence score zero; file without line scores zero; right line in the wrong
file scores zero; right location with the wrong algorithm family scores zero;
duplicate components do not multiply credit; `other`/`unknown` never match.

---

## 2. Does pqprobe's output format get a normalisation advantage?

**No, and the structure prevents it rather than the intent.**

* `tests/test_no_tool_specific_logic.py` parses all seven scoring modules and
  fails if a vendor name appears in any identifier or non-docstring string
  literal. It passes.
* `test_tool_name_does_not_affect_score` scores one document under five tool
  names, `pqprobe-static` among them: identical results.
* Added during review: `test_maintainers_own_quirk_gets_no_special_handling`.
  pqprobe-static's known quirk is emitting **absolute paths** from the clone
  directory. This asserts that absolute-path resolution works, that it produces
  the same score as the relative form, and that it behaves identically under
  every tool name. Absolute-path resolution exists because BF-CBOM workers clone
  into temporary directories (`common/utils.py:136`), which affects every tool.
* The worker shim is a **pass-through**: pqprobe-static emits CycloneDX and the
  shim returns it unchanged, so there is no conversion step anywhere that could
  be tuned. It lived in `upstream-contrib/`, outside the scorer entirely; that
  directory has since moved out of this repository (see the note at the end).

One residual risk, stated rather than solved: the OID table, the accepted
`properties[]` names and the algorithm alias table are all judgement calls made
by the maintainer. They are applied uniformly and are visible in the source, but
a future entry could in principle be chosen to favour one generator. The defence
is that each is a published table in a diffable file, not that the maintainer
promises not to.

---

## 3. Does schema validation actually fail on an invalid CBOM?

**Yes.** Verified against three shipped fixtures and six synthetic mutations.

| Fixture | Outcome |
| ------- | ------- |
| `samples/invalid/malformed.cdx.json` | rejected, `'specVersion' is a required property` |
| `samples/invalid/not-a-bom.json` | rejected, `'bomFormat' is a required property` |
| `samples/invalid/truncated.json` | rejected at parse, unterminated string |
| all 18 `samples/cboms/*.json` | accepted |

Mutation tests additionally confirm rejection of an invalid `components[].type`,
an invalid `cryptoProperties.assetType`, an occurrence missing the required
`location`, and an empty object. `tests/test_schema.py` pins both directions, so
the validator cannot silently degrade into approving everything.

---

## 4. Is every ground-truth entry detectable in principle?

This question found the most defects. The corpus contained assets that **no
generator could have found**.

### 4.1 Layer-5 assets named algorithms their manifest never mentions (fixed)

`go.mod` line 8 reads `require golang.org/x/crypto v0.36.0`, and the ground
truth called that asset **Curve25519**. Nothing on the line, or anywhere near
it, says Curve25519. A generator would have to resolve and analyse the module to
know that, from a manifest it can only report the library.

Same defect in `package.json` (`node-forge` labelled `RSA-OAEP`) and `pom.xml`.

**Fix:** layer-5 assets are now identified by the library the manifest names
(`golang.org/x/crypto`, `node-forge`, `PyNaCl`, `libsodium`, `bcprov-jdk18on`,
`chacha20poly1305`), with the crypto it provides moved to the note field. The
Java marker also moved from the `<version>` line to `<artifactId>`, since a
version number identifies nothing.

### 4.2 The Rust Ed25519 call site named no algorithm (fixed)

`let manifest = SigningKey::generate(&mut OsRng);`, the type is generic and the
algorithm appears only in the `use ed25519_dalek::...` import. **Fix:** the
import line is now an accepted alternative location, which is exactly what
`accept_locations` is for.

### 4.3 A config value the matcher rejected (fixed)

`legacy_jwks_signature: "RS256"` was labelled `RSA-2048`. `RS256` is
RSASSA-PKCS1-v1_5 with SHA-256; its `256` is a digest size, so the
parameter-contradiction rule correctly refused to match it against a *2048*-bit
key. But the config states no key size at all.

**Fix:** the ground truth now says `RS256`. A report of `RSA` is credited; a
report of `RSA-2048` is not, because the config does not state a key size and
naming one is an over-claim. Pinned in
`test_jws_algorithm_names_resolve_to_their_family`.

### 4.4 The detectability test itself was wrong (fixed)

The first version required a layer-3 asset's algorithm to appear in the same
file as the wrapper. That holds only in Go; in the other five projects the
wrapper and the primitive are deliberately in different files, which is the
whole point of the layer. The test now requires that the primitive exists
somewhere in the project *and* that the annotated line names a symbol leading to
the file holding it, a path a call-graph method could follow.

The test also now reuses the production matcher rather than a private hint list,
so it cannot pass on a technicality the scorer would reject.

### 4.5 Verified

All 108 assets across the six projects pass: every file exists, every line is
within its file, every accepted location is real, asset ids are unique, every
project covers all six layers, every asset type is a valid CycloneDX value, and
all layer-6 files are recognisable PEM or PKCS#12.

---

## 5. Does a fresh clone score a sample directory with one command?

**Yes.** Verified by copying the tree, committing it, cloning it, and running in
the clone, so that anything untracked or wrongly `.gitignore`d would show up:

```
pip install -r requirements.txt
./score.py --cboms samples/cboms
```

239 files tracked, no build artifacts in the clone, identical scores to the
working tree, and all 85 tests pass inside the clone.

### 5.1 `--out` outside the repository crashed (fixed)

Found while exercising the bundle path. `score.py` printed its summary with
`Path.relative_to(REPO_ROOT)`, which raises `ValueError` for any output
directory outside the repository, a normal thing to ask for. The run completed
and wrote correct files, then died on the last line. Fixed with a helper that
falls back to the absolute path.

### 5.2 The bundle path had never been exercised, now covered

The BF-CBOM bundle format was implemented from its source but not tested against
an archive in that exact layout. Built one
(`<insp_id>/<worker>/<owner>_<repo>_<worker>.json`, re-serialised the way
`coordinator/utils.py:547` does) and scored it: identical results to the raw
directory, with the tool correctly taken from the directory level and the
project recovered from the ambiguous filename. `tests/test_inputs.py` now covers
both layouts, including hyphenated tool names, underscored owner/repo pairs,
tool names containing underscores, extracted-directory bundles, and unparseable
names being *reported* rather than guessed.

---

## 6. Did any GPL code cross into the Apache tree?

**No.** BF-CBOM is GPL-3.0-only; this repository is Apache-2.0.

`tests/test_license_separation.py` enforces four properties: nothing under
`upstream-contrib/` imports from the Apache tree; nothing in the Apache tree
imports from `upstream-contrib/`; every contributed file declares
`GPL-3.0-only`; and no BF-CBOM implementation fingerprint (`def run_worker`,
`def build_handle_instruction`, `class JobInstruction`, `DataClassJsonMixin`,
`def collect_results_once`, `def build_cboms_zip`) appears in the Apache tree.
It also asserts `LICENSE` is Apache-2.0 and carries no GPL text.

The protocol was documented by *reading* BF-CBOM's source, with every claim
cited by file and line in `docs/bf-cbom-protocol.md`. Facts about an interface
are not copyrightable expression; no implementation was copied.

### 6.1 Two defects in the separation work itself (fixed)

* The licence test flagged **itself**: it necessarily contains the GPL notice
  and the BF-CBOM symbol names it searches for. It now excludes its own path,
  and a fragile "references the path before any import" string heuristic was
  removed in favour of the AST import check that actually means something.
* `worker-pqprobe-static.env.template` carried no GPL header. Added.

---

## 7. Defects found outside the six questions

### 7.1 The corpus shipped with the answer key in it, **fixed, worst defect found**

`deploy/jvm.options` has an extension that was not in the comment-style table,
so the generator copied it through untouched, **including its `@PS`
annotations**, which name the algorithm and layer of each planted asset. Two
assets shipped with their answers inline. Any generator that reads comments
would have been handed the answer key for those assets.

**Fix:** two parts. The extension was added, and, more importantly,
`build-corpus.py` now refuses to write any file where the marker survived
stripping, so the next unmapped extension fails the build instead of leaking.
`test_no_annotations_leaked_into_the_corpus` scans every shipped file.

### 7.2 `AES/GCM/NoPadding` was reduced to "NoPadding" (fixed)

The name normaliser split on the last `/` to strip cdxgen's opaque bom-refs
(`crypto/certificate/foo.gpg@sha256:...`). That also destroyed the exact string
Java's `Cipher.getInstance` takes, so a correct Java report matched nothing.
`/` is now an ordinary separator; the opaque-identifier problem is handled by the
`@` split alone, which is sufficient.

### 7.3 `--check` always reported the corpus as stale (fixed)

Two causes, both real: it compared the freshly generated tree against a shipped
tree containing build artifacts (`target/`, `node_modules/`, `*.o`), and the
staging tree contained `proofstein.json` while the shipped tree did not.
Comparison now considers only generated files, and project metadata is never
emitted as corpus source.

Left unfixed, the CI staleness gate would have been permanently red and
therefore ignored.

### 7.4 Cargo target-directory collision (fixed)

A holdout variant keeps the crate name of the project it derives from, so the
public corpus and the holdout competed for one `CARGO_TARGET_DIR` and the Rust
holdout intermittently failed to build. The target directory is now namespaced
per corpus.

This one is worth noting because the first failure looked like a defect in the
holdout transforms, a renamed program that would not compile. It was the build
harness.

### 7.5 `KNOWN_UNPLANTED` was over-broad (fixed)

The list exempting real-but-unplanted constructs from the phantom-algorithm
check had been written from memory and included **HMAC, PBKDF2, SHA-512, SHA-1
and CRC32, none of which appear anywhere in the corpus.** Each entry silently
forgave a genuine false positive.

**Fix:** every remaining entry is now justified against something verifiably
present in the shipped corpus source (CSPRNGs in all six projects; `base64` and
`hex` in the fingerprint paths; `MD5`, `RC4`, `DES`, `SSLv3` named as *disabled*
in `jvm.options`; `SHA-384` from the nginx suite; `X25519` from the JVM group
`x25519mlkem768`), with the reason recorded inline. Absent algorithms are
charged again, `test_phantom_algorithm_is_charged` uses Blowfish precisely
because it is not in the corpus.

---

## Summary

| # | Defect | Severity |
| - | ------ | -------- |
| 7.1 | Answer-key annotations shipped inside the corpus | high |
| 1.1 | Precision defeated by packing claims into few components | high |
| 4.1 | Layer-5 assets labelled with undetectable algorithms | high |
| 7.5 | False-positive check forgave algorithms absent from the corpus | medium |
| 7.2 | `AES/GCM/NoPadding` normalised to nothing useful | medium |
| 4.2 | Rust Ed25519 site unidentifiable without its import | medium |
| 4.3 | `RS256` config value labelled as `RSA-2048` | medium |
| 7.3 | Staleness gate permanently red | medium |
| 5.1 | Crash writing results outside the repository | low |
| 1.2 | Honest repetition scored as guessing | low |
| 7.4 | Cargo target collision between corpus and holdout | low |
| 4.4 | Detectability test assumed same-file indirection | low (test only) |
| 6.1 | Licence test flagged itself; missing GPL header | low (test only) |
| 1.3 | Line tolerance could be widened silently | low |

Test count went from 62 to 85 during the review. Every fix above is pinned by at
least one test that fails without it.

---

## Post-review adjustments

Three changes made after the review, before the first scoring run.

### A. The shim described a bug that no longer exists (fixed)

The review verified pqprobe-static's CLI empirically, which was right, but
against a **pre-2.0.0** binary. The argument-order defect it worked around
(flags after the subcommand silently ignored) was fixed at v2.0.0, and the shim
was documenting a dead bug as though it were current behaviour.

Rebuilt from a fresh worktree at the `v2.0.0` tag and re-verified all three
behaviours against it:

| Behaviour | v2.0.0 result |
| --------- | ------------- |
| Argument order | **both orders work**, byte-identical output (17239 bytes each); `parseInterleaved` at `cmd/pqprobe-static/main.go:49` |
| Exit status on findings | **1**, unchanged; still means findings, not failure |
| CycloneDX output value | `-output` documents `text, json, sarif, cbom`; `cyclonedx` is an **undocumented alias** producing identical bytes |

The shim now sends the documented `cbom` rather than the `cyclonedx` alias, so a
future release is free to drop the alias. `PQPROBE_TAG` is pinned to `2.0.0`,
the minimum with CycloneDX output, and the comments describe the pinned version
rather than the historical defect.

Also confirmed, and worth recording because the review had flagged it as an open
risk: v2.0.0 emits **repository-relative** paths, 19 occurrences over
`beacon-relay`, **0 absolute**, all carrying line numbers, all in
`evidence.occurrences`. The absolute-path concern is closed at the source rather
than absorbed by a normalisation.

### B. Transport for the 2026-07-27 run (decided)

The 2026-07-27 run uses the **raw-directory path** with generators invoked directly. The
BF-CBOM path is proven separately, once, as an integration test rather than as
the scoring vehicle, so a transport problem cannot be mistaken for a detection
problem. Recorded in METHODOLOGY.md §7.

### C. The judgement-table residual, governance, not code

The review closed §2 with a residual risk it could not fix in code: the OID
table, accepted `properties[]` names and algorithm aliases are the maintainer's
judgement, and a single well-chosen entry could tilt results without any vendor
name reaching the code.

That now has a rule (METHODOLOGY.md §9.1) and a mechanism:

* entries change **only by pull request**, never in the same PR as a scoring
  run, always applied uniformly, and listed in the run manifest;
* `tests/test_table_governance.py` **iterates over the tables themselves** rather
  than over a fixed list, scoring a document that exercises every OID, every
  accepted property name and every algorithm alias under six tool names,
  including `pqprobe-static`, and asserting the result never moves. An entry
  added later is covered by the same assertions with no test change;
* `test_no_alias_collapses_distinct_families` blocks the failure mode most
  likely to arrive with a well-meaning addition, and the only one that would
  inflate every tool at once;
* **co-maintainership of exactly those three tables is to be offered to SEG at
  the University of Bern**, a party maintaining the runner and the predecessor
  benchmark, with no stake in any scored generator. No approach has been made
  yet; the draft is held outside this repository.

This is the honest resolution: the residual risk is not eliminated, it is moved
out of one conflicted party's hands and made checkable.

Test count: 85 → 96.

---

## Known limitations, not defects

* **The corpus ground truth is complete for planted assets, not exhaustive of
  every cryptographic construct.** False positives are therefore counted
  narrowly, phantom file and phantom algorithm only, and everything else
  unmatched is reported uncharged. Proofstein measures recall well and precision
  conservatively.
* **The corpus is small**: six projects, 108 assets. It is a discriminator, not
  a population sample.
* **Judgement tables are the maintainer's.** The OID map, the accepted
  `properties[]` names and the algorithm aliases are all defensible choices, but
  they are choices; they are published and diffable rather than certified.
* **Layer 3 is scored generously.** A generator attributing a wrapper-mediated
  algorithm to either the wrapper body or its caller is credited, because both
  are defensible and scoring convention would not measure detection.

---

## Note on `upstream-contrib/`

Section 6 audited a directory that is no longer in this repository. It held a
GPL-3.0-only BF-CBOM worker plugin inside an Apache-2.0 tree, with a tested
boundary between them. It has since been moved out, to be sent as a pull request
to BF-CBOM rather than carried here.

The findings in section 6 stand as a record of what was checked at the time. The
boundary they tested no longer exists, because the two licences are no longer in
the same tree.
