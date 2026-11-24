# Methodology

How Proofstein scores a CBOM generator against the corpus, and how a run is
collected. The tests in `tests/` check the scorer against these rules.

---

## 1. What is measured

A planted asset is **detected** when a generator's CBOM contains a component
that

1. carries evidence resolving to the **file** the asset is planted in, or to one
   of its accepted locations (§3.5),
2. names an algorithm **compatible** with the planted one (§3.4), and
3. is of a kind the asset's **layer** accepts: a dependency component (§3.6)
   satisfies a layer-5 asset and no other.

The line a generator reports is recorded and never scored (§3.3).

Detection rate is detected assets over planted assets, per tool, per language
and per layer. For the same inputs each results page also reports the share of
assets reached by a claim in the right file within the line tolerance, by a
claim in the right file, and by the algorithm name anywhere in the document.
None of these is a detection.

### Not measured

* **Whether the generator ran.** A (project, tool) pair absent from the input
  is excluded from every table, not scored as zero.
* **Speed, memory, image size.**
* **The CycloneDX asset type.** It is recorded per asset in `results.json` and
  is not part of the detection rule.
* **Severity and operation labels.** The scorer reads neither a severity nor
  `cryptoFunctions`.

---

## 2. The six layers

Every corpus project plants assets in all six layers.

| Layer | What it plants |
| ----- | -------------- |
| 1 | Direct crypto API call sites |
| 2 | Aliased imports (`import hashlib as digestlib`, `use sha2::Sha256 as ContentHash`, a static import, a `#define`) |
| 3 | Wrapper functions reached through a constructor table |
| 4 | Config-driven selection (YAML, nginx, JVM properties, Helm values, TOML, `.conf`) |
| 5 | Crypto in a declared dependency that no shipped code calls |
| 6 | Key, certificate and keystore files |

A layer-5 asset is planted at the line of the manifest that declares the
dependency.

---

## 3. Matching rules

### 3.1 Location

Evidence is read from these shapes, for every tool:

* `evidence.occurrences[].location` and `.line`, as the CycloneDX 1.6 schema
  defines them.
* `properties[]` entries whose name, after any namespace prefix is stripped,
  is one of `SrcFile`, `sourceFile`, `source_file`, `location`, `filePath`,
  `file_path`, `file`, `path` (`LOCATION_PROPERTY_NAMES`), with the line taken
  from `line`, `lineNumber`, `line_number`, `startLine`, `start_line`
  (`LINE_PROPERTY_NAMES`). Names are compared case-insensitively.

### 3.2 Paths

Reported paths are normalised (separators, leading `./`) and resolved against
the project's file list by the longest matching suffix that names exactly one
file. A path that resolves to no file is counted as unresolvable in the
evidence table.

### 3.3 Lines

The reported line is recorded and not scored. `--line-tolerance`, default
**2**, decides only the `located` figure: a claim in the right file whose line
is within the tolerance of the planted line. A tolerance wider than the default
prints a warning and is recorded in the header of both output files. Published
runs use the default.

### 3.4 Algorithms

The names read from a component are its `name`, the canonical name of its
`cryptoProperties.oid` (`OID_ALGORITHMS` in `proofstein/cbom.py`), its
`algorithmProperties` `parameterSetIdentifier`, `primitive` and `curve`, its
`relatedCryptoMaterialProperties.type`, its `protocolProperties` `type` and
`version`, and a component `version` shorter than 24 characters.

Each name is reduced to a token set with separators removed, so `SHA-256`,
`SHA256` and `sha_256` are the same, as are `ML-KEM-768` and `MLKEM768`
(`_TOKEN_ALIASES` in `proofstein/matching.py` folds equivalent spellings). An
algorithm family is found where its marker (`_FAMILY_MARKERS`) begins at a token
boundary or immediately after a digit, and a marker ending in a digit is not
followed by another digit. `DES`, `SEED`, `IDEA`, `RC2`, `RC4`, `CAST5`,
`Camellia` and `bcrypt` (`_WHOLE_TOKEN_ONLY`) are matched only as complete
tokens, and only where every other token in the name is a size, a mode
qualifier or a descriptive word.

Before tokens are read:

* text after an `@` is dropped (`key@<uuid>`, `foo.gpg@sha256:...`);
* a combined signature name (`SHA256withECDSA`, `SHA384withRSA`,
  `sha256WithRSAEncryption`, `SHA256withRSA/PSS`) becomes its scheme and its
  digest;
* a JOSE algorithm name becomes its algorithm (`_JOSE_NAMES`): `RS256`, `RS384`
  and `RS512` are RSA, `PS256`, `PS384` and `PS512` are RSA-PSS, `RSA-OAEP-256`
  is RSA-OAEP, and `ES256`, `ES384` and `ES512` are ECDSA on P-256, P-384 and
  P-521; the number in a JOSE name is never read as a key size;
* a hybrid key-exchange group becomes its two halves (`_HYBRID_GROUPS`).

A reported name is compatible with a planted one when:

* they share a family and no parameter contradicts: a less specific report is
  credited (`AES` for a planted `AES-256-GCM`), a different size in the same
  family is not (`AES-128-GCM`, `ML-KEM-512` for `ML-KEM-768`);
* a report naming only a curve (`P-256`, `secp256r1`, `prime256v1`) or only `EC`
  credits an ECDSA or an ECDH plant on that curve; a report naming ECDSA or ECDH
  credits only that family;
* for a hybrid group plant (`X25519MLKEM768`, `X448MLKEM1024`,
  `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`), the report names the hybrid, or
  reports in the plant's file name both halves, each at its own parameters.

A report naming no family whose only overlap with the plant is a mode or
construction qualifier (`GCM`, `CBC`) is not compatible. Where either name
states a family, a bare number shared by the two is not compatible on its own.
Placeholder values (`other`, `unknown`, `generic`, `unspecified`) match nothing.
Only numbers in `CRYPTO_SIZES` are read as sizes, so the digits of `PKCS#8`,
`PKCS#12`, `SEC1` and `X.509` are not.

### 3.5 Accepted locations

An asset may carry `accept_locations` in the ground truth: further places whose
evidence counts for it, declared with a `//@PS +<id>` marker in the template.
They are part of the published ground truth and apply to every tool.

### 3.6 Dependency components

A component of type `library` or `framework` without `cryptoProperties` is a
dependency component. It may satisfy a layer-5 asset, is not counted among a
tool's crypto components or claims, and is never charged as a false positive.
A component carrying `cryptoProperties` is never a dependency component.

---

## 4. False positives

Two kinds of report are charged as false positives:

* **Phantom algorithm**: the component claims an algorithm family that is not
  among the project's planted algorithms (including the halves of a planted
  hybrid group) and is not covered by a `KNOWN_UNPLANTED` entry in `score.py`
  that reaches this project and file. It is charged wherever it is reported. A
  component with no reported location keeps a file-scoped allowance.
* **Phantom location**: every location the component reports fails to resolve
  to a file in the project.

A component that names no algorithm family is never charged as a phantom
algorithm. A component credited with a planted asset, and a dependency
component, are never charged.

Every other component that matches no planted asset is counted as
**unmatched** and not charged, unless it is in a file that holds a planted
asset, in which case it is not counted at all. The ground truth lists the
planted assets; it does not enumerate every cryptographic construct in the
corpus.

`KNOWN_UNPLANTED` holds constructs present in the corpus without a
ground-truth entry:

* in every project: `CSPRNG`, `DRBG`, `SecureRandom`, `OsRng`, `urandom`,
  `base64`, `hex`, `GCM`, `SHA-384`, `X25519` and `TLS`;
* in `ledger-svc/deploy/jvm.options` only, where they are named as disabled
  algorithms: `MD5`, `RC4`, `DES` and `SSLv3`.

### Negative cases

Two files plant no asset:

* `corpus/go/beacon-relay/ops/health/api.py`, a health-probe module built on the
  Falcon web framework. `beacon-relay` plants no Falcon (FN-DSA) signature, so a
  report of Falcon or FN-DSA in this file is a phantom algorithm.
* `corpus/javascript/session-broker/src/lms.ts`, a learning-management system client.
  `session-broker` plants no LMS signature, so a report of LMS in this file is a
  phantom algorithm.

### Precision

**Component precision** is credited crypto components over reported crypto
components.

**Claim precision** is credited `(component, file)` pairs over distinct
`(component, file, line)` claims. Repeated evidence for one location counts as
one claim. Dependency components are in neither figure.

---

## 5. Schema validity

Every CBOM is validated against the CycloneDX 1.6 JSON schema, vendored
unmodified under `schemas/` (`bom-1.6.schema.json`, with `spdx.schema.json` and
`jsf-0.82.schema.json`). Validity is reported per tool as a pass rate and does
not affect detection.

`samples/invalid/` holds three documents that fail validation: a document
missing `specVersion` with an invalid component type, a non-BOM JSON document,
and a truncated file. `tests/test_schema.py` asserts that they are rejected and
that a valid document is accepted.

---

## 6. Public corpus and holdout

**Public and holdout results are reported separately and never averaged.**

The public corpus, its ground truth and its runs' CBOMs are in the repository.

The holdout is generated from the same templates by `tools/generate-holdout.py
--seed <n>`, with transforms that leave the cryptography unchanged:

* a header block shifts every line number;
* wrapper functions, types and import aliases are renamed;
* files move within their package;
* config keys are reordered and, where declared, an algorithm is swapped for
  another member of its family (`ML-KEM-768` to `ML-KEM-1024`).

The holdout ground truth is computed from the transformed templates by the same
annotation parser as the public ground truth. Each holdout run uses a new seed.
The seed, the holdout ground truth and the run's CBOMs are archived privately.
None of them, and no holdout corpus, is committed. The run manifest records the SHA-256 of each
withheld CBOM (`tools/withhold-cboms.py`, which also verifies an archive against
them), and `results.json` names each holdout plant by its id, without file or
line.

---

## 7. Corpus export

`tools/collect-cboms.py` exports each public project with `git archive HEAD`
and runs every generator against that export. Holdout projects are copied
without build artifacts (`.git`, `node_modules`, `target`, `dist`,
`__pycache__`, `.venv`).

The scorer also reads a BF-CBOM artifact bundle (`score.py --bundle`).
`tools/publish-corpus.sh` produces each corpus project as a git repository that
BF-CBOM can clone by `file://` URL.

---

## 8. How a run is collected

1. **Corpus.** The run manifest records the corpus commit and the uncommitted
   paths of the tree. A run with an uncommitted path outside the run
   directories under `runs/` is not published.
2. **Holdout.** A holdout run generates a new holdout with a new seed (§6).
3. **Build.** Both corpora are built in the image of `tools/build.Dockerfile`,
   whose base is pinned by digest and whose JDK is pinned by release and
   SHA-256:
   ```
   docker build -t proofstein-build -f tools/build.Dockerfile tools
   docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/work -v <build-root>:/build \
       -e HOME=/build/home -e PROOFSTEIN_BUILD_ROOT=/build -w /work \
       proofstein-build tools/build-all.sh [ground-truth-holdout]
   ```
   A project that does not build is withdrawn from the run, and the manifest
   records it.
4. **Generators.** `tools/collect-cboms.py --config <generators.json> --out
   runs/<run-id>` runs each generator over each project. The run's
   `generators.json` and any wrapper scripts it calls (`harness/`) are kept in
   the run directory. The manifest records, per tool, its name and released
   version, the SHA-256 of the binary or package, the image and image digest where one is
   used, and the argument vector; per invocation, the exit status, duration,
   output size and stderr tail; and a digest of each judgement table (§9.1).
5. **Scoring.**
   ```
   ./score.py --cboms runs/<run-id>/cboms --manifest runs/<run-id>/manifest.json \
       --out runs/<run-id>/results [--ground-truth ground-truth-holdout]
   ```
6. **Holdout CBOMs.** `tools/withhold-cboms.py --run runs/<run-id> --archive
   <archive-dir>` moves them to the private archive and records their digests
   in the manifest.
7. **Table changes.** The manifest lists under `judgement_table_changes` every
   judgement table whose digest changed since the previous run of the same kind,
   with its entries and digest before and after, and the generators that
   prompted the change (§9.1, rules 2 and 6).

Run ids are the UTC start time to the minute and the kind:
`<YYYY-MM-DD>T<HHMM>Z-public`, `-holdout`, or the name of a tool scored outside
the main table.

---

## 9. Maintenance

Proofstein is maintained by Ottenheimer GmbH. Ottenheimer GmbH also makes
`pqprobe`, one of the scored generators.

These apply to every tool:

* **No tool-specific logic.** `tests/test_no_tool_specific_logic.py` parses each
  module on the scoring path and fails if a tool name appears in an identifier
  or a non-docstring string literal.
* **Tool-name invariance.**
  `tests/test_scoring.py::test_tool_name_does_not_affect_score` scores one
  document under several tool names, `pqprobe` among them, and asserts
  that the result is the same.
* **One set of rules.** Every rule in §3 and §4 applies to every tool. The scorer
  has no format handling for any single tool.
* **The judgement tables** and their rules, §9.1.

### 9.1 Governance of the judgement tables

The tables in these three modules encode judgement rather than fact:

| Location | Tables | What they decide |
| -------- | ------ | ---------------- |
| `proofstein/cbom.py` | `OID_ALGORITHMS`, `LOCATION_PROPERTY_NAMES`, `LINE_PROPERTY_NAMES` | which OID means which algorithm, and which `properties[]` entries count as evidence |
| `proofstein/matching.py` | `_TOKEN_ALIASES`, `_FAMILY_MARKERS`, `_WHOLE_TOKEN_ONLY`, `_JOSE_NAMES`, `_HYBRID_GROUPS` | which algorithm spellings mean the same thing, which markers identify a family, which names are matched only as complete tokens, what a JOSE algorithm name means, and which hybrid groups are made of which two halves |
| `score.py` | `KNOWN_UNPLANTED` | which algorithms absent from the ground truth go uncharged, and where |

Each run's manifest records a digest of every table at collection, and each
results page gives the digests of the scorer commit that produced it.

1. **A judgement-table change is its own commit**, separate from any run.
2. **The run manifest names the generator that prompted each table change.**
3. **Uniform application.** An entry applies to every tool. No entry can be
   scoped to a tool; `tests/test_no_tool_specific_logic.py` fails if one is.
4. **Every entry is covered by the invariance test.**
   `tests/test_table_governance.py` iterates over the tables, scores a document
   exercising each entry under six tool names, `pqprobe` among them, and
   asserts that the result is the same.
5. **No alias collapses distinct families.**
   `test_no_alias_collapses_distinct_families` fails if one does.
6. **Changes between runs are listed in the run manifest**, under
   `judgement_table_changes` (§8, step 7).

**Co-maintainership of these tables is offered to the SEG group at the
University of Bern**, as maintainers of BF-CBOM and CBOMbench and as a party
with no stake in any scored generator. The offer is specifically scoped to the
three tables above: review rights over the entries that encode judgement, which
is the part of Proofstein a conflicted maintainer could most plausibly bend. A
shared table is the only actual cure for a maintainer's judgement being the
single point of trust; the tests above are what make the sharing enforceable
rather than nominal.
