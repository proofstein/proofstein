# BF-CBOM: worker protocol, targeting, and artifact format

Everything here was established by reading BF-CBOM's source. Every claim cites
a file and line so it can be checked and re-checked when upstream moves.

**Source examined:** [SEG-UNIBE/BF-CBOM](https://github.com/SEG-UNIBE/BF-CBOM)
at commit `89a44b7`, `VERSION` = `1.0.3`, licence **GPL-3.0-only**
(`LICENSE:1`).

> BF-CBOM is GPL-3.0-only and Proofstein is Apache-2.0. **No BF-CBOM code is
> reproduced in this repository.** This document describes an interface so that
> Proofstein can consume its output and so a worker plugin can be contributed
> upstream under BF-CBOM's own licence.

---

## 1. Worker instruction protocol

Workers are Redis list consumers. One queue pair per worker name, where the name
is the worker's directory under `workers/`.

| Direction | Key | Payload |
| --------- | --- | ------- |
| coordinator → worker | `jobs:{name}` (`BLPOP`) | `JobInstruction` JSON |
| worker → coordinator | `results:{name}` (`RPUSH`) | `JobResult` JSON |

The loop is `common/worker.py:37-86`.

### JobInstruction (`common/models.py:63-67`)

```
job_id     str
tool       str
repo_info  RepoInfo
```

### RepoInfo (`common/models.py:41-48`)

```
full_name      str          "owner/repo"
git_url        str          clone URL
branch         str
size_kb        int
main_language  str | None
stars          int | None
```

### JobResult (`common/models.py:51-60`)

```
job_id        str
status        str          "ok" | "timeout" | "error"
repo_info     RepoInfo
json          str          <- the CBOM, as a STRING, not an object
duration_sec  float | None
size_bytes    int | None
worker        str | None
error         str | None
```

`json` carrying a serialised document rather than a nested object is the detail
most likely to trip up a new worker.

### Status handling

* The coordinator maps `ok` → `completed` and anything else → `failed`
  (`coordinator/redis_io.py:419`).
* Only `status == "ok"` results are included in an exported bundle
  (`coordinator/utils.py:539`, `misc/cli/cli.py:176`).
* Timeouts are enforced coordinator-side by a future timeout on a worker thread
  (`common/worker.py:49-51`), bounded by `WORKER_TIMEOUT_SEC`
  (`common/worker.py:32`).

### Writing a worker

`build_handle_instruction` (`common/worker.py:89-160`) is the supported
extension point: supply `produce_cbom(instruction, trace) -> str` and the
framework handles status, normalisation and error aggregation.
`normalize_json` (`common/utils.py:430-448`) rejects empty or invalid JSON,
turning it into `status = "error"`, so a worker that emits nothing is recorded
as a failure, not as an empty CBOM.

Registration is by directory presence under `workers/` plus the
`AVAILABLE_WORKERS` environment list (`common/utils.py:373-427`,
`docker-compose.yml:30`).

---

## 2. How repositories are targeted

Workers clone for themselves; there is no shared checkout. `clone_repo`
(`common/utils.py:136-298`) runs:

```
git clone --progress --depth 1 -b <branch> <git_url> <target>
```

falling back to the default branch if the requested one is missing.

Three consequences for a corpus:

1. **Public repositories only.** No credentials are injected, deliberately
   (`common/utils.py:174`).
2. **No history.** `--depth 1` means a generator cannot use history, and neither
   can a benchmark.
3. **Paths are temporary.** Each worker clones into its own scratch directory
   (e.g. `/tmp/cdxgen-<ms>/repo`, `workers/cdxgen/main.py:101-103`), so a
   generator reporting absolute paths reports paths that exist nowhere else.
   This is why Proofstein resolves reported paths by longest matching suffix
   against the project's real file list, for every tool alike.

Branch, language, stars and size are resolved from the GitHub API when an
inspection starts (`coordinator/redis_io.py:334-359`).

A repository is therefore targetable if it is a **public git repository with a
resolvable branch**, which is what `tools/publish-corpus.sh` produces.

---

## 3. Artifact bundle format

Two writers produce byte-identical layouts, the Streamlit download button
(`coordinator/utils.py:498-558`) and the CLI (`misc/cli/cli.py:152-191`):

```
<insp_id>/<worker>/<repo_full_name with "/" -> "_">_<worker>.json
```

packaged as `cboms_<insp_id[:8]>.zip`.

Two transformations are applied before writing
(`coordinator/utils.py:544-547`, `misc/cli/cli.py:180-183`):

1. A `{"bom": {...}}` wrapper is **unwrapped**.
2. The document is re-serialised with `indent=2, sort_keys=True`.

So a consumer must accept both bare CycloneDX and `bom`-wrapped documents.
Proofstein handles both, plus a single-element list wrapper, in
`proofstein/cbom.py::unwrap_bom`.

### The filename is ambiguous, the path is not

`<repo>_<worker>.json` with `/` replaced by `_` cannot be split reliably:
`acme_beacon-relay_cdxgen.json` gives no way to know where the repository name
ends and the worker name begins without already knowing the worker list.

Inside a bundle this does not matter, because the worker is *also* a directory
level, Proofstein reads the tool from the directory and recovers the project by
stripping the redundant `_<worker>` suffix. For flat directories of raw CBOMs,
Proofstein requires `<project>__<tool>.json` with a double underscore, which
cannot collide.

---

## 4. Observed generator output shapes

From the CBOMs checked into `tests/` upstream. These drove the design of
Proofstein's parser, and they are the reason it accepts more than one shape.

**cdxgen** (`tests/bisq_cdxgen.json`) records the source file as a
`properties[]` entry named `SrcFile` and emits **no line number**:

```json
{ "type": "cryptographic-asset",
  "name": "willyko.gpg",
  "cryptoProperties": { "assetType": "certificate" },
  "properties": [ { "name": "SrcFile", "value": "seednode/.../willyko.gpg" } ] }
```

**cbomkit** (`tests/bisq_cbomkit.json`) uses the spec-blessed
`evidence.occurrences[]` with `location`, `line`, `offset` and
`additionalContext`, but frequently leaves `name` as an opaque `key@<uuid>`,
identifying the algorithm only by `cryptoProperties.oid`:

```json
{ "cryptoProperties": { "assetType": "algorithm", "oid": "1.2.840.113549.1.1.8" },
  "evidence": { "occurrences": [ { "line": 193, "location": "common/.../Encryption.java" } ] },
  "name": "key@02711205-48b8-44bb-8967-af53f999b178" }
```

Reading only `evidence.occurrences` would score the first tool at zero. Reading
only `name` would score the second at zero. Neither outcome would say anything
about whether the generator found the asset, so Proofstein reads both shapes,
and maps OIDs through a published table, for every tool.

---

## 5. Related work: CBOMbench

[SEG-UNIBE/cbombench](https://github.com/SEG-UNIBE/cbombench), archived and
superseded by BF-CBOM, Apache-2.0.

Its per-CBOM metrics are, in full (`src/cbom_analyzer.py:159-163`):

```python
return {
    'total_components': len(components),
    'is_empty': len(components) == 0,
    'component_types': component_types,
}
```

plus execution time from `durations.json` (`src/cbom_analyzer.py:165-181`) and
repository size.

There is no ground truth anywhere in the project. The metrics measure how much
a tool emitted and how long it took, not whether any of it was correct. A tool
emitting a hundred fabricated components outscores one emitting ten correct
ones. That is the gap Proofstein exists to close, and it is why its headline
metric is anchored to file and line rather than to counts.
