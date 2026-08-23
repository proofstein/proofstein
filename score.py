#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Score CBOMs against the Proofstein ground-truth corpus.

    ./score.py --cboms path/to/cboms/          # raw CycloneDX directory
    ./score.py --bundle cboms_ab12cd34.zip     # BF-CBOM artifact bundle

Writes results/results.md and results/results.json.

The scorer runs standalone. It needs no runner, no Redis, and no network.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

from proofstein import schema as schema_module  # noqa: E402
from proofstein.cbom import parse_cbom  # noqa: E402
from proofstein.inputs import discover_bundle, discover_raw_directory  # noqa: E402
from proofstein.matching import DEFAULT_LINE_TOLERANCE  # noqa: E402
from proofstein.report import render_json, render_markdown  # noqa: E402
from proofstein.scoring import Unplanted, score_cbom  # noqa: E402

GROUND_TRUTH_DIR = REPO_ROOT / "ground-truth"
CORPUS_DIR = REPO_ROOT / "corpus"
RESULTS_DIR = REPO_ROOT / "results"

# Cryptographic constructs that genuinely exist in the corpus but carry no
# ground-truth entry, because they are not among the planted assets. A tool
# reporting one of these has not made an error, so they are excluded from the
# phantom-algorithm check.
#
# Every entry is justified by something actually present in the shipped corpus,
# and the list is deliberately short. Padding it with plausible-sounding
# algorithms that are *not* in the corpus would quietly forgive real false
# positives and make the false-positive column meaningless. Anything absent from
# the corpus -- Blowfish, 3DES, PBKDF2, HMAC, SHA-512 -- is charged.
#
# An entry is scoped to where its justification holds. A bare string is
# corpus-wide; ``Unplanted(name, project, file)`` reaches only that file. The
# distinction is not cosmetic: the weak algorithms below exist in one file of
# one project, and allowing them everywhere forgave five fabricated DES findings
# in the 2026-07-28 run, in four projects that contain no DES at all.
KNOWN_UNPLANTED: frozenset[str | Unplanted] = frozenset(
    {
        # CSPRNGs. Every project seeds nonces or keys from one:
        # crypto/rand.Read (Go), RAND_bytes (C), randomBytes (JS),
        # SecureRandom (Java), os.urandom (Python), OsRng (Rust).
        "CSPRNG",
        "DRBG",
        "SecureRandom",
        "OsRng",
        "urandom",
        # Encodings, not ciphers, but frequently reported as crypto assets.
        # encoding/hex and base64url appear in the fingerprint and JWKS paths.
        "base64",
        "hex",
        # A mode named on its own, where the planted asset is the full AEAD.
        "GCM",
        # Named in ledger-svc/deploy/jvm.options as *disabled* algorithms
        # (-Djdk.tls.disabledAlgorithms). A generator reporting them there has
        # read the config correctly, even though nothing here uses them.
        # Reported anywhere else they are fabrications, so the allowance stops
        # at the file that justifies it.
        Unplanted("MD5", "ledger-svc", "deploy/jvm.options"),
        Unplanted("RC4", "ledger-svc", "deploy/jvm.options"),
        Unplanted("DES", "ledger-svc", "deploy/jvm.options"),
        Unplanted("SSLv3", "ledger-svc", "deploy/jvm.options"),
        # Halves of planted composites a generator may reasonably split:
        # SHA-384 from the nginx suite ECDHE-ECDSA-AES256-GCM-SHA384, and
        # X25519 from the JVM group x25519mlkem768.
        "SHA-384",
        "X25519",
        # TLS versions appear in several configs; some are planted as protocol
        # assets, and a generator may report neighbouring versions from the
        # same line.
        "TLS",
    }
)


def load_projects(ground_truth_dir: Path = GROUND_TRUTH_DIR) -> dict[str, dict]:
    """Load every ground-truth document, keyed by project name."""
    if not ground_truth_dir.is_dir():
        raise SystemExit(f"no ground truth at {ground_truth_dir}; run tools/build-corpus.py first")

    projects: dict[str, dict] = {}
    for path in sorted(ground_truth_dir.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        projects[document["project"]] = document
    if not projects:
        raise SystemExit(f"no ground-truth files found in {GROUND_TRUTH_DIR}")
    return projects


def _corpus_hint(corpus_path: str) -> str:
    """What to run to produce a corpus that is not there."""
    if corpus_path.split("/", 1)[0] == "corpus":
        return "run tools/build-corpus.py first"
    # A holdout corpus is generated from a seed and deliberately not committed,
    # so a fresh checkout never has one.
    return "a holdout corpus is generated, not committed: regenerate it with tools/generate-holdout.py --seed <seed>"


def project_file_index(project: dict) -> frozenset[str]:
    """Every file in a corpus project, as repo-relative POSIX paths.

    Fails rather than returning an empty set, because an empty set is not a
    usable input and does not look like an error. Path resolution needs the
    project's real file list; given an empty one, every reported location fails
    to resolve, every component is charged as a phantom location, and the run
    reports 0/108 with a full sheet of false positives. That is indistinguishable
    from a generator that found nothing while fabricating everything, and it is
    what a missing holdout corpus produced while re-scoring the 2026-07-28 run --
    diagnosed from the shape of the result rather than from any message. See
    docs/pending-review.md entry 8.
    """
    corpus_path = project["corpus_path"]
    root = REPO_ROOT / corpus_path

    if not root.is_dir():
        raise SystemExit(
            f"no corpus directory for project {project['project']!r}: "
            f"{corpus_path} (resolved to {root}); {_corpus_hint(corpus_path)}"
        )

    skip = {".git", "node_modules", "target", "dist", "__pycache__", ".venv"}
    files = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in skip for part in relative.parts):
            continue
        files.add(relative.as_posix())

    if not files:
        raise SystemExit(
            f"corpus directory for project {project['project']!r} holds no files: "
            f"{corpus_path} (resolved to {root}); {_corpus_hint(corpus_path)}"
        )

    return frozenset(files)


def _display(path: Path) -> str:
    """Show a path relative to the repository when it is inside it.

    ``--out`` may point anywhere, including another filesystem, so this must not
    assume the output lives under the repository root.
    """
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def corpus_version() -> str:
    """Identify the corpus so a result file can be traced to an input."""
    try:
        revision = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if revision.returncode == 0:
            head = revision.stdout.strip()
            dirty = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "status", "--porcelain"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            suffix = "-dirty" if dirty.stdout.strip() else ""
            return f"{head}{suffix}"
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--cboms", type=Path, help="directory of raw CycloneDX CBOMs")
    source.add_argument("--bundle", type=Path, help="BF-CBOM artifact bundle (zip or directory)")
    parser.add_argument("--out", type=Path, default=RESULTS_DIR, help="output directory")
    parser.add_argument(
        "--line-tolerance",
        type=int,
        default=DEFAULT_LINE_TOLERANCE,
        help=f"lines a report may differ from the plant (default {DEFAULT_LINE_TOLERANCE})",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="run manifest from tools/collect-cboms.py; its tool versions, corpus "
        "commit and judgement-table digests are carried into the results",
    )
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=GROUND_TRUTH_DIR,
        help="ground-truth directory to score against (default: ground-truth/); "
        "pass ground-truth-holdout/ to score a holdout run. Holdout and public "
        "scores are reported separately and never averaged -- see METHODOLOGY.md 6.",
    )
    parser.add_argument("--no-schema", action="store_true", help="skip CycloneDX schema validation")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.line_tolerance < 0:
        raise SystemExit("--line-tolerance must not be negative")
    if args.line_tolerance > DEFAULT_LINE_TOLERANCE:
        # A wide tolerance turns "file and line" back into "file", which is the
        # rule this benchmark exists to avoid. It stays available for
        # diagnostics, but never silently: it is announced here and recorded in
        # the header of both output files.
        print(
            f"warning: line tolerance {args.line_tolerance} is wider than the default "
            f"{DEFAULT_LINE_TOLERANCE}; results are not comparable with published runs",
            file=sys.stderr,
        )

    projects = load_projects(args.ground_truth.resolve())
    known = set(projects)

    if args.cboms:
        if not args.cboms.is_dir():
            raise SystemExit(f"not a directory: {args.cboms}")
        inputs, problems = discover_raw_directory(args.cboms, known)
    else:
        if not args.bundle.exists():
            raise SystemExit(f"no such bundle: {args.bundle}")
        inputs, problems = discover_bundle(args.bundle, known)

    if not inputs:
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        raise SystemExit("no CBOMs found to score")

    validate_schema = not args.no_schema
    if validate_schema and not schema_module.available():
        print(
            "warning: jsonschema is unavailable, skipping schema validation "
            "(pip install -r requirements.txt)",
            file=sys.stderr,
        )
        validate_schema = False

    file_index = {name: project_file_index(project) for name, project in projects.items()}

    results = []
    for item in inputs:
        project = projects[item.project]
        bom, reported, parse_error = parse_cbom(item.raw)

        result = score_cbom(
            project=item.project,
            language=project["language"],
            tool=item.tool,
            source=item.source,
            ground_truth=project["assets"],
            reported=reported,
            project_files=file_index[item.project],
            known_unplanted=KNOWN_UNPLANTED,
            line_tolerance=args.line_tolerance,
        )
        result.parse_error = parse_error

        if validate_schema:
            if parse_error:
                result.schema_valid = False
                result.schema_errors = [parse_error]
            else:
                valid, errors = schema_module.validate(bom)
                result.schema_valid = valid
                result.schema_errors = errors

        results.append(result)

    scored_pairs = {(r.project, r.tool) for r in results}
    tools = sorted({r.tool for r in results})
    # A pair absent from the input is not scored as zero -- a tool that was
    # never run against a project must not be reported as having missed it.
    unscored = sum(
        1 for name in projects for tool in tools if (name, tool) not in scored_pairs
    )

    # A results table that cannot be traced to what produced it is a claim, not
    # a measurement. When a manifest is supplied its provenance wins over the
    # working tree, because the run happened at that commit and not this one.
    run_manifest = None
    if args.manifest:
        run_manifest = json.loads(args.manifest.read_text(encoding="utf-8"))

    meta = {
        "corpus_version": (
            run_manifest["run"].get("corpus_commit_short") or corpus_version()
            if run_manifest
            else corpus_version()
        ),
        "line_tolerance": args.line_tolerance,
        "corpus": "holdout" if args.ground_truth.resolve() != GROUND_TRUTH_DIR.resolve() else "public",
        "schema_validated": validate_schema,
        "cboms_scored": len(results),
        "projects": sorted(projects),
        "tools": tools,
        "unscored_pairs": unscored,
        "problems": problems,
    }

    if run_manifest:
        meta["run"] = {
            "manifest": str(args.manifest),
            "started_utc": run_manifest["run"].get("started_utc"),
            "corpus_commit": run_manifest["run"].get("corpus_commit"),
            "corpus_tree_dirty": run_manifest["run"].get("corpus_tree_dirty"),
            "attempted": run_manifest["run"].get("attempted"),
            "succeeded": run_manifest["run"].get("succeeded"),
            "tool_versions": {
                name: spec.get("version") for name, spec in run_manifest.get("tools", {}).items()
            },
            "judgement_tables": run_manifest.get("judgement_tables"),
            # Invocations that produced nothing. These are why a (project, tool)
            # pair is absent from the tables, and stating them is the difference
            # between "not run" and "found nothing".
            "failed_invocations": [
                {
                    "tool": entry["tool"],
                    "project": entry["project"],
                    "status": entry["status"],
                    "error": entry.get("error", ""),
                    "stderr_tail": entry.get("stderr_tail", ""),
                }
                for entry in run_manifest.get("invocations", [])
                if entry.get("status") != "ok"
            ],
        }

    args.out.mkdir(parents=True, exist_ok=True)
    markdown_path = args.out / "results.md"
    json_path = args.out / "results.json"
    markdown_path.write_text(render_markdown(results, meta), encoding="utf-8")
    json_path.write_text(
        json.dumps(render_json(results, meta), indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )

    if not args.quiet:
        print(f"scored {len(results)} CBOM(s) across {len(tools)} tool(s)")
        for tool in tools:
            subset = [r for r in results if r.tool == tool]
            detected = sum(r.detected for r in subset)
            total = sum(r.total for r in subset)
            rate = f"{100 * detected / total:.0f}%" if total else "--"
            fps = sum(r.false_positives for r in subset)
            print(f"  {tool:<20} {rate:>5} ({detected}/{total})  false positives: {fps}")
        if unscored:
            print(f"  {unscored} (project, tool) pair(s) not present in input; excluded, not zeroed")
        for problem in problems:
            print(f"  warning: {problem}", file=sys.stderr)
        print(f"\nwrote {_display(markdown_path)} and {_display(json_path)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
