# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Every judgement table entry must behave identically for every tool.

Three tables encode judgement calls rather than facts:

* ``proofstein/cbom.py::OID_ALGORITHMS`` -- OID to algorithm name,
* ``proofstein/cbom.py::LOCATION_PROPERTY_NAMES`` / ``LINE_PROPERTY_NAMES`` --
  which ``properties[]`` entries count as evidence,
* ``proofstein/matching.py::_TOKEN_ALIASES`` / ``_FAMILY_MARKERS`` -- which
  algorithm spellings mean the same thing.

METHODOLOGY.md §9.1 sets the governance rules for them: a table change is its
own commit, separate from any run, and applies to every tool.

This module **iterates over the tables themselves**, so every entry, including
one added later, is covered by the same assertions. A table entry that behaves
differently depending on which tool emitted the document fails here.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from proofstein.cbom import (  # noqa: E402
    LINE_PROPERTY_NAMES,
    LOCATION_PROPERTY_NAMES,
    OID_ALGORITHMS,
    parse_cbom,
)
from proofstein.matching import (  # noqa: E402
    _FAMILY_MARKERS,
    _HYBRID_GROUPS,
    _JOSE_NAMES,
    _TOKEN_ALIASES,
    algorithms_compatible,
    families,
    normalize_tokens,
)
from proofstein.scoring import _as_unplanted, score_cbom  # noqa: E402

from score import KNOWN_UNPLANTED  # noqa: E402

#: Names deliberately including the maintainer's own tool and its competitors.
TOOL_NAMES = ["pqprobe", "cdxgen", "cbomkit", "cryptobom-forge", "an-unknown-tool", ""]

PROJECT_FILES = frozenset({"src/seal.go", "keys/node.pem"})


def ground_truth(algorithm: str) -> list[dict]:
    return [
        {
            "id": "a",
            "file": "src/seal.go",
            "line": 10,
            "algorithm": algorithm,
            "layer": 1,
            "cyclonedx_asset_type": "algorithm",
        }
    ]


def score(
    raw: str,
    tool: str,
    algorithm: str,
    *,
    known_unplanted=frozenset(),
    project: str = "p",
):
    _, reported, _ = parse_cbom(raw)
    return score_cbom(
        project=project,
        language="go",
        tool=tool,
        source="test",
        ground_truth=ground_truth(algorithm),
        reported=reported,
        project_files=PROJECT_FILES,
        known_unplanted=known_unplanted,
        line_tolerance=2,
    )


def bom(components: list[dict]) -> str:
    return json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}
    )


class TestOidTableIsToolNeutral(unittest.TestCase):
    def test_every_oid_scores_identically_under_every_tool_name(self):
        self.assertGreater(len(OID_ALGORITHMS), 0, "OID table is empty")

        for oid, algorithm in sorted(OID_ALGORITHMS.items()):
            component = {
                "type": "cryptographic-asset",
                # Opaque name, as cbomkit emits: identity rests on the OID alone.
                "name": "key@50ece37a-ae77-437c-a7e2-130a571b628b",
                "cryptoProperties": {"assetType": "algorithm", "oid": oid},
                "evidence": {"occurrences": [{"location": "src/seal.go", "line": 10}]},
            }
            raw = bom([component])
            with self.subTest(oid=oid, algorithm=algorithm):
                results = {tool: score(raw, tool, algorithm).detected for tool in TOOL_NAMES}
                self.assertEqual(
                    len(set(results.values())),
                    1,
                    f"OID {oid} scored differently by tool: {results}",
                )

    def test_every_oid_resolves_to_its_own_algorithm(self):
        """An entry that does not match what it maps to is dead weight."""
        for oid, algorithm in sorted(OID_ALGORITHMS.items()):
            with self.subTest(oid=oid, algorithm=algorithm):
                self.assertTrue(
                    algorithms_compatible(algorithm, algorithm),
                    f"OID {oid} maps to {algorithm!r}, which does not match itself",
                )

    def test_oids_are_well_formed(self):
        for oid in OID_ALGORITHMS:
            with self.subTest(oid=oid):
                parts = oid.split(".")
                self.assertGreater(len(parts), 2, f"{oid} is not a dotted OID")
                self.assertTrue(all(p.isdigit() for p in parts), f"{oid} has non-numeric arcs")


class TestPropertyNamesAreToolNeutral(unittest.TestCase):
    def test_every_location_property_name_scores_identically(self):
        self.assertGreater(len(LOCATION_PROPERTY_NAMES), 0)

        for name in sorted(LOCATION_PROPERTY_NAMES):
            for line_name in sorted(LINE_PROPERTY_NAMES):
                component = {
                    "type": "cryptographic-asset",
                    "name": "AES-256-GCM",
                    "cryptoProperties": {"assetType": "algorithm"},
                    "properties": [
                        {"name": name, "value": "src/seal.go"},
                        {"name": line_name, "value": "10"},
                    ],
                }
                raw = bom([component])
                with self.subTest(location=name, line=line_name):
                    results = {
                        tool: score(raw, tool, "AES-256-GCM").detected for tool in TOOL_NAMES
                    }
                    self.assertEqual(
                        len(set(results.values())),
                        1,
                        f"property pair ({name}, {line_name}) scored differently by tool: {results}",
                    )
                    self.assertEqual(
                        set(results.values()),
                        {1},
                        f"property pair ({name}, {line_name}) is in the table but yields no detection",
                    )

    def test_namespaced_variants_behave_the_same(self):
        """Generators namespace these; the prefix must not change the outcome."""
        for name in sorted(LOCATION_PROPERTY_NAMES):
            plain = bom(
                [
                    {
                        "type": "cryptographic-asset",
                        "name": "AES-256-GCM",
                        "cryptoProperties": {"assetType": "algorithm"},
                        "properties": [
                            {"name": name, "value": "src/seal.go"},
                            {"name": "line", "value": "10"},
                        ],
                    }
                ]
            )
            namespaced = plain.replace(f'"{name}"', f'"cdx:cbom:{name}"')
            with self.subTest(property=name):
                self.assertEqual(
                    score(plain, "t", "AES-256-GCM").detected,
                    score(namespaced, "t", "AES-256-GCM").detected,
                )


class TestAlgorithmAliasesAreToolNeutral(unittest.TestCase):
    def test_every_alias_scores_identically_under_every_tool_name(self):
        self.assertGreater(len(_TOKEN_ALIASES), 0)

        for spelling, canonical in sorted(_TOKEN_ALIASES.items()):
            component = {
                "type": "cryptographic-asset",
                "name": spelling,
                "cryptoProperties": {"assetType": "algorithm"},
                "evidence": {"occurrences": [{"location": "src/seal.go", "line": 10}]},
            }
            raw = bom([component])
            with self.subTest(spelling=spelling, canonical=canonical):
                results = {tool: score(raw, tool, spelling).detected for tool in TOOL_NAMES}
                self.assertEqual(
                    len(set(results.values())),
                    1,
                    f"alias {spelling!r} scored differently by tool: {results}",
                )

    def test_every_family_marker_scores_identically_under_every_tool_name(self):
        self.assertGreater(len(_FAMILY_MARKERS), 0)

        for marker, family in _FAMILY_MARKERS:
            component = {
                "type": "cryptographic-asset",
                "name": marker,
                "cryptoProperties": {"assetType": "algorithm"},
                "evidence": {"occurrences": [{"location": "src/seal.go", "line": 10}]},
            }
            raw = bom([component])
            with self.subTest(marker=marker, family=family):
                results = {tool: score(raw, tool, marker).detected for tool in TOOL_NAMES}
                self.assertEqual(
                    len(set(results.values())),
                    1,
                    f"family marker {marker!r} scored differently by tool: {results}",
                )

    def test_every_alias_actually_normalises_to_something(self):
        """A spelling that reduces to nothing can never match and is dead weight."""
        for spelling in sorted(_TOKEN_ALIASES):
            with self.subTest(spelling=spelling):
                self.assertTrue(
                    normalize_tokens(spelling),
                    f"alias {spelling!r} normalises to an empty token set",
                )

    def test_every_jose_name_and_hybrid_group_scores_identically_under_every_tool_name(self):
        """The rewrite tables are judgement too, and are covered the same way."""
        spellings = list(_JOSE_NAMES) + list(_HYBRID_GROUPS)
        self.assertGreater(len(spellings), 0)
        for spelling in spellings:
            component = {
                "type": "cryptographic-asset",
                "name": spelling,
                "cryptoProperties": {"assetType": "algorithm"},
                "evidence": {"occurrences": [{"location": "src/seal.go", "line": 10}]},
            }
            raw = bom([component])
            with self.subTest(spelling=spelling):
                results = {tool: score(raw, tool, spelling).detected for tool in TOOL_NAMES}
                self.assertEqual(len(set(results.values())), 1, f"{spelling!r} scored differently by tool: {results}")
                self.assertEqual(set(results.values()), {1}, f"{spelling!r} does not find itself")

    def test_every_jose_name_and_hybrid_half_claims_a_family(self):
        for spelling, meaning in _JOSE_NAMES.items():
            with self.subTest(spelling=spelling):
                self.assertTrue(families(normalize_tokens(spelling)))
                self.assertEqual(families(normalize_tokens(spelling)), families(normalize_tokens(meaning)))
        for spelling, halves in _HYBRID_GROUPS.items():
            for half in halves:
                with self.subTest(spelling=spelling, half=half):
                    self.assertTrue(families(normalize_tokens(half)))

    def test_no_alias_collapses_distinct_families(self):
        """An alias must not make two different families match each other.

        This is the failure mode that would quietly inflate everyone's score,
        and the one most likely to slip in with a well-meaning addition.
        """
        distinct = [
            "AES-256-GCM", "RSA-2048", "Ed25519", "SHA-256", "ML-KEM-768", "ChaCha20-Poly1305",
            "ML-DSA-65", "SLH-DSA", "Falcon-512", "LMS", "XMSS", "DSA-2048",
            "ECDSA-P256", "ECDH-P256", "X25519", "X448", "Ed448", "DH-2048", "bcrypt", "scrypt",
        ]
        for left in distinct:
            for right in distinct:
                if left == right:
                    continue
                with self.subTest(left=left, right=right):
                    self.assertFalse(
                        algorithms_compatible(left, right),
                        f"{left} and {right} are distinct families but match",
                    )


class TestUnplantedAllowancesAreToolNeutralAndJustified(unittest.TestCase):
    """``KNOWN_UNPLANTED`` decides which unplanted algorithm names go uncharged.

    Every entry forgives an algorithm the ground truth does not contain, and a
    single over-broad entry removes a false-positive charge from every tool at
    once.
    """

    def test_every_entry_scores_identically_under_every_tool_name(self):
        self.assertGreater(len(KNOWN_UNPLANTED), 0, "allowance table is empty")

        for entry in sorted(KNOWN_UNPLANTED, key=lambda e: _as_unplanted(e).algorithm):
            allowance = _as_unplanted(entry)
            component = {
                "type": "cryptographic-asset",
                "name": allowance.algorithm,
                "cryptoProperties": {"assetType": "algorithm"},
                "evidence": {"occurrences": [{"location": "src/seal.go", "line": 99}]},
            }
            raw = bom([component])
            with self.subTest(algorithm=allowance.algorithm):
                results = {
                    tool: score(raw, tool, "AES-256-GCM", known_unplanted=KNOWN_UNPLANTED).false_positives
                    for tool in TOOL_NAMES
                }
                self.assertEqual(
                    len(set(results.values())),
                    1,
                    f"{allowance.algorithm} scored differently by tool: {results}",
                )

    def test_a_scoped_entry_does_not_forgive_the_whole_corpus(self):
        """Every scoped entry is charged in a project it does not name."""
        scoped = [_as_unplanted(e) for e in KNOWN_UNPLANTED if _as_unplanted(e).file is not None]
        self.assertGreater(len(scoped), 0, "no scoped allowances to check")

        for allowance in scoped:
            component = {
                "type": "cryptographic-asset",
                "name": allowance.algorithm,
                "cryptoProperties": {"assetType": "algorithm"},
                "evidence": {"occurrences": [{"location": "src/seal.go", "line": 99}]},
            }
            with self.subTest(algorithm=allowance.algorithm, file=allowance.file):
                result = score(
                    bom([component]),
                    "any-tool",
                    "AES-256-GCM",
                    known_unplanted=KNOWN_UNPLANTED,
                    project="a-project-the-allowance-does-not-name",
                )
                self.assertEqual(
                    result.phantom_algorithm,
                    1,
                    f"{allowance.algorithm} is scoped to {allowance.file} but went uncharged elsewhere",
                )


class TestTablesAreDocumented(unittest.TestCase):
    """The governance rule is only real if the tables are findable."""

    def test_collection_and_scoring_digest_the_tables_alike(self):
        """The run manifest and the results carry digests from one function, so
        a results file can say whether it was scored under the tables its run
        was collected with."""
        import importlib.util

        from proofstein.tables import judgement_table_digest

        spec = importlib.util.spec_from_file_location("collect_cboms", REPO_ROOT / "tools" / "collect-cboms.py")
        collect = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collect)
        self.assertEqual(collect.judgement_table_digest(), judgement_table_digest(KNOWN_UNPLANTED))

    def test_run_directories_do_not_dirty_the_corpus(self):
        """An uncommitted run directory is outside the exported corpus."""
        from score import corpus_dirty

        self.assertFalse(corpus_dirty({"corpus_tree_dirty": True, "uncommitted_paths": ["runs/2026-08-23T1519Z-public/"]}))
        self.assertTrue(corpus_dirty({"corpus_tree_dirty": True, "uncommitted_paths": ["runs/generators.json"]}))
        self.assertTrue(corpus_dirty({"corpus_tree_dirty": True, "uncommitted_paths": ["corpus/go/x.go", "runs/a/"]}))
        self.assertTrue(corpus_dirty({"corpus_tree_dirty": True}))

    def test_methodology_names_each_table(self):
        text = (REPO_ROOT / "METHODOLOGY.md").read_text(encoding="utf-8")
        for needle in (
            "OID_ALGORITHMS",
            "LOCATION_PROPERTY_NAMES",
            "_TOKEN_ALIASES",
            "_WHOLE_TOKEN_ONLY",
            "KNOWN_UNPLANTED",
        ):
            with self.subTest(table=needle):
                self.assertIn(needle, text, f"{needle} is not named in METHODOLOGY.md")

    def test_methodology_states_the_change_rule(self):
        text = (REPO_ROOT / "METHODOLOGY.md").read_text(encoding="utf-8").lower()
        self.assertIn("a judgement-table change is its own commit", text)


if __name__ == "__main__":
    unittest.main()
