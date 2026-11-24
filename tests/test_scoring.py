# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Tests that the scorer cannot be talked into inflating a rate.

These are the executable form of the guarantee the README makes.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from proofstein.cbom import parse_cbom  # noqa: E402
from proofstein.scoring import Unplanted, score_cbom  # noqa: E402

GROUND_TRUTH = [
    {
        "id": "a",
        "file": "src/seal.go",
        "line": 10,
        "algorithm": "AES-256-GCM",
        "layer": 1,
        "cyclonedx_asset_type": "algorithm",
    },
    {
        "id": "b",
        "file": "src/identity.go",
        "line": 20,
        "algorithm": "RSA-2048",
        "layer": 1,
        "cyclonedx_asset_type": "algorithm",
    },
    {
        "id": "c",
        "file": "keys/node.pem",
        "line": 1,
        "algorithm": "Ed25519",
        "layer": 6,
        "cyclonedx_asset_type": "related-crypto-material",
    },
]

PROJECT_FILES = frozenset({"src/seal.go", "src/identity.go", "keys/node.pem", "README.md"})


def crypto(name: str, location: str | None = None, line: int | None = None) -> dict:
    component = {
        "type": "cryptographic-asset",
        "name": name,
        "cryptoProperties": {"assetType": "algorithm"},
    }
    if location is not None:
        occurrence: dict = {"location": location}
        if line is not None:
            occurrence["line"] = line
        component["evidence"] = {"occurrences": [occurrence]}
    return component


def make_bom(components: list[dict]) -> str:
    return json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}
    )


def run(raw: str, *, tool: str = "t", line_tolerance: int = 2):
    _, reported, _ = parse_cbom(raw)
    return score_cbom(
        project="p",
        language="go",
        tool=tool,
        source="test",
        ground_truth=GROUND_TRUTH,
        reported=reported,
        project_files=PROJECT_FILES,
        known_unplanted=frozenset(),
        line_tolerance=line_tolerance,
    )


class TestUnplantedAllowanceIsScoped(unittest.TestCase):
    """An allowance reaches only as far as the thing that justifies it.

    ``DES`` is in the corpus once, named as a *disabled* algorithm in one
    project's JVM options. The allowance forgives a DES claim at that file in
    that project only; anywhere else DES is a phantom algorithm.
    """

    ALLOWANCE = frozenset({Unplanted("DES", "p", "config/jvm.options")})

    def score(self, components: list[dict], *, project: str = "p"):
        _, reported, _ = parse_cbom(make_bom(components))
        return score_cbom(
            project=project,
            language="go",
            tool="t",
            source="test",
            ground_truth=GROUND_TRUTH,
            reported=reported,
            project_files=frozenset(PROJECT_FILES | {"config/jvm.options"}),
            known_unplanted=self.ALLOWANCE,
            line_tolerance=2,
        )

    def test_allowed_at_the_file_that_justifies_it(self):
        result = self.score([crypto("DES", "config/jvm.options", 13)])
        self.assertEqual(result.phantom_algorithm, 0)

    def test_charged_at_any_other_file_in_the_same_project(self):
        result = self.score([crypto("DES", "src/seal.go", 3)])
        self.assertEqual(result.phantom_algorithm, 1)

    def test_charged_in_a_project_the_allowance_does_not_name(self):
        result = self.score([crypto("DES", "config/jvm.options", 13)], project="other")
        self.assertEqual(result.phantom_algorithm, 1)

    def test_a_report_with_no_location_keeps_the_allowance(self):
        """Failing to say where is already measured; it is not a second offence."""
        result = self.score([crypto("DES")])
        self.assertEqual(result.phantom_algorithm, 0)

    def test_a_family_absent_from_the_project_is_charged_wherever_reported(self):
        """Naming LMS or Falcon in a project that plants neither is a phantom
        algorithm."""
        for name in ("LMS", "FN-DSA", "Falcon"):
            with self.subTest(name=name):
                result = self.score([crypto(name, "README.md", 3)])
                self.assertEqual(result.phantom_algorithm, 1)

    def test_a_bare_string_entry_stays_corpus_wide(self):
        """MD5, not CSPRNG: the name has to claim a family to reach this path."""
        components = [crypto("MD5", "src/seal.go", 3)]

        def score_with(allowance):
            _, reported, _ = parse_cbom(make_bom(components))
            return score_cbom(
                project="p",
                language="go",
                tool="t",
                source="test",
                ground_truth=GROUND_TRUTH,
                reported=reported,
                project_files=PROJECT_FILES,
                known_unplanted=allowance,
                line_tolerance=2,
            )

        self.assertEqual(score_with(frozenset({"MD5"})).phantom_algorithm, 0)
        # Same document, same name, no allowance: the charge must appear, or the
        # assertion above is passing for the wrong reason.
        self.assertEqual(score_with(frozenset()).phantom_algorithm, 1)


class TestNoInflation(unittest.TestCase):
    def test_empty_cbom_detects_nothing(self):
        result = run(make_bom([]))
        self.assertEqual(result.detected, 0)
        self.assertEqual(result.total, 3)

    def test_correct_names_without_evidence_detect_nothing(self):
        """The central rule: naming the algorithm is not finding it.

        Every project in the corpus contains AES-GCM and RSA, so a generator
        that emits those names unconditionally has said nothing checkable.
        """
        result = run(make_bom([crypto("AES-256-GCM"), crypto("RSA-2048"), crypto("Ed25519")]))
        self.assertEqual(result.detected, 0)
        self.assertTrue(all(v.name_only for v in result.verdicts))

    def test_file_without_line_is_a_detection(self):
        """Detection is file + algorithm + layer; the line is not scored.

        A generator reporting the right algorithm in the right file is credited
        whether it names a line or not.
        """
        result = run(
            make_bom(
                [
                    crypto("AES-256-GCM", "src/seal.go"),
                    crypto("RSA-2048", "src/identity.go"),
                ]
            )
        )
        self.assertEqual(result.detected, 2)
        self.assertTrue(all(v.file_only for v in result.verdicts if v.id in {"a", "b"}))
        self.assertFalse(
            any(v.located for v in result.verdicts if v.id in {"a", "b"}),
            "located still reports whether a line agreed, it just does not score",
        )

    def test_right_line_wrong_file_detects_nothing(self):
        result = run(make_bom([crypto("AES-256-GCM", "README.md", 10)]))
        self.assertEqual(result.detected, 0)

    def test_right_location_wrong_family_is_not_credited(self):
        result = run(make_bom([crypto("RSA-2048", "src/seal.go", 10)]))
        verdict = next(v for v in result.verdicts if v.id == "a")
        self.assertFalse(verdict.detected)
        self.assertTrue(verdict.located, "location agreed, so the diagnostic should say so")

    def test_correct_report_is_credited(self):
        result = run(
            make_bom(
                [
                    crypto("AES-256-GCM", "src/seal.go", 10),
                    crypto("RSA-2048", "src/identity.go", 20),
                    crypto("Ed25519", "keys/node.pem", 1),
                ]
            )
        )
        self.assertEqual(result.detected, 3)
        self.assertEqual(result.precision, 1.0)

    def test_shotgun_earns_recall_but_loses_precision(self):
        """Claiming everything everywhere must not look like competence."""
        components = []
        for path in sorted(PROJECT_FILES):
            for line in range(1, 40):
                for name in ("AES-256-GCM", "RSA-2048", "Ed25519"):
                    components.append(crypto(name, path, line))
        result = run(make_bom(components))

        self.assertEqual(result.detected, 3, "shotgun does reach every plant")
        self.assertLess(result.precision, 0.01, "but precision must expose it")
        self.assertGreater(result.unmatched_reports, 100)

    def test_shotgun_packed_into_few_components_still_loses(self):
        """The shotgun hidden inside a handful of components.

        Component-level precision alone is not enough: an attacker who puts the
        same exhaustive guessing into one component per algorithm keeps every
        component matching something, so component precision stays high and no
        false positive is charged. Claim precision is what prices it.
        """
        occurrences = [
            {"location": path, "line": line}
            for path in sorted(PROJECT_FILES)
            for line in range(1, 40)
        ]
        components = [
            {
                "type": "cryptographic-asset",
                "name": name,
                "cryptoProperties": {"assetType": "algorithm"},
                "evidence": {"occurrences": occurrences},
            }
            for name in ("AES-256-GCM", "RSA-2048", "Ed25519")
        ]
        result = run(make_bom(components))

        self.assertEqual(result.detected, 3, "the attack does reach every plant")
        self.assertGreater(result.precision, 0.5, "and component precision does not catch it")
        self.assertLess(
            result.claim_precision, 0.05, "claim precision must expose the guessing"
        )

    def test_precise_report_scores_well_on_both_precisions(self):
        """The counterpart: one claim per real site keeps both figures high."""
        result = run(
            make_bom(
                [
                    crypto("AES-256-GCM", "src/seal.go", 10),
                    crypto("RSA-2048", "src/identity.go", 20),
                    crypto("Ed25519", "keys/node.pem", 1),
                ]
            )
        )
        self.assertEqual(result.detected, 3)
        self.assertEqual(result.precision, 1.0)
        self.assertEqual(result.claim_precision, 1.0)

    def test_repeated_evidence_for_one_plant_is_not_punished(self):
        """Duplicated evidence is repetition, not guessing.

        A generator reporting the same site three times has not made two wrong
        claims, so claim precision must not treat it as though it had.
        """
        occurrence = {"location": "src/seal.go", "line": 10}
        component = {
            "type": "cryptographic-asset",
            "name": "AES-256-GCM",
            "cryptoProperties": {"assetType": "algorithm"},
            "evidence": {"occurrences": [occurrence, occurrence, occurrence]},
        }
        result = run(make_bom([component]))
        self.assertEqual(result.detected, 1)
        self.assertEqual(result.claim_precision, 1.0)

    def test_duplicate_reports_do_not_multiply_credit(self):
        component = crypto("AES-256-GCM", "src/seal.go", 10)
        result = run(make_bom([component] * 50))
        self.assertEqual(result.detected, 1)

    def test_tool_name_does_not_affect_score(self):
        """No scoring path may branch on which tool produced a document."""
        raw = make_bom([crypto("AES-256-GCM", "src/seal.go", 10)])
        names = ["pqprobe", "cdxgen", "cbomkit", "anything-at-all", ""]
        scores = {name: run(raw, tool=name).detected for name in names}
        self.assertEqual(len(set(scores.values())), 1, f"score varied by tool name: {scores}")

    def test_maintainers_own_quirk_gets_no_special_handling(self):
        """The conflict-of-interest case, stated concretely.

        Proofstein's maintainer also ships pqprobe, whose known quirk is
        emitting absolute paths from the clone directory. Absolute-path
        resolution is a documented, tool-neutral accommodation, so this asserts
        two things at once: that the accommodation works, and that it works
        exactly the same under every tool name -- including the maintainer's.
        """
        absolute = make_bom(
            [crypto("AES-256-GCM", "/tmp/pqprobe-1737/repo/src/seal.go", 10)]
        )
        relative = make_bom([crypto("AES-256-GCM", "src/seal.go", 10)])

        names = ["pqprobe", "cdxgen", "cbomkit", "some-other-tool"]
        absolute_scores = {n: run(absolute, tool=n).detected for n in names}
        relative_scores = {n: run(relative, tool=n).detected for n in names}

        self.assertEqual(
            set(absolute_scores.values()),
            {1},
            f"absolute-path handling varied by tool: {absolute_scores}",
        )
        self.assertEqual(
            absolute_scores, relative_scores, "absolute paths scored differently from relative ones"
        )

    def test_line_tolerance_does_not_gate_detection(self):
        """Tolerance decides `located`, which is reported, not scored."""
        raw = make_bom([crypto("AES-256-GCM", "src/seal.go", 13)])
        for tolerance in (2, 3):
            result = run(raw, line_tolerance=tolerance)
            self.assertEqual(result.detected, 1, f"tolerance {tolerance}")
        self.assertFalse(run(raw, line_tolerance=2).verdicts[0].located)
        self.assertTrue(run(raw, line_tolerance=3).verdicts[0].located)

    def test_phantom_file_is_charged(self):
        result = run(make_bom([crypto("AES-256-GCM", "src/imaginary.go", 10)]))
        self.assertEqual(result.phantom_location, 1)
        self.assertEqual(result.false_positives, 1)

    def test_phantom_algorithm_is_charged(self):
        result = run(make_bom([crypto("Blowfish-448", "src/seal.go", 10)]))
        self.assertEqual(result.phantom_algorithm, 1)
        self.assertEqual(result.false_positives, 1)

    def test_component_naming_a_file_is_not_a_phantom_algorithm(self):
        """A component named after a key file is not a phantom algorithm.

        cdxgen names a key-file component after the file -- ``relay-key.pem`` --
        and marks it ``assetType: certificate``. That is a correct finding of a
        layer-6 asset whose algorithm cannot be known without parsing the key.
        """
        component = {
            "type": "cryptographic-asset",
            "name": "node.pem",
            "cryptoProperties": {"assetType": "certificate"},
            "properties": [{"name": "SrcFile", "value": "keys/node.pem"}],
        }
        result = run(make_bom([component]))
        self.assertEqual(result.phantom_algorithm, 0)
        self.assertEqual(result.false_positives, 0)
        # Not credited either: no line, so there is nothing to check. That
        # shortfall belongs in the evidence-quality table, not in a
        # false-positive count.
        self.assertEqual(result.detected, 0)
        verdict = next(v for v in result.verdicts if v.id == "c")
        self.assertTrue(verdict.file_only, "the right file was found and should show as such")

    def test_opaque_component_on_a_planted_file_is_not_charged(self):
        component = {
            "type": "cryptographic-asset",
            "name": "key@50ece37a-ae77-437c-a7e2-130a571b628b",
            "cryptoProperties": {"assetType": "related-crypto-material"},
            "evidence": {"occurrences": [{"location": "src/seal.go"}]},
        }
        result = run(make_bom([component]))
        self.assertEqual(result.false_positives, 0)

    def test_wrong_family_is_charged_even_on_a_planted_file(self):
        """The location exemption does not cover a wrong algorithm family."""
        result = run(make_bom([crypto("Blowfish-448", "src/seal.go", 10)]))
        self.assertEqual(result.phantom_algorithm, 1)

    def test_unparseable_document_scores_zero_without_raising(self):
        _, reported, error = parse_cbom("{not json")
        self.assertIsNotNone(error)
        self.assertEqual(reported, [])


class TestEvidenceShapesAreEqualCitizens(unittest.TestCase):
    """Every documented evidence shape is read for every tool.

    A generator must not be advantaged or disadvantaged by which of the
    documented shapes it happens to use, only by whether the evidence is there.
    """

    def test_properties_srcfile_is_read(self):
        component = {
            "type": "cryptographic-asset",
            "name": "AES-256-GCM",
            "cryptoProperties": {"assetType": "algorithm"},
            "properties": [{"name": "SrcFile", "value": "src/seal.go"}, {"name": "line", "value": "10"}],
        }
        result = run(make_bom([component]))
        self.assertEqual(result.detected, 1, "properties-based evidence must count")

    def test_namespaced_property_names_are_read(self):
        component = {
            "type": "cryptographic-asset",
            "name": "AES-256-GCM",
            "cryptoProperties": {"assetType": "algorithm"},
            "properties": [
                {"name": "cdx:cbom:SrcFile", "value": "src/seal.go"},
                {"name": "cdx:cbom:Line", "value": 10},
            ],
        }
        self.assertEqual(run(make_bom([component])).detected, 1)

    def test_oid_identifies_the_algorithm(self):
        """cbomkit routinely leaves name opaque and gives only an OID."""
        component = {
            "type": "cryptographic-asset",
            "name": "key@50ece37a-ae77-437c-a7e2-130a571b628b",
            "cryptoProperties": {"assetType": "algorithm", "oid": "1.2.840.113549.1.1.1"},
            "evidence": {"occurrences": [{"location": "src/identity.go", "line": 20}]},
        }
        self.assertEqual(run(make_bom([component])).detected, 1)

    def test_absolute_clone_path_is_resolved(self):
        component = crypto("AES-256-GCM", "/tmp/cdxgen-1737/repo/src/seal.go", 10)
        self.assertEqual(run(make_bom([component])).detected, 1)

    def test_bom_wrapper_is_unwrapped(self):
        inner = json.loads(make_bom([crypto("AES-256-GCM", "src/seal.go", 10)]))
        self.assertEqual(run(json.dumps({"bom": inner})).detected, 1)

    def test_list_wrapped_document_is_unwrapped(self):
        inner = json.loads(make_bom([crypto("AES-256-GCM", "src/seal.go", 10)]))
        self.assertEqual(run(json.dumps([{"bom": inner}])).detected, 1)

    def test_nested_components_are_searched(self):
        outer = {
            "type": "library",
            "name": "wrapper",
            "components": [crypto("AES-256-GCM", "src/seal.go", 10)],
        }
        self.assertEqual(run(make_bom([outer])).detected, 1)

    def test_crypto_properties_without_type_still_count(self):
        """A populated crypto block with a mislabelled type is still a find."""
        component = {
            "type": "library",
            "name": "AES-256-GCM",
            "cryptoProperties": {"assetType": "algorithm"},
            "evidence": {"occurrences": [{"location": "src/seal.go", "line": 10}]},
        }
        self.assertEqual(run(make_bom([component])).detected, 1)


if __name__ == "__main__":
    unittest.main()


class TestHybridPlant(unittest.TestCase):
    """A hybrid group is found by naming it or both its halves in its file."""

    GROUND_TRUTH = [
        {
            "id": "h",
            "file": "src/tls.c",
            "line": 30,
            "algorithm": "X25519MLKEM768",
            "layer": 1,
            "cyclonedx_asset_type": "algorithm",
        },
        {
            "id": "k",
            "file": "src/kem.c",
            "line": 5,
            "algorithm": "ML-KEM-512",
            "layer": 1,
            "cyclonedx_asset_type": "algorithm",
        },
    ]
    FILES = frozenset({"src/tls.c", "src/kem.c", "src/other.c"})

    def score(self, components):
        _, reported, _ = parse_cbom(make_bom(components))
        result = score_cbom(
            project="p",
            language="c",
            tool="t",
            source="test",
            ground_truth=self.GROUND_TRUTH,
            reported=reported,
            project_files=self.FILES,
            known_unplanted=frozenset(),
            line_tolerance=2,
        )
        return {v.id: v.detected for v in result.verdicts}, result

    def test_the_hybrid_name_finds_it(self):
        found, _ = self.score([crypto("X25519MLKEM768", "src/tls.c", 30)])
        self.assertTrue(found["h"])

    def test_both_halves_in_the_file_find_it(self):
        found, result = self.score(
            [crypto("X25519", "src/tls.c", 30), crypto("ML-KEM-768", "src/tls.c", 30)]
        )
        self.assertTrue(found["h"])
        self.assertEqual(result.credited_claims, 2)
        self.assertEqual(result.false_positives, 0)

    def test_one_half_does_not_find_it_and_is_not_charged(self):
        for name in ("X25519", "ML-KEM-768"):
            with self.subTest(name=name):
                found, result = self.score([crypto(name, "src/tls.c", 30)])
                self.assertFalse(found["h"])
                self.assertEqual(result.phantom_algorithm, 0)

    def test_halves_in_different_files_do_not_find_it(self):
        found, _ = self.score([crypto("X25519", "src/tls.c", 30), crypto("ML-KEM-768", "src/other.c", 1)])
        self.assertFalse(found["h"])

    def test_wrong_post_quantum_parameter_does_not_find_it(self):
        found, _ = self.score([crypto("X25519", "src/tls.c", 30), crypto("ML-KEM-512", "src/tls.c", 30)])
        self.assertFalse(found["h"])


class TestBcryptIsCharged(unittest.TestCase):
    def test_bcrypt_in_a_project_without_it_is_a_phantom_algorithm(self):
        result = run(make_bom([crypto("bcrypt", "src/seal.go", 10)]))
        self.assertEqual(result.phantom_algorithm, 1)

    def test_a_cng_identifier_is_not_a_bcrypt_claim(self):
        result = run(make_bom([crypto("BCryptOpenAlgorithmProvider", "src/seal.go", 10)]))
        self.assertEqual(result.phantom_algorithm, 0)


class TestCombinedSignatureOid(unittest.TestCase):
    """The OID of ecdsa-with-SHA256 credits the ECDSA and the SHA-256 in its file."""

    GROUND_TRUTH = [
        {"id": "sig", "file": "src/sign.c", "line": 5, "algorithm": "ECDSA-P256", "layer": 1, "cyclonedx_asset_type": "algorithm"},
        {"id": "dig", "file": "src/sign.c", "line": 7, "algorithm": "SHA-256", "layer": 1, "cyclonedx_asset_type": "algorithm"},
        {"id": "kex", "file": "src/sign.c", "line": 9, "algorithm": "ECDH-P256", "layer": 1, "cyclonedx_asset_type": "algorithm"},
        {"id": "big", "file": "src/sign.c", "line": 11, "algorithm": "SHA-384", "layer": 1, "cyclonedx_asset_type": "algorithm"},
    ]

    def test_the_oid_credits_signature_and_digest_only(self):
        component = {
            "type": "cryptographic-asset",
            "name": "key@50ece37a-ae77-437c-a7e2-130a571b628b",
            "cryptoProperties": {"assetType": "algorithm", "oid": "1.2.840.10045.4.3.2"},
            "evidence": {"occurrences": [{"location": "src/sign.c", "line": 5}]},
        }
        _, reported, _ = parse_cbom(make_bom([component]))
        result = score_cbom(
            project="p", language="c", tool="t", source="test", ground_truth=self.GROUND_TRUTH,
            reported=reported, project_files=frozenset({"src/sign.c"}), known_unplanted=frozenset(),
            line_tolerance=2,
        )
        found = {v.id: v.detected for v in result.verdicts}
        self.assertEqual(found, {"sig": True, "dig": True, "kex": False, "big": False})
