# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Tests for algorithm and path matching.

Run with: python3 -m unittest discover -s tests
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from proofstein.matching import (  # noqa: E402
    _FAMILY_MARKERS,
    _WHOLE_TOKEN_ONLY,
    PathResolver,
    algorithms_compatible,
    families,
    location_matches,
    normalize_path,
    normalize_tokens,
)


def claims_a_family(name: str) -> bool:
    """Whether a reported name makes any algorithm claim at all.

    This is the predicate the false-positive path keys on
    (``scoring._count_false_positives``): a name carrying no family cannot be
    charged with naming the wrong algorithm, and a name carrying one can.
    """
    return bool(families(normalize_tokens(name)))


class TestFamilyMarkersAreAnchored(unittest.TestCase):
    """An algorithm name is matched as tokens, never as a substring.

    Every entry in NOT_ALGORITHM_NAMES is a string a generator has emitted or
    plausibly could: a filename, an identifier, a word from a comment. Before
    family markers were anchored, each of the first four produced a family and
    could therefore be charged as a false positive, or worse, silently credited.

    The DES row is the one with a run behind it. In scoring the 2026-07-28 run a generator
    reported ``DES`` five times after matching the letters inside "decides" in a
    config comment. The scorer did not catch it, and the reason it did not is
    recorded in docs/pending-review.md entry 6. These cases exist so that the
    scorer's own version of that bug cannot come back.
    """

    NOT_ALGORITHM_NAMES = [
        "universal-hash",  # contains RSA
        "Caesar",  # contains AES
        "caesar.py",
        "peer-mtls-key.pem",  # contains TLS
        "decides",  # contains DES
        "nodes",
        "provides",
        "description",
        "modes",
        "releases",
        "phrases",
        "seedRandom",  # begins with SEED
        "seed_material",
        "random seed",
        "seed value",
        "ideal",  # begins with IDEA
        "identifier",
        "idea list",
        "IDEAS",
    ]

    ALGORITHM_NAMES = [
        ("AES-256-GCM", "AES"),
        ("aes256-gcm", "AES"),
        ("AES/GCM/NoPadding", "AES"),
        ("ML-KEM-768", "MLKEM"),
        ("MLKEM768", "MLKEM"),
        ("x25519mlkem768", "MLKEM"),
        ("x25519mlkem768", "X25519"),
        ("SHA256withRSA", "RSA"),
        ("SHA256withRSA", "SHA256"),
        ("HMAC-SHA256", "HMAC"),
        ("SHA3-256", "SHA3"),
        ("Ed25519", "ED25519"),
        ("ECDSA", "ECDSA"),
        ("DES", "DES"),
        ("DES cipher", "DES"),
        ("DES block cipher in use", "DES"),
        ("DES-EDE3-CBC", "DES"),
        ("3DES", "3DES"),
        ("TRIPLE-DES", "3DES"),
        ("RC4", "RC4"),
        ("ARC4", "RC4"),
        ("RC2", "RC2"),
        ("SEED", "SEED"),
        ("SEED-CBC", "SEED"),
        ("SEED-128-CBC", "SEED"),
        ("IDEA", "IDEA"),
        ("IDEA-CBC", "IDEA"),
        ("CAST5", "CAST5"),
        ("Camellia", "CAMELLIA"),
        ("Camellia-256-CBC", "CAMELLIA"),
    ]

    def test_ordinary_words_and_filenames_claim_nothing(self):
        for name in self.NOT_ALGORITHM_NAMES:
            with self.subTest(name=name):
                self.assertFalse(
                    claims_a_family(name),
                    f"{name!r} claims {sorted(families(normalize_tokens(name)))}",
                )

    def test_real_names_still_resolve_to_their_family(self):
        for name, family in self.ALGORITHM_NAMES:
            with self.subTest(name=name, family=family):
                self.assertIn(family, families(normalize_tokens(name)))

    def test_a_family_is_not_found_inside_a_longer_parameter(self):
        """SHA-384 is not SHA-3, and SHA-1 is not the 1 in a longer number."""
        self.assertNotIn("SHA3", families(normalize_tokens("SHA-384")))
        self.assertNotIn("SHA3", families(normalize_tokens("SHA384")))
        self.assertIn("SHA384", families(normalize_tokens("SHA-384")))
        self.assertIn("SHA3", families(normalize_tokens("SHA-3")))

    def test_ecdsa_is_not_dsa(self):
        """DSA sits inside ECDSA. They are different families and different keys."""
        self.assertNotIn("DSA", families(normalize_tokens("ECDSA-P256")))
        self.assertIn("DSA", families(normalize_tokens("DSA")))
        self.assertFalse(algorithms_compatible("DSA-2048", "ECDSA-P256"))

    def test_dictionary_families_are_never_markers(self):
        """The whole-token-only families must have no substring path at all.

        Adding one to _FAMILY_MARKERS would reintroduce exactly the bug this
        module pins, so the invariant is asserted rather than trusted.
        """
        overlap = sorted({marker for marker, _ in _FAMILY_MARKERS} & _WHOLE_TOKEN_ONLY)
        self.assertEqual(overlap, [], f"dictionary-word families used as markers: {overlap}")


class TestAlgorithmCompatibility(unittest.TestCase):
    """A vaguer report counts; a different or contradictory one does not."""

    EXACT = [
        ("AES-256-GCM", "AES-256-GCM"),
        ("Ed25519", "Ed25519"),
        ("SHA-256", "SHA-256"),
        ("ML-KEM-768", "ML-KEM-768"),
    ]

    SPELLING = [
        ("AES-256-GCM", "aes256-gcm"),
        ("AES-256-GCM", "AES/GCM/NoPadding"),
        ("SHA-256", "SHA256"),
        ("SHA-256", "sha_256"),
        ("ML-KEM-768", "MLKEM768"),
        ("ML-KEM-768", "Kyber768"),
        ("Ed25519", "EdDSA"),
        ("ECDSA-P256", "secp256r1"),
        ("ECDSA-P256", "prime256v1"),
        ("ECDSA-P256", "P-256"),
    ]

    LESS_SPECIFIC = [
        ("AES-256-GCM", "AES"),
        ("RSA-2048", "RSA"),
        ("ML-KEM-768", "ML-KEM"),
        ("RSA-2048", "SHA256withRSA"),
    ]

    WRONG_FAMILY = [
        ("AES-256-GCM", "RSA"),
        ("Ed25519", "ECDSA-P256"),
        ("SHA-256", "SHA-512"),
        ("RSA-2048", "AES"),
        ("ML-KEM-768", "Ed25519"),
    ]

    CONTRADICTORY_PARAMETERS = [
        ("AES-256-GCM", "AES-128-GCM"),
        ("ML-KEM-768", "ML-KEM-512"),
        ("RSA-2048", "RSA-4096"),
    ]

    OPAQUE = [
        ("AES-256-GCM", "key@50ece37a-ae77-437c-a7e2-130a571b628b"),
        ("AES-256-GCM", ""),
        ("AES-256-GCM", "unknown"),
        ("AES-256-GCM", "other"),
    ]

    def test_exact_names_match(self):
        for planted, reported in self.EXACT:
            with self.subTest(planted=planted, reported=reported):
                self.assertTrue(algorithms_compatible(planted, reported))

    def test_spelling_differences_do_not_matter(self):
        for planted, reported in self.SPELLING:
            with self.subTest(planted=planted, reported=reported):
                self.assertTrue(algorithms_compatible(planted, reported))

    def test_less_specific_report_is_credited(self):
        for planted, reported in self.LESS_SPECIFIC:
            with self.subTest(planted=planted, reported=reported):
                self.assertTrue(algorithms_compatible(planted, reported))

    def test_wrong_family_is_rejected(self):
        for planted, reported in self.WRONG_FAMILY:
            with self.subTest(planted=planted, reported=reported):
                self.assertFalse(algorithms_compatible(planted, reported))

    def test_contradictory_parameters_are_rejected(self):
        for planted, reported in self.CONTRADICTORY_PARAMETERS:
            with self.subTest(planted=planted, reported=reported):
                self.assertFalse(algorithms_compatible(planted, reported))

    def test_opaque_identifiers_never_match(self):
        """A generator identifier is not an algorithm name."""
        for planted, reported in self.OPAQUE:
            with self.subTest(planted=planted, reported=reported):
                self.assertFalse(algorithms_compatible(planted, reported))

    def test_encoding_version_numbers_are_not_key_sizes(self):
        """Found in scoring the 2026-07-28 run, against a real generator.

        ``PKCS#8`` and ``PKCS#12`` name key-material structures; their digits are
        format versions. Reading them as key sizes made "RSA private key
        (PKCS#8)" contradict a planted RSA-2048, which simultaneously denied a
        correct detection and charged a false positive for the same component.

        This fix raises the maintainer's own tool's score, which is why it is
        pinned here and disclosed in the run notes.
        """
        self.assertTrue(algorithms_compatible("RSA-2048", "RSA private key (PKCS#8)"))
        self.assertTrue(algorithms_compatible("ECDSA-P256", "EC private key (SEC1)"))
        self.assertTrue(algorithms_compatible("ECDSA-P256", "PKCS#12 keystore EC key"))
        self.assertTrue(algorithms_compatible("Ed25519", "Ed25519 private key (PKCS#8)"))

    def test_real_size_contradictions_still_reject(self):
        """The narrower parameter rule must not stop catching real conflicts."""
        self.assertFalse(algorithms_compatible("AES-256-GCM", "AES-128-GCM"))
        self.assertFalse(algorithms_compatible("ML-KEM-768", "ML-KEM-512"))
        self.assertFalse(algorithms_compatible("RSA-2048", "RSA-4096"))
        self.assertFalse(algorithms_compatible("SHA-256", "SHA-512"))

    def test_jws_algorithm_names_resolve_to_their_family(self):
        """RS256 and ES256 name a family, and their digits are a digest size.

        A config that says ``RS256`` is credited by a report of ``RSA``. It is
        deliberately *not* credited by a report of ``RSA-2048``: the config does
        not state a key size, so naming one is an over-claim, and the 256 in
        RS256 refers to SHA-256 rather than to a modulus.
        """
        self.assertTrue(algorithms_compatible("RS256", "RSA"))
        self.assertTrue(algorithms_compatible("RS256", "RS256"))
        self.assertFalse(algorithms_compatible("RS256", "RSA-2048"))
        self.assertFalse(algorithms_compatible("RS256", "AES-256-GCM"))
        self.assertTrue(algorithms_compatible("ES256", "ECDSA"))

    def test_placeholder_names_do_not_match_everything(self):
        """'other' and 'unknown' are real cbomkit values; they must stay inert."""
        for placeholder in ("other", "unknown", "generic", "unspecified"):
            for planted in ("AES-256-GCM", "RSA-2048", "Ed25519", "ML-KEM-768"):
                with self.subTest(placeholder=placeholder, planted=planted):
                    self.assertFalse(algorithms_compatible(planted, placeholder))


class TestPathHandling(unittest.TestCase):
    FILES = frozenset(
        {
            "src/main.rs",
            "src/envelope.rs",
            "internal/seal/seal.go",
            "cmd/beacon-relay/main.go",
            "keys/relay-key.pem",
        }
    )

    def setUp(self):
        self.resolver = PathResolver(project_files=self.FILES)

    def test_normalize_strips_prefixes(self):
        self.assertEqual(normalize_path("./src/main.rs"), "src/main.rs")
        self.assertEqual(normalize_path("src\\main.rs"), "src/main.rs")
        self.assertEqual(normalize_path("  src/main.rs  "), "src/main.rs")

    def test_exact_paths_resolve(self):
        self.assertEqual(self.resolver.resolve("src/main.rs"), "src/main.rs")

    def test_absolute_clone_paths_resolve(self):
        """Generators run against a clone in a temp dir and report its path."""
        self.assertEqual(
            self.resolver.resolve("/tmp/cdxgen-1737/repo/internal/seal/seal.go"),
            "internal/seal/seal.go",
        )

    def test_ambiguous_basename_does_not_resolve(self):
        """Two files named main.go: a bare basename must not pick one."""
        resolver = PathResolver(project_files=frozenset({"a/main.go", "b/main.go"}))
        self.assertIsNone(resolver.resolve("main.go"))

    def test_unknown_path_does_not_resolve(self):
        self.assertIsNone(self.resolver.resolve("src/nonexistent.rs"))


class TestLocationMatching(unittest.TestCase):
    def test_requires_both_file_and_line(self):
        self.assertFalse(location_matches("a.go", 10, "a.go", None, line_tolerance=2))
        self.assertFalse(location_matches("a.go", 10, None, 10, line_tolerance=2))
        self.assertTrue(location_matches("a.go", 10, "a.go", 10, line_tolerance=2))

    def test_tolerance_is_symmetric_and_bounded(self):
        self.assertTrue(location_matches("a.go", 10, "a.go", 12, line_tolerance=2))
        self.assertTrue(location_matches("a.go", 10, "a.go", 8, line_tolerance=2))
        self.assertFalse(location_matches("a.go", 10, "a.go", 13, line_tolerance=2))

    def test_wrong_file_never_matches(self):
        self.assertFalse(location_matches("a.go", 10, "b.go", 10, line_tolerance=100))


if __name__ == "__main__":
    unittest.main()
