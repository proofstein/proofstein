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
    plausibly could: a filename, an identifier, a word from a comment. None
    produces a family, so none is charged as a false positive or credited.
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

    def test_post_quantum_signature_families_are_distinct(self):
        """ML-DSA, SLH-DSA, FN-DSA and DSA share a suffix, not a family."""
        self.assertEqual(families(normalize_tokens("ML-DSA-65")), {"MLDSA"})
        self.assertEqual(families(normalize_tokens("SLH-DSA")), {"SLHDSA"})
        self.assertEqual(families(normalize_tokens("SPHINCS+")), {"SLHDSA"})
        self.assertEqual(families(normalize_tokens("FN-DSA")), {"FALCON"})
        self.assertEqual(families(normalize_tokens("Falcon-1024")), {"FALCON"})
        self.assertEqual(families(normalize_tokens("DSA-2048")), {"DSA"})
        for left, right in [
            ("ML-DSA", "DSA"),
            ("SLH-DSA", "DSA"),
            ("ML-DSA", "SLH-DSA"),
            ("ML-DSA", "FN-DSA"),
            ("SLH-DSA", "FN-DSA"),
            ("Falcon-1024", "DSA"),
            ("Falcon-1024", "Falcon-512"),
        ]:
            with self.subTest(left=left, right=right):
                self.assertFalse(algorithms_compatible(left, right))
                self.assertFalse(algorithms_compatible(right, left))
        self.assertTrue(algorithms_compatible("Falcon-1024", "FN-DSA"))
        self.assertTrue(algorithms_compatible("Falcon-512", "falcon512"))

    def test_stateful_hash_signatures_are_families(self):
        """LMS and XMSS are families."""
        for name in ("LMS", "lms_sha256_n32_h10", "LMSigParameters", "wc_LmsKey_SetLmsParm"):
            with self.subTest(name=name):
                self.assertIn("LMS", families(normalize_tokens(name)))
        for name in ("XMSS", "XMSS-SHA2_10_256"):
            with self.subTest(name=name):
                self.assertIn("XMSS", families(normalize_tokens(name)))
        self.assertNotIn("LMS", families(normalize_tokens("helms")))
        self.assertFalse(algorithms_compatible("LMS", "XMSS"))

    def test_a_mode_alone_does_not_identify_a_cipher(self):
        """A report sharing only a mode with the plant does not find it."""
        self.assertFalse(algorithms_compatible("AES-256-GCM", "gcm-detection"))
        self.assertFalse(algorithms_compatible("AES-256-GCM", "GCM"))
        self.assertTrue(algorithms_compatible("AES-256-GCM", "AES"))
        self.assertTrue(algorithms_compatible("AES-256-GCM", "AES/GCM/NoPadding"))

    def test_dictionary_families_are_never_markers(self):
        """The whole-token-only families must have no substring path at all.

        No family in _WHOLE_TOKEN_ONLY appears in _FAMILY_MARKERS.
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
        """``PKCS#8`` and ``PKCS#12`` digits are format versions, not key sizes.

        They name key-material structures, so "RSA private key (PKCS#8)" is
        compatible with a planted RSA-2048.
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
        """A JOSE name is its algorithm, and its number is a digest length.

        RS256 is RSA with SHA-256 at whatever modulus the key has, so it neither
        contradicts nor states a key size: ``RSA-2048`` credits it like any more
        specific report of the same family. ES256, ES384 and ES512 do fix their
        curve, so ES384 is not ECDSA on P-256.
        """
        for jose in ("RS256", "RS384", "RS512", "PS256", "RSA-OAEP-256"):
            with self.subTest(jose=jose):
                self.assertEqual(families(normalize_tokens(jose)), {"RSA"})
                self.assertTrue(algorithms_compatible(jose, "RSA"))
                self.assertTrue(algorithms_compatible(jose, "RSA-2048"))
                self.assertTrue(algorithms_compatible("RSA-2048", jose))
                self.assertFalse(algorithms_compatible(jose, "AES-256-GCM"))
                self.assertFalse(algorithms_compatible(jose, "SHA-256"))
        self.assertTrue(algorithms_compatible("RS256", "RS256"))
        self.assertTrue(algorithms_compatible("PS256", "RSASSA-PSS"))
        self.assertTrue(algorithms_compatible("RSA-OAEP-256", "RSA-OAEP"))
        self.assertTrue(algorithms_compatible("ES256", "ECDSA"))
        self.assertTrue(algorithms_compatible("ES256", "ECDSA-P256"))
        self.assertTrue(algorithms_compatible("ES384", "secp384r1"))
        self.assertFalse(algorithms_compatible("ES384", "ECDSA-P256"))
        self.assertFalse(algorithms_compatible("ES256", "ECDH-P256"))

    def test_ecdh_is_not_ecdsa(self):
        """Key agreement and signature on one curve are different assets."""
        self.assertEqual(families(normalize_tokens("ECDH-P256")), {"ECDH"})
        self.assertEqual(families(normalize_tokens("BCRYPT_ECDH_P256_ALGORITHM")), {"ECDH"})
        self.assertFalse(algorithms_compatible("ECDH-P256", "ECDSA-P256"))
        self.assertFalse(algorithms_compatible("ECDSA-P256", "ECDH-P256"))
        self.assertFalse(algorithms_compatible("ECDH-P256", "ECDSA"))
        self.assertTrue(algorithms_compatible("ECDH-P256", "ECDH"))
        self.assertTrue(algorithms_compatible("ECDH-P256", "BCRYPT_ECDH_P256_ALGORITHM"))
        self.assertFalse(algorithms_compatible("ECDH-P256", "ECDH-P384"))
        # A curve alone states no use; see test_a_bare_curve_credits_either_use.
        self.assertTrue(algorithms_compatible("ECDSA-P256", "secp256r1"))
        self.assertTrue(algorithms_compatible("ECDH-P256", "secp256r1"))
        # A cipher suite carries both.
        self.assertTrue(algorithms_compatible("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDH"))
        self.assertTrue(algorithms_compatible("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDSA"))

    def test_a_bare_curve_credits_either_use(self):
        """A curve name, or EC alone, credits an ECDSA or an ECDH plant on that curve."""
        for report in ("P-256", "secp256r1", "prime256v1", "NIST P-256", "EC"):
            for planted in ("ECDSA-P256", "ECDH-P256"):
                with self.subTest(report=report, planted=planted):
                    self.assertTrue(algorithms_compatible(planted, report))
        for planted in ("ECDSA-P256", "ECDH-P256"):
            with self.subTest(planted=planted):
                self.assertFalse(algorithms_compatible(planted, "P-384"))
                self.assertFalse(algorithms_compatible(planted, "secp384r1"))
        self.assertTrue(algorithms_compatible("ECDH-P384", "P-384"))

    def test_a_named_use_credits_only_its_family(self):
        """A report that says ECDSA or ECDH credits only that use, on any curve."""
        for report in ("ECDSA", "ECDSA-P256", "ECDSA with P-256", "ECDSA-SHA256", "ES256"):
            with self.subTest(report=report):
                self.assertTrue(algorithms_compatible("ECDSA-P256", report))
                self.assertFalse(algorithms_compatible("ECDH-P256", report))
        for report in ("ECDH", "ECDH-P256", "ECDH on secp256r1", "BCRYPT_ECDH_P256_ALGORITHM"):
            with self.subTest(report=report):
                self.assertTrue(algorithms_compatible("ECDH-P256", report))
                self.assertFalse(algorithms_compatible("ECDSA-P256", report))

    def test_hybrid_group_needs_both_halves(self):
        """A hybrid is found by naming it, not by naming one of its halves."""
        for planted in ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"):
            with self.subTest(planted=planted):
                self.assertTrue(algorithms_compatible(planted, planted))
                self.assertTrue(algorithms_compatible(planted, planted.lower()))
                self.assertFalse(algorithms_compatible(planted, "ML-KEM"))
        self.assertTrue(algorithms_compatible("X25519MLKEM768", "X25519 + ML-KEM-768"))
        self.assertTrue(algorithms_compatible("X25519MLKEM768", "X25519-ML-KEM-768"))
        self.assertFalse(algorithms_compatible("X25519MLKEM768", "X25519"))
        self.assertFalse(algorithms_compatible("X25519MLKEM768", "ML-KEM-768"))
        self.assertFalse(algorithms_compatible("X25519MLKEM768", "X25519MLKEM1024"))
        self.assertFalse(algorithms_compatible("SecP256r1MLKEM768", "ECDSA-P256"))
        self.assertFalse(algorithms_compatible("SecP256r1MLKEM768", "ECDH-P256"))
        self.assertFalse(algorithms_compatible("SecP384r1MLKEM1024", "SecP256r1MLKEM768"))
        # A list separator lists two groups; it does not compose them.
        self.assertFalse(algorithms_compatible("X25519MLKEM768", "X25519:MLKEM768"))
        # A hybrid report names each half, at its own parameters.
        self.assertTrue(algorithms_compatible("ML-KEM-768", "X25519MLKEM768"))
        self.assertTrue(algorithms_compatible("X25519", "X25519MLKEM768"))
        self.assertFalse(algorithms_compatible("ML-KEM-512", "X25519MLKEM768"))
        self.assertEqual(families(normalize_tokens("SecP256r1MLKEM768")), {"ECDH", "MLKEM"})

    def test_curve_and_group_names_have_families(self):
        self.assertEqual(families(normalize_tokens("P-384")), {"EC"})
        self.assertEqual(families(normalize_tokens("P-521")), {"EC"})
        self.assertTrue(algorithms_compatible("ECDSA-P384", "P-384"))
        self.assertFalse(algorithms_compatible("ECDSA-P256", "P-384"))
        self.assertTrue(algorithms_compatible("secp521r1", "P-521"))
        self.assertEqual(families(normalize_tokens("X448")), {"X448"})
        self.assertEqual(families(normalize_tokens("Ed448")), {"ED448"})
        self.assertFalse(algorithms_compatible("X448", "X25519"))
        self.assertFalse(algorithms_compatible("Ed448", "Ed25519"))
        for name in ("ffdhe2048", "ffdhe3072", "FFDHE-4096", "ffdhe6144"):
            with self.subTest(name=name):
                self.assertEqual(families(normalize_tokens(name)), {"DH"})
        self.assertTrue(algorithms_compatible("ffdhe3072", "DH"))
        self.assertFalse(algorithms_compatible("ffdhe3072", "ffdhe2048"))

    def test_a_shared_number_identifies_nothing(self):
        """A name with no family is not credited by another family sharing its number."""
        self.assertFalse(algorithms_compatible("Widget-2048", "RSA-2048"))
        self.assertFalse(algorithms_compatible("ffdhe2048", "RSA-2048"))
        self.assertFalse(algorithms_compatible("RSA-2048", "2048"))

    def test_bcrypt_is_a_family_and_cng_is_not_bcrypt(self):
        """The password hash is a family; the Windows CNG prefix is not that hash."""
        self.assertEqual(families(normalize_tokens("bcrypt")), {"BCRYPT"})
        self.assertEqual(families(normalize_tokens("BCryptOpenAlgorithmProvider")), set())
        self.assertNotIn("BCRYPT", families(normalize_tokens("BCRYPT_ECDH_P256_ALGORITHM")))
        self.assertNotIn("BCRYPT", families(normalize_tokens("BCRYPT_RSA_ALGORITHM")))
        self.assertFalse(algorithms_compatible("bcrypt", "scrypt"))

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


class TestNumbersBetweenFamilylessNames(unittest.TestCase):
    def test_a_keystore_file_still_names_its_container(self):
        """Two familyless names may share only a number; that link is kept."""
        self.assertTrue(algorithms_compatible("PKCS#12", "ledger-node.p12"))

    def test_a_bare_parameter_does_not_credit_another_family(self):
        """The 512 of an ML-KEM report is not a report of Falcon-512."""
        self.assertFalse(algorithms_compatible("Falcon-512", "512"))
        self.assertFalse(algorithms_compatible("AES-256-GCM", "256"))


class TestCombinedSignatureNames(unittest.TestCase):
    """SHA256withECDSA names the signature scheme and the digest."""

    def test_a_combined_name_credits_both_halves(self):
        for planted, reported in [
            ("ECDSA-P256", "SHA256withECDSA"),
            ("SHA-256", "SHA256withECDSA"),
            ("ECDSA-P384", "SHA384withECDSA"),
            ("SHA-384", "SHA384withECDSA"),
            ("RSA-2048", "SHA384withRSA"),
            ("SHA-384", "SHA384withRSA"),
            ("RSA-2048", "SHA256withRSA/PSS"),
            ("SHA-256", "sha256WithRSAEncryption"),
        ]:
            with self.subTest(planted=planted, reported=reported):
                self.assertTrue(algorithms_compatible(planted, reported))

    def test_a_combined_name_credits_nothing_else(self):
        for planted, reported in [
            ("ECDH-P256", "SHA256withECDSA"),
            ("RSA-2048", "SHA256withECDSA"),
            ("SHA-384", "SHA256withECDSA"),
            ("SHA-256", "SHA384withRSA"),
            ("ECDSA-P256", "SHA256withRSA"),
        ]:
            with self.subTest(planted=planted, reported=reported):
                self.assertFalse(algorithms_compatible(planted, reported))
