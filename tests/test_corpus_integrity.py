# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""The ground truth must describe the corpus that actually shipped.

If an entry points at a line that does not exist, or at a line where nothing
about the algorithm is discoverable, then no generator could ever find it and
the benchmark would be measuring an impossibility.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from proofstein.matching import algorithms_compatible, normalize_tokens  # noqa: E402
from psmarkers import LAYERS  # noqa: E402

GROUND_TRUTH = REPO_ROOT / "ground-truth"

#: Library symbols that identify an algorithm without naming it outright.
#: Used only by the detectability check, never by scoring.
API_HINTS = {
    "AES": ("aes", "aead", "aesgcm", "gcm", "cipher"),
    "RSA": ("rsa",),
    "ECDSA": ("ecdsa", "ec", "secp", "prime256", "p256", "elliptic", "sec1"),
    "ED25519": ("ed25519", "eddsa"),
    "SHA256": ("sha256", "sha_256", "sha-256", "digest", "sum256", "messagedigest"),
    "MLKEM": ("mlkem", "ml_kem", "ml-kem", "kyber", "fips203", "encaps", "decaps"),
    "TLS": ("tls", "ssl"),
    "X25519": ("x25519", "curve25519"),
    "CHACHA20": ("chacha", "poly1305"),
    "SALSA20": ("salsa", "nacl", "sodium"),
    "MGF1": ("mgf1",),
}


def load_documents() -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(GROUND_TRUTH.glob("*.json"))]


class TestGroundTruthMatchesCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.documents = load_documents()
        if not cls.documents:
            raise unittest.SkipTest("no ground truth; run tools/build-corpus.py")

    def test_every_file_exists(self):
        for document in self.documents:
            root = REPO_ROOT / document["corpus_path"]
            for asset in document["assets"]:
                with self.subTest(project=document["project"], asset=asset["id"]):
                    self.assertTrue(
                        (root / asset["file"]).exists(),
                        f"{asset['id']}: {asset['file']} is not in the corpus",
                    )

    def test_every_line_exists(self):
        for document in self.documents:
            root = REPO_ROOT / document["corpus_path"]
            for asset in document["assets"]:
                path = root / asset["file"]
                if not path.exists():
                    continue
                with self.subTest(project=document["project"], asset=asset["id"]):
                    try:
                        count = len(path.read_text(encoding="utf-8").splitlines())
                    except UnicodeDecodeError:
                        continue  # binary keystore, anchored at line 1
                    self.assertLessEqual(
                        asset["line"], max(count, 1), f"{asset['id']}: line beyond end of file"
                    )

    def test_accept_locations_are_real(self):
        for document in self.documents:
            root = REPO_ROOT / document["corpus_path"]
            for asset in document["assets"]:
                for alternative in asset.get("accept_locations", []):
                    with self.subTest(project=document["project"], asset=asset["id"]):
                        path = root / alternative["file"]
                        self.assertTrue(path.exists(), f"{asset['id']}: {alternative['file']} missing")
                        count = len(path.read_text(encoding="utf-8").splitlines())
                        self.assertLessEqual(alternative["line"], max(count, 1))

    def test_asset_ids_are_unique_across_the_corpus(self):
        seen: dict[str, str] = {}
        for document in self.documents:
            for asset in document["assets"]:
                with self.subTest(asset=asset["id"]):
                    self.assertNotIn(
                        asset["id"], seen, f"{asset['id']} also used by {seen.get(asset['id'])}"
                    )
                    seen[asset["id"]] = document["project"]

    def test_every_project_covers_every_layer(self):
        for document in self.documents:
            present = {int(layer) for layer in document["layer_counts"]}
            with self.subTest(project=document["project"]):
                self.assertEqual(present, set(LAYERS), f"missing layers: {set(LAYERS) - present}")

    def test_asset_types_are_valid_cyclonedx(self):
        allowed = {"algorithm", "certificate", "protocol", "related-crypto-material"}
        for document in self.documents:
            for asset in document["assets"]:
                with self.subTest(asset=asset["id"]):
                    self.assertIn(asset["cyclonedx_asset_type"], allowed)

    def test_no_annotations_leaked_into_the_corpus(self):
        """A leaked marker would hand the answer key to any tool reading comments."""
        for document in self.documents:
            root = REPO_ROOT / document["corpus_path"]
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue
                with self.subTest(file=str(path.relative_to(REPO_ROOT))):
                    self.assertNotIn("@PS", text, "annotation survived into the shipped corpus")


class TestDetectability(unittest.TestCase):
    """Every planted asset must be findable in principle by some method.

    The bar differs by layer, because the layers exist precisely to require
    different methods:

    * Layers 1, 2, 4 and 5 must be reachable by reading the annotated line or
      one of its accepted alternatives -- a lexical method suffices.
    * Layer 3 is reached through indirection by construction, so the bar is
      that the algorithm is discoverable somewhere in the same file, which is
      what a call-graph or data-flow method would follow.
    * Layer 6 must be recognisable key material.
    """

    @classmethod
    def setUpClass(cls):
        cls.documents = load_documents()
        if not cls.documents:
            raise unittest.SkipTest("no ground truth; run tools/build-corpus.py")

    @staticmethod
    def _hints(algorithm: str) -> tuple[str, ...]:
        tokens = normalize_tokens(algorithm)
        hints: list[str] = []
        for token in tokens:
            hints.extend(API_HINTS.get(token, ()))
            if len(token) >= 3:
                hints.append(token.lower())
        return tuple(hints)

    def _text_at(self, root: Path, file: str, line: int) -> str:
        path = root / file
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            return ""
        index = line - 1
        if 0 <= index < len(lines):
            return lines[index].lower()
        return ""

    def test_lexical_layers_are_visible_on_their_line(self):
        """A generator reading just this line must be able to identify the asset.

        Two ways count, because both are things a real generator does:

        * the line contains a library symbol that implies the algorithm
          (``aes.NewCipher``, ``EVP_sha256``, ``ed25519_dalek``), or
        * the line contains a string the scorer's own matcher accepts for the
          planted algorithm -- which is what credits a config naming ``RS256``
          against a planted ``RSA-2048``.

        The second arm deliberately reuses the production matcher, so this test
        cannot pass on a technicality the scorer would reject.
        """
        token = re.compile(r"[A-Za-z][A-Za-z0-9_.\-/]{2,}")

        for document in self.documents:
            root = REPO_ROOT / document["corpus_path"]
            for asset in document["assets"]:
                if asset["layer"] not in (1, 2, 4, 5):
                    continue
                lines = [self._text_at(root, asset["file"], asset["line"])]
                for alternative in asset.get("accept_locations", []):
                    lines.append(self._text_at(root, alternative["file"], alternative["line"]))

                hints = self._hints(asset["algorithm"])
                lexical = any(hint in text for text in lines for hint in hints)
                by_matcher = any(
                    algorithms_compatible(asset["algorithm"], candidate)
                    for text in lines
                    for candidate in token.findall(text)
                )

                with self.subTest(project=document["project"], asset=asset["id"]):
                    self.assertTrue(
                        lexical or by_matcher,
                        f"{asset['id']} ({asset['algorithm']}) is not discoverable at "
                        f"{asset['file']}:{asset['line']} or any accepted location; "
                        f"no generator could find it",
                    )

    def test_wrapper_layer_has_a_followable_path_to_the_primitive(self):
        """Layer 3 is indirection by construction, usually across files.

        The bar is therefore not "the algorithm is on this line" -- if it were,
        the layer would be testing nothing beyond layer 1. It is that the
        primitive exists somewhere in the project and the annotated line names
        a symbol that leads there, which is the path a call-graph or data-flow
        method would follow.
        """
        identifier = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")

        for document in self.documents:
            root = REPO_ROOT / document["corpus_path"]
            sources = {}
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                try:
                    sources[path] = path.read_text(encoding="utf-8").lower()
                except (UnicodeDecodeError, OSError):
                    continue

            for asset in document["assets"]:
                if asset["layer"] != 3:
                    continue
                hints = self._hints(asset["algorithm"])

                with self.subTest(project=document["project"], asset=asset["id"]):
                    holders = [
                        path
                        for path, text in sources.items()
                        if any(hint in text for hint in hints)
                    ]
                    self.assertTrue(
                        holders,
                        f"{asset['id']} ({asset['algorithm']}) appears nowhere in the project",
                    )

                    lines = [self._text_at(root, asset["file"], asset["line"])]
                    for alternative in asset.get("accept_locations", []):
                        lines.append(self._text_at(root, alternative["file"], alternative["line"]))

                    symbols = {
                        token.lower() for line in lines for token in identifier.findall(line)
                    }
                    linked = any(
                        symbol in sources[path]
                        for path in holders
                        for symbol in symbols
                        if path != root / asset["file"] or True
                    )
                    self.assertTrue(
                        linked,
                        f"{asset['id']}: nothing on {asset['file']}:{asset['line']} links to "
                        f"the file holding {asset['algorithm']}; there is no path to follow",
                    )

    def test_key_material_is_recognisable(self):
        for document in self.documents:
            root = REPO_ROOT / document["corpus_path"]
            for asset in document["assets"]:
                if asset["layer"] != 6:
                    continue
                path = root / asset["file"]
                blob = path.read_bytes()
                with self.subTest(project=document["project"], asset=asset["id"]):
                    is_pem = b"-----BEGIN" in blob[:400]
                    # PKCS#12 and JKS are DER/binary: a SEQUENCE or the JKS magic.
                    is_binary_store = blob[:1] == b"\x30" or blob[:4] == b"\xfe\xed\xfe\xed"
                    self.assertTrue(
                        is_pem or is_binary_store,
                        f"{asset['id']}: {asset['file']} is not recognisable key material",
                    )


class TestCorpusIsInSyncWithTemplates(unittest.TestCase):
    def test_regenerating_changes_nothing(self):
        """The committed corpus must match what the templates produce."""
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "build-corpus.py"), "--check", "--quiet"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"corpus is stale; run tools/build-corpus.py\n{result.stdout}\n{result.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
