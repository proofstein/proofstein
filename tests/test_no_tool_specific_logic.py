# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""No scoring code may branch on which tool produced a document.

Proofstein is maintained by a party that also ships a scored tool. The
structural defence against that conflict of interest is that the scoring path
contains no way to express "if this is my tool". This test enforces it.

Vendor names are allowed -- encouraged, even -- in docstrings and comments,
because the reason a particular evidence shape is supported is exactly that
some real generator emits it, and that reasoning should be written down. What
is forbidden is a vendor name reachable by executing code: an identifier, a
dict key, a comparison, a lookup table entry.

The runtime counterpart is ``test_tool_name_does_not_affect_score`` in
test_scoring.py, which scores the same document under several tool names and
asserts the result never moves.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

#: Every module that participates in turning a CBOM into a number.
SCORING_PATH = [
    REPO_ROOT / "proofstein" / "cbom.py",
    REPO_ROOT / "proofstein" / "matching.py",
    REPO_ROOT / "proofstein" / "scoring.py",
    REPO_ROOT / "proofstein" / "inputs.py",
    REPO_ROOT / "proofstein" / "report.py",
    REPO_ROOT / "proofstein" / "schema.py",
    REPO_ROOT / "score.py",
]

#: Names of generators that are or could be scored, plus the maintainer's own.
VENDOR_NAMES = [
    "pqprobe",
    "cdxgen",
    "cbomkit",
    "cryptobomforge",
    "cryptobom",
    "deepseek",
    "mssbomtool",
    "sonarqube",
    "codeql",
    "ottenheimer",
]


def docstring_nodes(tree: ast.AST) -> set[int]:
    """Return ids of Constant nodes that are docstrings."""
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if not body:
                continue
            first = body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                if isinstance(first.value.value, str):
                    found.add(id(first.value))
    return found


class TestNoToolSpecificLogic(unittest.TestCase):
    def test_scoring_path_files_exist(self):
        for path in SCORING_PATH:
            with self.subTest(path=path.name):
                self.assertTrue(path.exists(), f"scoring path file missing: {path}")

    def test_no_vendor_name_in_executable_code(self):
        offences: list[str] = []

        for path in SCORING_PATH:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            docstrings = docstring_nodes(tree)

            for node in ast.walk(tree):
                # String literals that are not docstrings.
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if id(node) in docstrings:
                        continue
                    haystack = node.value.lower()
                    for vendor in VENDOR_NAMES:
                        if vendor in haystack:
                            offences.append(
                                f"{path.name}:{node.lineno}: string literal contains "
                                f"{vendor!r}: {node.value[:60]!r}"
                            )

                # Identifiers.
                for attribute in ("id", "name", "attr", "arg"):
                    value = getattr(node, attribute, None)
                    if isinstance(value, str):
                        lowered = value.lower()
                        for vendor in VENDOR_NAMES:
                            if vendor in lowered:
                                offences.append(
                                    f"{path.name}:{getattr(node, 'lineno', '?')}: "
                                    f"identifier {value!r} contains {vendor!r}"
                                )

        self.assertEqual(
            offences,
            [],
            "the scoring path must not be able to recognise a specific tool:\n  "
            + "\n  ".join(offences),
        )

    def test_vendor_names_are_actually_searched_for(self):
        """Guard against the guard silently matching nothing."""
        sample = "this mentions cdxgen and pqprobe"
        hits = [vendor for vendor in VENDOR_NAMES if vendor in sample]
        self.assertEqual(sorted(hits), ["cdxgen", "pqprobe"])


if __name__ == "__main__":
    unittest.main()
