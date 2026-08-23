# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Generator configs carry names; the environment supplies paths.

A build root lives on whichever machine has the disk for it, so a config with a
literal path is correct on one host and wrong on every other. ${VAR} expansion
is what makes one config usable from either. The failure mode it must not have
is a quiet one: a run attributed to a binary that did not produce it.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_collector():
    """Import collect-cboms.py, whose filename is not a legal module name."""
    path = REPO_ROOT / "tools" / "collect-cboms.py"
    spec = importlib.util.spec_from_file_location("collect_cboms", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = _load_collector()


class TestExpansion(unittest.TestCase):
    def test_expands_in_strings_lists_and_nested_dicts(self):
        config = [
            {
                "name": "example",
                "binary": "${ROOT}/bin/tool",
                "invocation": ["${ROOT}/bin/tool", "--out", "{out}", "{project}"],
                "env": {"CACHE": "${ROOT}/cache"},
            }
        ]
        out = collector.expand_config_vars(config, {"ROOT": "/opt/x"})
        self.assertEqual(out[0]["binary"], "/opt/x/bin/tool")
        self.assertEqual(out[0]["invocation"][0], "/opt/x/bin/tool")
        self.assertEqual(out[0]["env"]["CACHE"], "/opt/x/cache")

    def test_placeholders_are_left_alone(self):
        """{out} and {project} are substituted later, per invocation."""
        out = collector.expand_config_vars(["${ROOT}", "{out}", "{project}"], {"ROOT": "/r"})
        self.assertEqual(out, ["/r", "{out}", "{project}"])

    def test_bare_dollar_is_not_an_expansion(self):
        """Braces are required, so a dollar in a path is not a silent variable."""
        out = collector.expand_config_vars("/opt/we$rd/bin", {})
        self.assertEqual(out, "/opt/we$rd/bin")

    def test_two_variables_in_one_string(self):
        out = collector.expand_config_vars("${A}/${B}", {"A": "/one", "B": "two"})
        self.assertEqual(out, "/one/two")


class TestUnsetVariableFailsLoudly(unittest.TestCase):
    def test_unset_variable_raises_naming_the_variable(self):
        with self.assertRaises(collector.UnsetVariable) as caught:
            collector.expand_config_vars({"binary": "${PQPROBE_STATIC_BIN}"}, {})
        self.assertIn("PQPROBE_STATIC_BIN", str(caught.exception))

    def test_every_missing_variable_is_named(self):
        with self.assertRaises(collector.UnsetVariable) as caught:
            collector.expand_config_vars(["${ALPHA}", "${BETA}"], {"BETA": "set"})
        message = str(caught.exception)
        self.assertIn("ALPHA", message)
        self.assertNotIn("BETA", message)

    def test_unset_never_becomes_empty_or_literal(self):
        """The two silent failures this exists to prevent."""
        with self.assertRaises(collector.UnsetVariable):
            collector.expand_config_vars("${NOT_SET_ANYWHERE}/scan", {})

    def test_collector_exits_nonzero_rather_than_running(self):
        """End to end: the process must refuse, not scan with a broken path."""
        env = {k: v for k, v in os.environ.items() if k != "PQPROBE_STATIC_BIN"}
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "collect-cboms.py"),
                "--config", str(REPO_ROOT / "runs" / "generators.json"),
                "--out", "/tmp/proofstein-should-not-be-created",
                "--tool", "pqprobe-static",
            ],
            capture_output=True,
            text=True,
            env=env,
            cwd=REPO_ROOT,
            timeout=120,
        )
        self.assertNotEqual(result.returncode, 0, "an unset variable must fail the run")
        self.assertIn("PQPROBE_STATIC_BIN", result.stderr)
        self.assertFalse(
            Path("/tmp/proofstein-should-not-be-created").exists(),
            "the run directory must not be created when the config cannot resolve",
        )


class TestShippedConfig(unittest.TestCase):
    def test_pqprobe_entry_uses_the_variable(self):
        config = json.loads((REPO_ROOT / "runs" / "generators.json").read_text())
        entry = next(t for t in config["tools"] if t["name"] == "pqprobe-static")
        self.assertIn("${PQPROBE_STATIC_BIN}", entry["binary"])
        self.assertIn("${PQPROBE_STATIC_BIN}", entry["invocation"][0])

    def test_the_variable_is_documented(self):
        config = json.loads((REPO_ROOT / "runs" / "generators.json").read_text())
        self.assertIn("PQPROBE_STATIC_BIN", "\n".join(config["_comment"]))

    def test_cdxgen_needs_no_variable(self):
        """It is invoked through a pinned image, so it is already portable."""
        config = json.loads((REPO_ROOT / "runs" / "generators.json").read_text())
        entry = next(t for t in config["tools"] if t["name"] == "cdxgen")
        self.assertNotIn("${", entry["binary"])


def _public_run() -> Path:
    """The public run in the tree. Discovered, never named.

    Run directories are named for the minute they started, so hard-coding one
    breaks on the next run. That is the same brittleness the naming convention
    itself had when it used the date alone.
    """
    runs = sorted((REPO_ROOT / "runs").glob("*-public"))
    if not runs:
        raise unittest.SkipTest("no public run in the tree")
    return runs[-1]


class TestManifestRecordsResolvedPaths(unittest.TestCase):
    """A run record must say what ran, not what the config asked for."""

    def test_manifest_holds_a_resolved_path_and_a_digest(self):
        """The config's variable must be gone, and identity must be pinned.

        The recorded path is normalised, repository-relative, or
        <external>/<filename> for a binary that lived outside the checkout,
        because the absolute paths of the machine that ran a scan are not a
        property of the run. What identifies the binary is binary_sha256, which
        is never rewritten.
        """
        manifest = json.loads((_public_run() / "manifest.json").read_text())
        entry = manifest["tools"]["pqprobe-static"]
        self.assertNotIn("${", entry["binary"], "a manifest must not carry a placeholder")
        self.assertRegex(entry["binary_sha256"] or "", r"^[0-9a-f]{64}$")

    def test_manifest_carries_no_machine_paths(self):
        for run in sorted((REPO_ROOT / "runs").glob("*-*")):
            manifest = run / "manifest.json"
            if not manifest.is_file():
                continue
            raw = manifest.read_text()
            for leak in ("/home/", "/mnt/", "/tmp/claude"):
                self.assertNotIn(leak, raw, f"{run.name} manifest carries {leak}")


class TestRecordedVersionIsPlainText(unittest.TestCase):
    """A version banner is provenance, so it must survive as readable text.

    cdxgen bolds its banner. Left alone, the escape sequence travels from the
    version command into the manifest and out into the published results table,
    where it renders as literal noise wrapped around the version number.
    """

    def test_ansi_styling_is_stripped(self):
        spec = {"version_command": [
            sys.executable, "-c",
            r"print('\x1b[1mCycloneDX Generator 12.8.2\x1b[0m')",
        ]}
        self.assertEqual(collector.tool_version(spec), "CycloneDX Generator 12.8.2")

    def test_plain_output_is_untouched(self):
        spec = {"version_command": [sys.executable, "-c", "print('PQProbe Static v3.6.0')"]}
        self.assertEqual(collector.tool_version(spec), "PQProbe Static v3.6.0")

    def test_shipped_manifests_carry_no_escapes(self):
        """Checked against parsed values, not the file text.

        json.dump writes the escape as the six characters \\u001b, so searching
        the raw text for a real ESC byte passes on a manifest that carries one.
        """
        for run in sorted((REPO_ROOT / "runs").glob("*-*")):
            manifest = run / "manifest.json"
            if not manifest.is_file():
                continue
            tools = json.loads(manifest.read_text())["tools"]
            for name, entry in tools.items():
                self.assertNotIn(
                    "\x1b", str(entry.get("version", "")),
                    f"{run.name}: {name} version carries terminal styling",
                )


if __name__ == "__main__":
    unittest.main()
