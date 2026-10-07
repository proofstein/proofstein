#!/usr/bin/env python3
"""Remove the scanning machine's paths from ecdsa-scan --json output.

ecdsa-scan records the absolute scan root ("root") and every finding's
absolute path ("absolutePath"). Both are dropped, and any other string that
carries the root is made relative to it, so nothing about the machine that
ran the scan is kept. Usage: strip.py <raw.json> <scan root>"""
import json
import sys

data = json.load(open(sys.argv[1]))
root = sys.argv[2].rstrip("/") + "/"


def clean(value):
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items() if k not in ("root", "absolutePath")}
    if isinstance(value, list):
        return [clean(v) for v in value]
    if isinstance(value, str):
        return value.replace(root, "").replace(root.rstrip("/"), ".")
    return value


out = clean(data)
text = json.dumps(out, indent=1)
if root.rstrip("/") in text:
    sys.exit("strip.py: the scan root survived stripping")
print(text)
