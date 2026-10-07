#!/usr/bin/env python3
"""Select the opengrep-rules snapshot's cryptography rules: every rule whose
metadata names one of the CWEs below, in the languages the corpus uses plus
generic and yaml. Writes one rule file per selected file under <out>.
Usage: select_rules.py <opengrep-rules> <out>"""
import os, re, sys, yaml, shutil
CWES = {295, 296, 297, 321, 323, 324, 326, 327, 328, 329, 330, 331, 335, 337, 338, 347, 757, 759, 760, 780, 916, 1204, 1240}
DIRS = {"c", "go", "java", "javascript", "typescript", "python", "rust", "generic", "yaml", "kotlin"}
src, out = sys.argv[1], sys.argv[2]
shutil.rmtree(out, ignore_errors=True)
n = 0
for d in sorted(DIRS):
    for root, _, files in os.walk(os.path.join(src, d)):
        for f in files:
            if not f.endswith((".yaml", ".yml")) or f.endswith(".test.yaml"):
                continue
            p = os.path.join(root, f)
            try:
                doc = yaml.safe_load(open(p))
            except Exception:
                continue
            if not isinstance(doc, dict) or "rules" not in doc:
                continue
            keep = []
            for r in doc["rules"]:
                cwe = (r.get("metadata") or {}).get("cwe") or []
                cwe = cwe if isinstance(cwe, list) else [cwe]
                nums = {int(m) for c in cwe for m in re.findall(r"CWE-(\d+)", str(c))}
                if nums & CWES:
                    keep.append(r)
            if keep:
                dst = os.path.join(out, os.path.relpath(p, src))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                yaml.safe_dump({"rules": keep}, open(dst, "w"), sort_keys=False)
                n += len(keep)
print(n, "rules selected")
