#!/usr/bin/env python3
"""Convert ecdsa-scan --json output to CycloneDX 1.6, mapping only what the
tool names: inventory algorithms and curves as algorithm components, inventory
libraries as library components, each at the files the tool lists (it gives no
lines). Operations and defect findings name no algorithm and are not mapped.
Usage: to_cbom.py <in.json> <out.json> [--no-curves] [--signature-only]"""
import hashlib, json, re, sys

SIG = re.compile(r"ecdsa|eddsa|ed25519|ed448|\brsa|rs256|ps256|es256|ml-?dsa|dilithium|slh-?dsa|sphincs|falcon|\blms\b|xmss|\bdsa\b|\bp-?(256|384|521)\b|secp\d+[rk]1", re.I)

def is_sig(c):
    return c.get("cryptoProperties", {}).get("assetType") == "algorithm" and SIG.search(c["name"] or "")

def convert(d, curves=True):
    comps = []
    def add(kind, name, files, typ):
        ref = hashlib.sha256(f"{kind}|{name}".encode()).hexdigest()[:16]
        c = {"type": typ, "bom-ref": f"{kind}-{ref}", "name": name,
             "evidence": {"occurrences": [{"location": f} for f in sorted(set(files))]}}
        if typ == "cryptographic-asset":
            c["cryptoProperties"] = {"assetType": "algorithm"}
        comps.append(c)
    inv = d.get("inventory") or {}
    for a in inv.get("algorithms", []):
        add("algorithm", a["name"], a["files"], "cryptographic-asset")
    if curves:
        for a in inv.get("curves", []):
            add("curve", a["name"], a["files"], "cryptographic-asset")
    for a in inv.get("libraries", []):
        add("library", a["name"], a["files"], "library")
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"tools": {"components": [{"type": "application", "name": d["tool"]["name"], "version": d["tool"]["version"]}]}},
            "components": comps}

if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    bom = convert(json.load(open(src)), curves="--no-curves" not in sys.argv)
    if "--signature-only" in sys.argv:
        bom["components"] = [c for c in bom["components"] if is_sig(c)]
    json.dump(bom, open(dst, "w"), indent=1)
