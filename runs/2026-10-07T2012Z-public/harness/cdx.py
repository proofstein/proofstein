"""Shared CycloneDX 1.6 writer for the converters: one component per name,
with every (file, line) the tool reported for it."""
import hashlib, json, sys

def bom(tool, version, sightings, component_type="cryptographic-asset"):
    by = {}
    for name, path, line in sightings:
        by.setdefault(name, set()).add((path, line))
    comps = []
    for name in sorted(by):
        occ = []
        for path, line in sorted(by[name], key=lambda x: (x[0], x[1] or 0)):
            o = {"location": path}
            if line:
                o["line"] = line
            occ.append(o)
        comps.append({"type": component_type,
                      "bom-ref": "alg-" + hashlib.sha256(name.encode()).hexdigest()[:16],
                      "name": name, "cryptoProperties": {"assetType": "algorithm"},
                      "evidence": {"occurrences": occ}})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"tools": {"components": [{"type": "application", "name": tool, "version": version}]}},
            "components": comps}

def emit(doc):
    json.dump(doc, sys.stdout, indent=1)
    sys.stdout.write("\n")
