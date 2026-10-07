#!/usr/bin/env python3
"""The cuts this run's README reports, read from score.py's results.json.

* full corpus: every planted asset;
* its languages: the projects in the source languages ecdsa-scan reads
  (go, javascript, python);
* signature assets: planted algorithm assets of signature schemes (SIGALG);
* both.

Precision figures are the scorer's own, summed over the projects in the cut.
Usage: cuts.py <results.json> [...]"""
import json, sys, collections
SIGALG = {"ECDSA-P256","Ed25519","RS256","RSA-2048","Falcon-1024","Falcon-512","LMS","ML-DSA","ML-DSA-65","SLH-DSA","XMSS"}
LANGS = {"go","javascript","python"}
def load(p): return json.load(open(p))["results"]
def agg(rs, assetfilter=lambda a: True, projfilter=lambda r: True):
    det=tot=0; cc=cm=comp=compm=fp=ph=um=0
    for r in rs:
        if not projfilter(r): continue
        for a in r["assets"]:
            if assetfilter(a): tot+=1; det+=a["detected"]
        cp=r["claim_precision"]; 
        cc+=r["credited_claims"]; cm+=r["evidence"]["distinct_claims"]
        compm+=r["matched_components"]; comp+=r["evidence"]["crypto_components"]
        fp+=r["false_positives"]; ph+=r["phantom_algorithm"]; um+=r["unmatched_reports"]
    pct=lambda a,b: f"{100*a/b:.0f}% ({a}/{b})" if b else "n/a (0/0)"
    return dict(recall=pct(det,tot), claim_precision=pct(cc,cm), component_precision=pct(compm,comp), false_positives=fp, phantom_algorithm=ph, unmatched=um)
for path in sys.argv[1:]:
    rs=load(path); print("==", path.split("/")[-2])
    sig=lambda a: a["cyclonedx_asset_type"]=="algorithm" and a["algorithm"] in SIGALG
    print("  full corpus      ", agg(rs))
    print("  its languages    ", agg(rs, projfilter=lambda r: r["language"] in LANGS))
    print("  signature assets ", agg(rs, sig))
    print("  sig, its langs   ", agg(rs, sig, lambda r: r["language"] in LANGS))
    for r in rs:
        print(f"    {r['project']:15} {r['language']:10} det {r['detected']}/{r['total']} claims {r['credited_claims']}/{r['evidence']['distinct_claims']} comps {r['evidence']['crypto_components']} FP {r['false_positives']} phantom {r['phantom_algorithm']} unmatched {r['unmatched_reports']} layers {{{', '.join(f'{k}:{v['detected']}/{v['total']}' for k,v in r['by_layer'].items())}}}")
