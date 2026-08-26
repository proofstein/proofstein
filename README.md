# Proofstein

Proofstein is meant to be a simple test of how much of the cryptography in a 
codebase a post-quantum inventory tool actually inventories. "Proof is in 
the stein" as the people testing for gold used to say. 

It contains six small programs for testing, one each in C, Go, Java, 
JavaScript, Python and Rust. Between them they use cryptography a known 
amount, and exactly where. Some sit in plain sight, as a direct call to an 
encryption function. Others are tucked away: behind a wrapper, chosen in a 
config file, or only listed as a dependency.

Run any tool over the six test programs, feed the tool results to the scorer, 
and see what the tool found and what it didn't, by language and method hidden.

## Check a tool

Everything you need is meant to be here. The six programs and answers are in 
the repository, with the scorer as a single script. There is nothing to
compile.

**1. Installation and Setup.**

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

Most current Linux distributions refuse a plain `pip install` outside a
virtual environment, so the two steps are given together. If you would rather
activate the environment, `source .venv/bin/activate` and then `pip install -r
requirements.txt` does the same thing, and every `.venv/bin/python` below
becomes plain `python`.

**2. Run your tool over each of the six programs**, saving one CycloneDX 1.6
CBOM file per program:

| program | where it is | language |
|---|---|---|
| `tinyattest` | `corpus/c/tinyattest` | C |
| `beacon-relay` | `corpus/go/beacon-relay` | Go |
| `ledger-svc` | `corpus/java/ledger-svc` | Java |
| `session-broker` | `corpus/javascript/session-broker` | JavaScript/TypeScript |
| `vaultkeeper` | `corpus/python/vaultkeeper` | Python |
| `sealbox` | `corpus/rust/sealbox` | Rust |

Put all six files in one folder and name them `<program>__<tool>.json`, with
two underscores in the middle. For example: `sealbox__mytool.json`.

**3. Scoring.**

```bash
.venv/bin/python score.py --cboms my-cboms/ --out my-results/
```

You get `my-results/results.md`. It shows four things:

- how much the tool found in each language
- how much it found at each kind of hiding place
- how much of what it reported was actually correct
- how often it reported something that isn't there

The scorer needs no network, no Docker and nothing running in the
background.

### What counts as finding something

A tool has to say **where** it found the cryptography, not just that it is
somewhere in the project. Knowing that a codebase uses RSA does not help you
replace it; you need to know which file to open. So a report that names an
algorithm but no file is not counted.

A report counts when it names the right algorithm in the right file. It does
not have to name the right line. Tools disagree about that: some point at
the import, some at the call a few lines below. Both are telling you the
same useful thing. The line each tool reported is still shown, just not
scored.

`results.md` also has a column showing what the score would have been if
naming the algorithm alone were enough. The gap between the two is what a
looser benchmark would have given away.

The full rules are in [METHODOLOGY.md](METHODOLOGY.md), sections 3 and 3.3.

## An example run

[`runs/2026-08-23T1519Z-public/`](runs/2026-08-23T1519Z-public/) has a complete scored
run already done: three tools, cdxgen 12.8.2, pqprobe-static 3.6.0 and
sonar-cryptography 1.6.1, with their output files and their scores. You can
re-score it yourself and check you get the same numbers:

```bash
.venv/bin/python score.py --cboms runs/2026-08-23T1519Z-public/cboms --out /tmp/proofstein
diff <(grep -A5 'by language' /tmp/proofstein/results.md) <(grep -A5 'by language' runs/2026-08-23T1519Z-public/results/results.md)
```

One thing to know before reading those numbers. sonar-cryptography reads Java,
Python and Go, and not the other three languages, so it is scored over 67 of the
124 assets instead of all of them. Its overall percentage is not comparable with
the other two tools'; compare the per-language rows instead, where all three
tools are measured against the same programs. The run's own README explains this
at more length.

The same three tools were also run over a scrambled copy of the six programs,
to check they were finding cryptography rather than being tuned to these
particular files. Those results are in
[`runs/2026-08-23T1519Z-holdout/`](runs/2026-08-23T1519Z-holdout/).

To run the tests: `.venv/bin/python -m unittest discover -s tests`.

## More detail

- [METHODOLOGY.md](METHODOLOGY.md): the scoring rules in full, what each
  kind of hiding place means, and every case where a tool is given the
  benefit of the doubt.
- [docs/pending-review.md](docs/pending-review.md): a log of every
  judgement call that could have changed somebody's score.

## Who maintains this

Proofstein is maintained by Ottenheimer GmbH, who also makes one of the tools it
scores. That is a conflict of interest, which is addressed by openly
recording every decision that could move a score, in the
[docs/pending-review.md](docs/pending-review.md) file, so anyone can check. If 
you have a better idea, submit it to the repository. Feedback wanted.
The safeguards are described in
[METHODOLOGY.md §9.1](METHODOLOGY.md#91-governance-of-the-judgement-tables).
Outside review is welcome; the Software Engineering Group at the University
of Bern may be the right place to start.

## Licence

Apache 2.0. You may benchmark whatever you like, publish the results, and
name the tools you measured.
