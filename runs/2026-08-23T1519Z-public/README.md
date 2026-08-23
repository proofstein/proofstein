# 2026-08-23T1519Z, public corpus

| | |
|---|---|
| corpus commit | `49c979d3e8a3b0f7ef063ea89d61cea5c30ea889` |
| assets | 124 |
| rule | detection is **file + algorithm + layer**; the line is recorded and reported, never scored (METHODOLOGY.md §3.3) |
| cdxgen | 12.8.2, the control, held at the same version across every run |
| pqprobe-static | 3.6.0 |
| sonar-cryptography | 1.6.1, on `sonarqube:26.8.0.126808-community` |

## Scores

| tool | scored assets | all |
|---|---|---|
| cdxgen 12.8.2 | 124 | 5% (6/124) |
| pqprobe-static 3.6.0 | 124 | 96% (119/124) |
| sonar-cryptography 1.6.1 | 67 | 34% (23/67) |

Full tables in `results/results.md`.

## Read the sonar-cryptography number against 67, not 124

Its denominator is smaller than the other two, and comparing the three "all"
figures side by side without that in mind is the one mistake this run invites.

The engine reads **Java, Python and Go**. C, JavaScript and Rust are not
languages it parses, so on `tinyattest`, `session-broker` and `sealbox` its
crypto sensor never looks at anything. Those three scans complete, report
success, and produce no document:

```
INFO  No cryptography assets were detected. CBOM will not be generated.
INFO  EXECUTION SUCCESS
```

The scorer excludes an absent (project, tool) pair rather than counting it as
zero, which is why 67 assets are in scope rather than 124. Three of the eighteen
invocations produced no document for this reason, and the manifest records each
one.

So 34% is a rate over the languages the tool covers, not over the corpus. It is
not comparable with 96% and 5%, which are rates over the whole corpus. **The
per-language table in `results/results.md` is the informative one**, because
there the denominators match:

| language | cdxgen | pqprobe-static | sonar-cryptography |
|---|---|---|---|
| go | 0% (0/19) | 100% (19/19) | 42% (8/19) |
| java | 8% (2/25) | 96% (24/25) | 48% (12/25) |
| python | 4% (1/23) | 96% (22/23) | 13% (3/23) |

Language coverage is a property of the tool, not a handicap the benchmark
imposed. A reader wanting a single number that charges it for the languages it
does not read can compute one from `results/results.json`; this run does not
publish that number as its headline, because "did not run" and "found nothing"
are different claims and the manifest distinguishes them.

Within the three languages it does read, the layer table is where it separates
from cdxgen: 75% on direct calls and 80% on aliased imports, against 0% on
config, declared dependencies and key files.

## False positives

cdxgen and pqprobe-static were charged none.

sonar-cryptography was charged three, all phantom algorithms: a family named in
a project that does not contain it. Two are `NATIVEPRNG` in `beacon-relay`, at
`internal/identity/identity.go:33` and `:38`. `NATIVEPRNG` is a JCA
`SecureRandom` provider name, reported here against Go source.

All three tools' documents were schema-valid, and none pointed at a file that is
not in the project.

## Environment

cdxgen is invoked through the pinned image `ghcr.io/cyclonedx/cdxgen:12.8.2` via
`tools/cdxgen-docker.sh`. pqprobe-static comes from `${PQPROBE_STATIC_BIN}`; the
manifest records the path it resolved to and that file's sha256.

sonar-cryptography is a SonarQube plugin rather than a binary, so
`tools/sonar-cryptography-docker.sh` boots a pinned server with the plugin jar
pinned by sha256, and scans through the pinned scanner image. Booting also
activates the plugin's Inventory rules, which ship switched off and, left off,
produce a silent zero on every language. That is
[docs/pending-review.md](../../docs/pending-review.md) entry 13, along with the
measurement showing that supplying Java bytecode changed nothing on this corpus.
