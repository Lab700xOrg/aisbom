# Bypass regression corpus

A reproducible corpus of publicly-documented pickle/model-scanner evasion
techniques, and the regression gate that keeps AIsbom's detection of them
honest.

## What is here

| Path | Committed? | What it is |
| --- | --- | --- |
| `baseline.json` | yes | The current verdict for every case in both scan modes. Describes what detection *is*. |
| `floor.json` | yes | The best verdict every case has ever reached. The release gate. |
| `artifacts/` | **no** (gitignored) | The generated mock artifacts. Rebuilt on demand. |
| `../../aisbom/corpus.py` | yes | Case definitions (citation, evasion class, expected verdict) and the generators. |
| `../../docs/bypass-scorecard.md` | yes | Human-readable scorecard, published by the `/blog` article. |

**No malware is stored in this repository.** Every artifact is synthesized from
`aisbom/mock_generator.py`'s inert primitives and names a harmless `echo` string
where real malware would carry a payload. Following the same rule as
`demo_data/`, the generators are committed and the binaries are not — a clone
never carries mock-malicious model files. The corpus is only ever *disassembled*;
`corpus.score_corpus()` traps `pickle.load`/`pickle.loads` for the duration of a
run and records the result, so the harness can prove it never executed its own
corpus.

## Running it

```bash
poetry run aisbom bypass-scorecard
```

Add `--json` for machine-readable output, or `--output-dir DIR` to keep the
generated artifacts around for inspection.

## Two files, two jobs

`baseline.json` is a **description**. The tests fail if any verdict differs from
it in either direction, so every change to detection shows up in review. You
regenerate it freely.

`floor.json` is a **promise**: the best verdict each case has ever reached. Once
an evasion is caught, it stays caught. `--write` raises the floor and never
lowers it, so a regression cannot be absorbed by regenerating — the floor keeps
the old value and the gate keeps failing.

That distinction is the whole point. Without it, the documented fix for "the
scorecard test is failing" would be "regenerate the scorecard", which would turn
the regression gate into a rubber stamp.

## Changing detection

After improving detection:

```bash
poetry run aisbom bypass-scorecard --write
```

That rewrites `baseline.json`, raises `floor.json`, and refreshes
`docs/bypass-scorecard.md`. Commit all three alongside the detection change so
the diff shows exactly which evasions flipped.

If you genuinely need to lower the floor — a case was wrong, or a technique was
retired — edit `floor.json` **by hand**. There is deliberately no flag for it;
the manual edit is the audit trail.

## The release gate

```bash
poetry run aisbom bypass-scorecard --check
```

Exits `2` if any case scores below the floor. This runs on every PR (`ci.yml`)
and blocks both release channels — PyPI (`publish.yml`) and the standalone
binaries (`binaries.yml`) — so a scanner that has quietly stopped catching a
known bypass cannot ship.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `detected` | The scanner named the dangerous global. |
| `partial` | It refused to call the file safe, but never disassembled the payload — so it reports the wrong reason. |
| `missed` | Nothing was surfaced. |
| `clean` | Benign control, correctly not flagged. |
| `false-positive` | Benign control incorrectly flagged. |

`partial` is the interesting column. A file flagged `CRITICAL (Legacy Binary)`
looks like a catch on a dashboard but tells the user nothing about the reverse
shell inside it, and it is the verdict that regresses to `missed` the moment
someone "fixes" the heuristic that produced it.
