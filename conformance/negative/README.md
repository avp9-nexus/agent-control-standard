# Negative conformance vectors for the enforcement layer

Implements the proposal of issue #29 and the conformance-suite gap of issue #19.

The security value of an enforcement point is defined by its behaviour on inputs that are
*almost* right. This directory holds test vectors for those inputs: actions that are correctly
signed but unauthorized, replayed, stale, bound to the wrong principal, carried by malformed
evidence, or stripped of their observability references.

## Design rules

**1. Two rejection verdicts, never one.** A rejection because evidence was measured and found
wrong (`REJECT`) is a different verdict from a rejection because evidence could not be measured
at all (`UNMEASURABLE`). Both must refuse the action. Collapsing them either lets unmeasurable
inputs fail open, or sends operators hunting for frauds that never happened. Every vector
declares which of the two it expects.

**2. Every category carries a positive control.** Each category includes at least one
almost-identical input that MUST pass. A suite made only of must-reject inputs cannot
distinguish an enforcement layer that works from one that rejects everything. The runner fails
the whole suite if any category lacks its positive control.

**3. Vectors are framework-agnostic.** A vector describes an action, its authorization
evidence, and the state the enforcement point can consult. It never references a specific
implementation. Each implementation provides one adapter (see `runner.py`).

**4. Declared gaps are part of the suite.** Category 3 (expired or revoked mandates) is
covered here for expiry only. Revocation vectors are absent because the contributing
implementation has no revocation mechanism, by documented decision, and vectors for a path
never exercised in production would be design fiction. The gap is stated rather than filled.
Contributions from implementations that exercise revocation are the way to close it.

**5. A vector is named by its bytes, and the name is checked.** Every `id` is the SHA-256 of
the vector's canonical `input`. The previous ids read `neg-cat1-001` / `pos-cat1-001`: the
verdict class was in the first field an adapter received, and an adapter that never opened
`input` scored 19/19 off the name (review 5561917538, issue #53). Naming by digest closes the
leak through the identifier, and the runner refuses a suite whose ids do not match their
inputs, so the property is enforced at load rather than promised here. It closes nothing
else: the corpus is published, so a table keyed on the bytes of `input` scores the same as an
implementation, which is why this suite describes itself as a self-certification aid.

**6. The value that decides a verdict is never carried by the evidence it judges.** A freshness bound
is policy the enforcement point holds, so it lives in `state`, not in `authorization`. An adapter that
read it from the authorization passed a stale decision declaring its own ten-year bound, and an adapter
that skipped the check when the decision carried no timestamp passed a decision nobody could date. The
first is refused as stale; the second is refused as unmeasurable, the same way an action is refused when
the connected device was never read.

## Failure codes (proposed enumeration)

| Code | Verdict | Meaning |
|---|---|---|
| `CONTEXT_NOT_SUPPORTED` | REJECT | Signature valid, but the consulted state does not carry this action (wrong target, closed auction, exceeded bound) |
| `REPLAY_CONSUMED` | REJECT | The authorization was already used once; one authorization covers one act |
| `STALE_DECISION` | REJECT | The evidence is older than the freshness bound the enforcement point's policy sets |
| `PRINCIPAL_MISMATCH` | REJECT | Approval bound to a different agent, tool, or signing device than the one acting |
| `REFERENCE_MISSING` | REJECT | A required observability reference is present and unusable: zeroed, or bound to a different context |
| `REFERENCE_MISMATCH` | REJECT | The named reference diverges from the one already bound to this action's context |
| `MALFORMED_EVIDENCE` | UNMEASURABLE | Evidence present but not decodable to the declared shape; consumers must fail closed |
| `ORACLE_UNAVAILABLE` | UNMEASURABLE | The state needed to judge could not be read; absence of measurement is never a pass |

## Vector schema

All twenty-one vectors live as a single array in `vectors/negative_vectors.json`; the schema
below describes one entry.

```json
{
  "id": "<sha256 hex of the canonical input, 64 characters>",
  "category": 1,
  "description": "what makes this input almost right, and why it must fail",
  "input": {
    "action": { },
    "authorization": { },
    "state": { }
  },
  "expected": {
    "verdict": "REJECT | UNMEASURABLE | PASS",
    "code": "one of the enumeration above, absent for PASS",
    "reason_must_mention": ["substring the refusal message must contain"]
  },
  "positive_control": false
}
```

The id is computed as

```python
hashlib.sha256(json.dumps(vector["input"], sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")).hexdigest()
```

and by nothing else: not the verdict, not the category, not the description. `runner.py`
recomputes it for every vector at load and refuses the suite (exit 2) on any mismatch or any
duplicate, so a vector renamed by hand, or edited in place under its old name, cannot enter a
run. Anyone can recompute the ids from the file with the line above.

`reason_must_mention` exists because a correct verdict with a wrong reason is a latent bug:
an enforcement point can reject for the wrong cause and pass the suite while hunting the
wrong class of attack.

## Running

```
python conformance/negative/runner.py --adapter your_adapter.py
```

The adapter exposes `evaluate(question) -> {"verdict": ..., "code": ..., "reason": ...,
"entry_point": ...}`, where `question` carries `input` and nothing else - the expected
verdict, the `positive_control` flag, the category and the id never leave the runner - and
`entry_point` names the production entry point the adapter dispatched through for that
vector. The runner exits non-zero on: an empty suite, any verdict mismatch, any code mismatch
(positive controls included), any missing `reason_must_mention` substring, any category
lacking a positive control (a control counts only if it expects `PASS`), any answer naming
no entry point, or any category whose positive controls resolved through a different entry
point than its negative vectors. Vector failures and category failures are counted and
reported separately, so the conformance count never absorbs a category-level result.

The answer key is handled one layer earlier: since the adapter is never handed the expected
verdict, an adapter that would derive its answer from it has nothing to derive it from, and
fails on its first call. That family is no longer something the suite detects, it is
something that cannot be expressed (review of 2026-08-27, run against `459ec820`: a
six-line answer-key adapter scored 18/18 under the previous contract, and scores 0/18 with
`KeyError: 'expected'` under this one). The same holds for the name: an adapter that would
look the verdict up by id has no id to look up, and fails the same way with `KeyError: 'id'`.

The entry-point rules remain a declaration the runner compares only against itself. They
catch a suite whose positive controls and negative vectors resolve through different paths;
they do not establish that the named function ran. Observing execution from outside the
adapter is the mechanism that would, and it is discussed in #35.

An empty vector file is refused. A suite with no vectors distinguishes nothing, and the
count it would otherwise print - `0/0 vectors conform` with a zero exit - is
indistinguishable from a suite that passed. The rule the structural gate applies per
category applies to the suite itself.

## Negative controls for the suite itself

```
python conformance/negative/selftest.py
```

A suite that has only ever been run against an implementation which passes it has not been
shown to discriminate, and a verifier that rejected every input would pass every must-reject
vector ever written. `selftest.py` is the pairing: thirty-one cases the suite must refuse,
plus the one it must accept, so that a green run means the gate is live rather than absent.

Three families. **Fake adapters** enforce nothing or satisfy the letter of the adapter
contract while defeating its purpose: one that would read the answer key, one that would look
the verdict up by the vector's id, one that refuses everything, one that allows everything,
one that names no entry point, one whose entry point is only whitespace, one that answers the
must-pass inputs from a second path, one that names a function which exists nowhere, and two
that return the right verdict with the wrong code or the wrong reason. **Runner guards** are
inputs refused before any adapter is consulted: an empty suite, a suite whose positive
controls have been removed, a vector stripped of its requirement, and a vector whose input was
edited under its old name. **Adapter mutants** delete exactly one check from the reference
adapter, one mutant per check, and the suite has to go red for every one.

The mutants are the part that finds vectors nobody wrote. A mutant that survives is not a
tolerable gap: it names a rule the suite claims to enforce and does not exercise. Two came
out of the first run of this file. The entry-point check accepted a name made of spaces,
because `if not ep` is true for `""` and false for `"   "`. And the rule refusing an action
whose signing device was never read survived its own deletion, because no vector exercised
it - the category-4 vector whose device was never read is that vector, and it was written
because the mutant lived. A mutant whose pattern no longer matches the adapter is reported as
such rather than counted as killed, so a rule that silently stops being tested shows up as a
changed count.

## What each vector binds to

Every vector carries a `requirement` object: the spec version it was written against, the profile,
the anchor in `docs/spec/conformance.md`, the clause, and the sentence it quotes. The corpus binds to
the normative text before it binds to CI, which is what #33 and #53 both asked for.

`ledger_id` is present on every vector and is **null**, deliberately. The normative-requirement ledger
proposed in #33 does not exist yet, so there is no identifier to cite. The field is there so that the
day the ledger lands, filling it is a mechanical pass and not a re-reading of twenty-one vectors. An
identifier invented here would have looked like a binding and been a guess.

## What this corpus does not claim

These vectors were written for this suite. They are not evidence about any deployment, and nothing
here reports on a running system: the only thing measured in this directory is the suite's own
behaviour against an adapter, which anyone can re-run with the two commands above.
