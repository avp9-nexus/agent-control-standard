#!/usr/bin/env python3
"""Negative conformance runner (issue #29, gap #19).

Loads the vector suite, calls one implementation adapter per vector, and fails on:
  - any verdict mismatch,
  - any failure-code mismatch (positive controls included),
  - any missing reason substring (a right verdict for a wrong reason is a latent bug),
  - any category lacking its POSITIVE CONTROL (a control counts only if it expects PASS),
  - any adapter answer that names no entry_point, and any category whose positive
    controls dispatched through a different entry point than its negative vectors
    (a suite that certifies a test double certifies nothing - review 4996153628).

The last rule is structural, not cosmetic: a suite made only of must-reject inputs cannot
distinguish an enforcement layer that works from one that rejects everything.

Adapter contract: a Python file exposing
    evaluate(question: dict) -> {"verdict": "PASS|REJECT|UNMEASURABLE", "code": str|None,
                                 "reason": str, "entry_point": str}
where question carries only {"id", "category", "input"} - the expected verdict and the
control flag never leave the runner, so an adapter that would derive its verdict from
the answer has nothing to derive it from (review 5444732337, run against 459ec820:
a six-line answer-key adapter scored 18/18 while enforcing nothing) - and entry_point
names the production entry point the adapter dispatched through.

Usage:
    python runner.py --adapter path/to/adapter.py [--vectors vectors/negative_vectors.json]
"""
import argparse
import importlib
import importlib.util
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).parent


def load_adapter(path: Path):
    # An adapter spanning several files must be able to import its siblings (review 4996153628).
    sys.path.insert(0, str(path.resolve().parent))
    spec = importlib.util.spec_from_file_location("acs_adapter", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not hasattr(mod, "evaluate"):
        sys.exit(f"FATAL: adapter {path} exposes no evaluate(vector)")
    return mod


def resolve_entry_point(name: str, adapter_path: Path):
    """Resolve a dotted `module.function` to something that actually answers to it.

    A NAME IS NOT A FACT until something resolves it. Measured on this suite: an adapter that
    answered exactly like the reference one but declared
    `nowhere.at.all.this_function_does_not_exist` scored 19/19 and exited 0, because the field this
    runner treats as structural was only ever compared to other strings. The reference adapter
    shipped here declared `reference_adapter.decide` three times while defining `evaluate` and no
    `decide`, so the shipped example named a function that did not exist.

    The adapter's own directory is searched first, then sys.path. An entry point that cannot be
    imported in the harness cannot be evidence in the harness, and the failure says which part
    did not resolve.
    """
    if "." not in name:
        return False, "not a dotted path (expected module.function)"
    mod_name, _, attr = name.rpartition(".")
    sys.path.insert(0, str(adapter_path.resolve().parent))
    try:
        mod = importlib.import_module(mod_name)
    except Exception as e:
        return False, f"module {mod_name!r} does not import ({type(e).__name__}: {e})"
    finally:
        sys.path.pop(0)
    target = getattr(mod, attr, None)
    if target is None:
        return False, f"module {mod_name!r} has no attribute {attr!r}"
    if not callable(target):
        return False, f"{name} resolves to {type(target).__name__}, not to a callable"
    return True, ""


def check_against_schema(suite, schema_path: Path):
    """Run the schema that ships beside the vectors, instead of only shipping it.

    Measured on this suite: `vector.schema.json` was referenced by no code at all, so the suite
    declared a contract that nothing enforced. If `jsonschema` is installed it is used; otherwise
    the standard-library subset below covers what this schema actually expresses: required keys,
    types, enums, string patterns and minima. It is a SUBSET, and says so rather than implying a
    full validation.
    """
    if not schema_path.exists():
        return [f"{schema_path.name} is missing: the suite ships a contract it cannot check"]
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        import jsonschema  # optional; absent from a standard-library-only run
        v = jsonschema.Draft202012Validator(schema)
        return [f"{'/'.join(str(p) for p in e.path) or '(root)'}: {e.message}" for e in v.iter_errors(suite)]
    except ImportError:
        pass

    types = {"string": str, "integer": int, "object": dict, "array": list, "boolean": bool,
             "number": (int, float)}
    problems = []

    def verifier(valeur, regle, ou):
        if "type" in regle and regle["type"] in types and not isinstance(valeur, types[regle["type"]]):
            problems.append(f"{ou}: expected {regle['type']}, got {type(valeur).__name__}")
            return
        if "enum" in regle and valeur not in regle["enum"]:
            problems.append(f"{ou}: {valeur!r} is not one of {regle['enum']}")
        if "pattern" in regle and isinstance(valeur, str) and not re.search(regle["pattern"], valeur):
            problems.append(f"{ou}: {valeur!r} does not match {regle['pattern']}")
        if "minLength" in regle and isinstance(valeur, str) and len(valeur) < regle["minLength"]:
            problems.append(f"{ou}: shorter than {regle['minLength']} characters")
        if "minimum" in regle and isinstance(valeur, int) and valeur < regle["minimum"]:
            problems.append(f"{ou}: {valeur} is below {regle['minimum']}")
        if "maximum" in regle and isinstance(valeur, int) and valeur > regle["maximum"]:
            problems.append(f"{ou}: {valeur} is above {regle['maximum']}")
        if isinstance(valeur, dict):
            for k in regle.get("required", []):
                if k not in valeur:
                    problems.append(f"{ou}: required field {k!r} is missing")
            for k, sous in regle.get("properties", {}).items():
                if k in valeur:
                    verifier(valeur[k], sous, f"{ou}.{k}" if ou else k)
        if isinstance(valeur, list):
            if "minItems" in regle and len(valeur) < regle["minItems"]:
                problems.append(f"{ou}: fewer than {regle['minItems']} items")
            if "items" in regle:
                for i, x in enumerate(valeur):
                    verifier(x, regle["items"], f"{ou}[{i}]")

    verifier(suite, schema, "")
    return problems


def is_positive_control(v):
    """A positive control is DECLARED and EXPECTS PASS - decided once, in the one function
    both sites call (review 5444732337: the structural gate applied this rule while the
    entry-point bucketing read the declared flag alone, so a must-reject vector carrying
    the flag was refused a place in the count and still landed in the positive bucket).
    A declared flag is not a positive control; only an expected PASS is (review 4996153628)."""
    return bool(v.get("positive_control")) and v["expected"]["verdict"] == "PASS"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", required=True, type=Path)
    ap.add_argument("--vectors", type=Path, default=HERE / "vectors" / "negative_vectors.json")
    args = ap.parse_args()

    suite = json.loads(args.vectors.read_text(encoding="utf-8"))
    vectors = suite["vectors"]
    adapter = load_adapter(args.adapter)

    # The contract that ships beside the vectors is RUN, not just shipped.
    ecarts = check_against_schema(suite, HERE / "vector.schema.json")
    if ecarts:
        print(f"SUITE INVALID: {len(ecarts)} vector(s) do not match vector.schema.json")
        for e in ecarts[:10]:
            print(f"  {e}")
        if len(ecarts) > 10:
            print(f"  ... and {len(ecarts) - 10} more")
        return 2

    # An empty suite discriminates nothing, and the count it prints is what hides that:
    # "0/0 vectors conform" with a zero exit reads exactly like a suite that passed.
    # The rule the gate below enforces per category has to hold for the suite itself.
    if not vectors:
        print("SUITE INVALID: no vectors. An empty suite cannot distinguish an enforcement "
              "layer from one that does nothing, and reports a clean run either way.")
        return 2

    # Structural gate first: every category present must carry a positive control.
    cats = defaultdict(lambda: {"neg": 0, "pos": 0})
    for v in vectors:
        cats[v["category"]]["pos" if is_positive_control(v) else "neg"] += 1
    missing = [c for c, k in sorted(cats.items()) if k["pos"] == 0]
    if missing:
        print(f"SUITE INVALID: categories without a positive control: {missing}")
        print("A suite of pure rejections cannot tell a working layer from one that rejects everything.")
        return 2

    failures = []
    entry_points = defaultdict(lambda: {"pos": set(), "neg": set()})
    for v in vectors:
        # The adapter is never handed the answer: expected verdict and control flag stay in
        # the runner, so the answer-key family stops being something to detect and becomes
        # something that cannot be expressed (review 5444732337).
        try:
            question = {"id": v["id"], "category": v["category"], "input": v["input"]}
            out = adapter.evaluate(question) or {}
        except Exception as e:  # an adapter crash - or a malformed vector - is a failure, never a skip
            failures.append((v.get("id", "?"), f"adapter raised {type(e).__name__}: {e}"))
            continue
        exp = v["expected"]
        # The suite certifies an enforcement layer, not a test double (review 4996153628):
        # every adapter answer must name the production entry point it dispatched through.
        # A name made of spaces is not a name: `if not ep` accepts "   ", and the field
        # the suite treats as structural would be satisfied by whitespace.
        ep = (out.get("entry_point") or "").strip()
        if not ep:
            failures.append((v["id"], "adapter reported no entry_point - cannot tell the enforcement layer from a test double"))
            continue
        # A declared name proves nothing until it resolves: comparing two strings to each other
        # certifies whichever double typed them. Measured before this line existed.
        resolu, pourquoi = resolve_entry_point(ep, args.adapter)
        if not resolu:
            failures.append((v["id"], f"entry_point {ep!r} resolves to nothing: {pourquoi}"))
            continue
        entry_points[v["category"]]["pos" if is_positive_control(v) else "neg"].add(ep)
        if out.get("verdict") != exp["verdict"]:
            failures.append((v["id"], f"verdict {out.get('verdict')!r} != expected {exp['verdict']!r}"))
            continue
        # code and reason are compared on PASS vectors too (review 4996153628: a positive
        # control's code field previously went uncompared; the always-true conditional that
        # wrapped this block is gone - review 5444732337 called it, cosmetic and right).
        if out.get("code") != exp.get("code"):
            failures.append((v["id"], f"code {out.get('code')!r} != expected {exp.get('code')!r}"))
            continue
        reason = (out.get("reason") or "").lower()
        for needle in exp.get("reason_must_mention", []):
            if needle.lower() not in reason:
                failures.append((v["id"], f"reason does not mention {needle!r}: {reason[:120]!r}"))
                break

    # Category failures are counted apart from vector failures: subtracting them from the
    # vector total printed "17/18 vectors conform" on a suite whose 18 vectors all conformed,
    # which is a wrong number reported by the very line that is supposed to make the run legible.
    category_failures = []
    for c, k in sorted(entry_points.items()):
        if k["pos"] and k["neg"] and k["pos"] != k["neg"]:
            category_failures.append((f"cat{c}", f"positive controls resolved through {sorted(k['pos'])} but negatives through {sorted(k['neg'])} - the gate certified a different code path than the one negatively tested"))

    print(f"{len(vectors) - len(failures)}/{len(vectors)} vectors conform "
          f"({sum(k['pos'] for k in cats.values())} positive controls across {len(cats)} categories)")
    for vid, why in failures:
        print(f"  FAIL {vid}: {why}")
    for cid, why in category_failures:
        print(f"  FAIL {cid}: {why}")
    # The headline counted vector failures only, so a run could print "19/19 vectors conform" and
    # exit 1 on a category failure listed three lines below. A reader and a CI job must not be able
    # to read two different verdicts off the same output: the last line carries the verdict.
    echoue = bool(failures or category_failures)
    print(f"RESULT: {'FAIL' if echoue else 'PASS'} - "
          f"{len(failures)} vector failure(s), {len(category_failures)} category failure(s)")
    return 1 if echoue else 0


if __name__ == "__main__":
    sys.exit(main())

