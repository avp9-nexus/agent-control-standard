"""Reference adapter: a minimal enforcement layer that satisfies the negative suite.

Ships WITH the suite for one reason: a runner nobody can execute end-to-end is a promise.
This adapter is the suite's own positive control. It is deliberately small and readable;
it is not a product.

The entry point is DERIVED, never typed. Three earlier versions of this file declared
`reference_adapter.decide` while defining `evaluate` and no `decide`: the shipped example named a
function that did not exist, and the runner accepted it because it compared strings instead of
resolving them. A name that is computed from the function that answers cannot drift away from it.
"""

import os

# Derived from the FILE, not from __name__: a runner that loads this file under a synthetic module
# name would otherwise make the adapter announce a module nobody can import.
ENTRY_POINT = os.path.splitext(os.path.basename(__file__))[0] + ".evaluate"


def evaluate(vector):
    inp = vector["input"]
    action, auth, state = inp.get("action", {}), inp.get("authorization", {}), inp.get("state", {})

    def reject(code, reason):
        return {"verdict": "REJECT", "code": code, "entry_point": ENTRY_POINT, "reason": reason}

    def unmeasurable(code, reason):
        return {"verdict": "UNMEASURABLE", "code": code, "entry_point": ENTRY_POINT, "reason": reason}

    # Evidence shape first: fail closed on what cannot be decoded, with its own code.
    oracle = state.get("oracle_response", "ABSENT_KEY")
    if oracle is None:
        return unmeasurable("ORACLE_UNAVAILABLE", "state could not be measured; absence is never a pass")
    if isinstance(oracle, dict):
        if oracle.get("shape") == "address" and not oracle.get("bytes_hex", "").startswith("0" * 24):
            return unmeasurable("MALFORMED_EVIDENCE", "leading bytes do not encode the declared address type")
        if oracle.get("shape", "").endswith("_6_fields") and oracle.get("fields_served") != 6:
            return unmeasurable("MALFORMED_EVIDENCE", f"expected 6 fields, served {oracle.get('fields_served')}")

    # Observability references. NOTE: this can only judge a reference that is present and
    # wrong. Nothing in a vector declares that a given action REQUIRED one, so an action
    # that omits the field is indistinguishable here from one for which no reference was
    # ever due - `commit_funds` appears in this suite both with a reference (category 6)
    # and without one on vectors that must pass. The "absent" arm of REFERENCE_MISSING is
    # therefore not expressible against the current vector shape, and the enumeration text
    # says so rather than promising it.
    if "registry_ref" in action:
        ref = action["registry_ref"]
        if set(ref.replace("0x", "")) == {"0"}:
            return reject("REFERENCE_MISSING", "required registry reference is zeroed")
        target = state.get(action.get("target"), {})
        bound = target.get("bound_registry_ref")
        if bound and bound != ref:
            return reject("REFERENCE_MISMATCH", f"reference diverges from the one bound to this context ({bound})")

    # Principal binding.
    if auth.get("decision_for") and auth["decision_for"] != action.get("actor"):
        return reject("PRINCIPAL_MISMATCH", f"decision names agent {auth['decision_for']}, actor differs")
    if "required_signer" in action:
        # `not in (None, required)` accepted the absence of evidence: an action naming a
        # required signer, with nothing said about the connected device, passed every guard.
        # Absence of a measurement is never a match; it is the UNMEASURABLE case by the
        # enumeration's own distinction.
        derived = auth.get("connected_device_derives")
        if derived is None:
            return unmeasurable("ORACLE_UNAVAILABLE",
                                "no evidence of which device is connected; absence is never a match")
        if derived != action["required_signer"]:
            return reject("PRINCIPAL_MISMATCH", "connected device derives a different key; wrong device")

    # Approval lifetime: section 9.3 as proposed in PR #294 (not merged). A request that presents an
    # approval names it by the request_id of the request whose ASK the grant answered: refers_to_request_id
    # is this suite's name for a reference ACS v0.1 does not carry (#175 proposes one). Whether the grant is
    # consumed, which session it belongs to, and which request presented it and is still awaiting its
    # decision, is the Guardian's record, held in the state, never the evidence being judged (design rule 6).
    # The record holds the grants the vectors present, consumed ones and earlier sessions' included, and
    # marks consumption and the awaited decision only on a one-time approval, so scope is not read here.
    # Section 9.3 does not rule on a reference the record does not resolve, or on a grant or a state that
    # does not give its session: the suite cannot tell a grant never issued from a record that lost it,
    # and refuses such a request as not measured rather than take the grant as fresh (design rule 1).
    grant_ref = auth.get("refers_to_request_id")
    if grant_ref is not None:
        grants = state.get("grants")
        grant = grants.get(grant_ref) if isinstance(grants, dict) else None
        if grant is None:
            return unmeasurable("ORACLE_UNAVAILABLE", "the record holds no grant under this reference")
        if grant.get("session_id") is None or state.get("session_id") is None:
            return unmeasurable("ORACLE_UNAVAILABLE", "the record does not tie the grant and the request to a session")
        if grant.get("session_id") != state.get("session_id"):
            return reject("REPLAY_CONSUMED", "the grant belongs to another session")
        if grant.get("consumed"):
            return reject("REPLAY_CONSUMED", "this one-time approval was already consumed")
        # While the request that presented a one-time approval is still awaiting its decision, another
        # request that presents it is refused, even before that decision returns. request_id is the
        # request's own signed identity: a second arrival of the same request_id is a duplicate, refused
        # under section 10.3 (REPLAY_DETECTED), which this suite does not model.
        pending = grant.get("awaiting_decision_for")
        if pending is not None and pending != auth.get("request_id"):
            return reject("REPLAY_CONSUMED", "this one-time approval is awaiting its decision for another request")

    # Freshness. The bound that decides is policy the enforcement point holds, so it is read from the
    # state and never from the authorization being judged: a decision that declared its own bound would
    # declare its own verdict. Reading it from the authorization passed a stale decision carrying a
    # ten-year bound, and skipping the check when the timestamp was missing passed a decision whose
    # age nobody could measure.
    freshness_bound = state.get("freshness_bound_seconds")
    if freshness_bound is not None and "decision_written_at" not in auth:
        return unmeasurable("ORACLE_UNAVAILABLE",
                            "decision carries no timestamp; its freshness cannot be measured")
    if freshness_bound is not None and "decision_written_at" in auth:
        from datetime import datetime
        age = (datetime.fromisoformat(state["now"].replace("Z", "+00:00"))
               - datetime.fromisoformat(auth["decision_written_at"].replace("Z", "+00:00"))).total_seconds()
        if age > freshness_bound:
            return reject("STALE_DECISION", f"decision is {int(age)}s old, freshness bound exceeded")

    # Context: signature validity alone never suffices; the state must carry the action.
    target = state.get(action.get("target"), {})
    if target.get("settled"):
        return reject("CONTEXT_NOT_SUPPORTED", "target auction is settled; this action replays a closed context")
    if "ceiling" in target and int(action.get("amount", 0)) > int(target["ceiling"]):
        return reject("CONTEXT_NOT_SUPPORTED", f"amount exceeds the ceiling the state carries ({target['ceiling']})")

    return {"verdict": "PASS", "code": None, "entry_point": ENTRY_POINT, "reason": "context supports the action"}
