#!/usr/bin/env python3
"""Append the P13 conformance vectors to conformance/corpus.jsonl: fail-closed approval `when` (a missing or
wrong-typed argument needs approval) and the load-time lints (per-role limits bypassed by another grant of the same
role; approval `when` arguments not covered by a required tool-wide limit).

Earlier vectors are kept byte-for-byte; any previous `p13-` lines are dropped and a fresh deterministic set appended.
Run conformance/run.sh --update-golden afterwards."""
from __future__ import annotations

import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
corpus = HERE / "corpus.jsonl"
base = [l for l in corpus.read_text(encoding="utf-8").splitlines() if l.strip() and not json.loads(l)["id"].startswith("p13-")]
out: list[dict] = []
N0 = len(base)
A, D, N = "allow", "deny", "needs_approval"


def add(policy: str, req=None, *, raw: str | None = None, expect=None):
    v: dict = {"id": f"p13-{N0 + len(out):05d}", "policyYaml": policy}
    if raw is not None:
        v["requestJson"] = raw
    elif req is not None:
        v["requestJson"] = json.dumps(req, ensure_ascii=False)
    if expect:
        v["expect"] = expect
    out.append(v)


def call(tool, args=None, roles=("r",)):
    r = {"tool": tool, "identity": {"id": "u", "roles": list(roles)}}
    if args is not None:
        r["args"] = args
    return r


def pol(when: str, extra: str = "") -> str:
    return f"version: 1\nroles:\n  r: {{tools: [pay]}}\napprovals:\n  - {{tool: pay, when: {when}}}\n{extra}"


# 1. numeric when: a missing / wrong-typed amount needs approval (was: no approval)
P = pol("{amount: {min: 100}}")
for args, want in [({"amount": 50}, A), ({"amount": 100}, N), ({"amount": 150}, N), ({}, N), (None, N), ({"amount": "900"}, N),
                   ({"amount": "50"}, N), ({"amount": True}, N), ({"amount": None}, N), ({"amount": [150]}, N), ({"amount": {"v": 1}}, N),
                   ({"other": 1}, N), ({"amount": -0.0}, A), ({"amount": 99.999}, A)]:
    add(P, call("pay", args), expect={"decision": want})
add(P, raw='{"tool":"pay","args":{"amount":1e400},"identity":{"id":"u","roles":["r"]}}', expect={"decision": N})
add(P, raw='{"tool":"pay","args":{"amount":-1e400},"identity":{"id":"u","roles":["r"]}}', expect={"decision": N})
add(P, raw='{"tool":"pay","args":{"amount":1e-400},"identity":{"id":"u","roles":["r"]}}', expect={"decision": A})
# max / integer
P = pol("{n: {max: 10, integer: true}}")
for args, want in [({"n": 5}, N), ({"n": 11}, A), ({"n": 5.5}, A), ({"n": "5"}, N), ({}, N), ({"n": False}, N)]:
    add(P, call("pay", args), expect={"decision": want})
# 2. eq / in: a value of another kind is unevaluable
P = pol("{env: {eq: prod}}")
for args, want in [({"env": "prod"}, N), ({"env": "dev"}, A), ({"env": "PROD"}, A), ({}, N), ({"env": 1}, N), ({"env": None}, N), ({"env": ["prod"]}, N), ({"env": True}, N)]:
    add(P, call("pay", args), expect={"decision": want})
P = pol("{n: {eq: 1}}")
for args, want in [({"n": 1}, N), ({"n": 1.0}, N), ({"n": 2}, A), ({"n": "1"}, N), ({"n": True}, N)]:
    add(P, call("pay", args), expect={"decision": want})
P = pol("{flag: {eq: true}}")
for args, want in [({"flag": True}, N), ({"flag": False}, A), ({"flag": 1}, N), ({"flag": "true"}, N)]:
    add(P, call("pay", args), expect={"decision": want})
P = pol("{env: {in: [prod, staging]}}")
for args, want in [({"env": "prod"}, N), ({"env": "staging"}, N), ({"env": "dev"}, A), ({"env": 3}, N), ({}, N)]:
    add(P, call("pay", args), expect={"decision": want})
P = pol("{v: {in: [1, x]}}")
for args, want in [({"v": 1}, N), ({"v": "x"}, N), ({"v": 2}, A), ({"v": "y"}, A), ({"v": False}, N)]:
    add(P, call("pay", args), expect={"decision": want})
# 3. maxLength / pattern need a string
P = pol("{note: {maxLength: 5}}")
for args, want in [({"note": "abc"}, N), ({"note": "abcdefgh"}, A), ({"note": 5}, N), ({}, N)]:
    add(P, call("pay", args), expect={"decision": want})
P = pol("{code: {pattern: 'x[0-9]+'}}")
for args, want in [({"code": "x12"}, N), ({"code": "y12"}, A), ({"code": 12}, N), ({"code": None}, N)]:
    add(P, call("pay", args), expect={"decision": want})
# 4. optional: absent = the rule does not apply (unchanged); present but wrong-typed = approval
P = pol("{amount: {min: 100, optional: true}}")
for args, want in [({}, N), ({"amount": 5}, A), ({"amount": 500}, N), ({"amount": "5"}, N)]:
    add(P, call("pay", args), expect={"decision": want})
# 5. several arguments: a well-typed value that fails decides (AND); otherwise an unevaluable one needs approval
P = pol("{amount: {min: 100}, currency: {eq: USD}}")
for args, want in [({"amount": 50, "currency": "EUR"}, A), ({"amount": 150, "currency": "EUR"}, A), ({"amount": 150, "currency": "USD"}, N),
                   ({"amount": 50}, A), ({"amount": 150}, N), ({"currency": "USD"}, N), ({"currency": "EUR"}, N), ({"amount": "x", "currency": "EUR"}, N)]:
    add(P, call("pay", args), expect={"decision": want})
# 6. per-tool approve.when; with tool-wide limits the limits deny first (unchanged)
P = "version: 1\nroles:\n  r: {}\ntools:\n  pay:\n    allow: [r]\n    limits: {amount: {min: 0, max: 500}}\n    approve: {when: {amount: {min: 100}}}\n"
for args, want, reason in [({"amount": 50}, A, "ok"), ({"amount": 150}, N, "ok"), ({}, D, "user:constraint:missing:amount"), ({"amount": "150"}, D, "user:constraint:not_a_finite_number:amount")]:
    add(P, call("pay", args), expect={"decision": want, "reason": reason})
P = "version: 1\nroles:\n  r: {}\ntools:\n  pay:\n    allow: [r]\n    approve: {when: {amount: {min: 100}}}\n"
for args, want in [({"amount": 50}, A), ({}, N), ({"amount": "150"}, N)]:
    add(P, call("pay", args), expect={"decision": want})
# pattern approvals over several tools
P = "version: 1\nroles:\n  r: {tools: ['admin.*']}\napprovals:\n  - {tool: 'admin.*', when: {env: {eq: prod}}}\n"
for tool, args, want in [("admin.restart", {"env": "prod"}, N), ("admin.restart", {"env": "dev"}, A), ("admin.restart", {}, N), ("admin.restart", {"env": 0}, N)]:
    add(P, call(tool, args), expect={"decision": want})
# a denial never becomes needs_approval
add(pol("{amount: {min: 100}}"), call("pay", {}, roles=("nobody",)), expect={"decision": D})
add(pol("{amount: {min: 100}}"), call("other", {}), expect={"decision": D})

# 7. lints (policy only: {"ok":true,"warnings":[...]})
L = [
    # wildcard of the same role bypasses its per-role limits
    "version: 1\nroles:\n  r: {tools: ['*']}\ntools:\n  refund: {allow: {r: {amount: {max: 50}}}}\n",
    # explicit exact-name grant of a higher role is deliberate: no warning; the wildcard one warns
    "version: 1\nroles:\n  owner: {tools: [refund], includes: [staff]}\n  staff: {}\ntools:\n  refund: {allow: {staff: {amount: {max: 50}}}}\n",
    "version: 1\nroles:\n  owner: {tools: ['*'], includes: [staff]}\n  staff: {}\ntools:\n  refund: {allow: {staff: {amount: {max: 50}}}}\n",
    # the role's own limits bypassed by an included role's grant
    "version: 1\nroles:\n  r: {includes: [base]}\n  base: {tools: ['*']}\ntools:\n  refund: {allow: {r: {amount: {max: 50}}}}\n",
    # dotted names and prefix patterns
    "version: 1\nroles:\n  r: {tools: ['billing.*']}\ntools:\n  billing.refund: {allow: {r: {amount: {max: 50}}}}\n  billing.list: {allow: [r]}\n",
    "version: 1\nroles:\n  r: {tools: ['ref*']}\ntools:\n  refund: {allow: {r: {amount: {max: 50}}}}\n",
    # role-entry limits ({name, limits}) and no other grant: no warning
    "version: 1\nroles:\n  r: {tools: [{name: refund, limits: {amount: {max: 50}}}, list]}\n",
    "version: 1\nroles:\n  r: {tools: [{name: refund, limits: {amount: {max: 50}}}, 'r*']}\n",
    # tool-wide limits: nothing to warn about
    "version: 1\nroles:\n  r: {tools: ['*']}\ntools:\n  refund: {allow: [r], limits: {amount: {max: 50}}}\n",
    # class grants
    "version: 1\nroles:\n  r: {}\ntools:\n  refund: {allow: {r: {amount: {max: 50}}}}\nsemantics:\n  grants: {r: [read]}\n",
    "version: 1\nroles:\n  r: {}\n  s: {}\ntools:\n  refund: {allow: {r: {amount: {max: 50}}}}\nsemantics:\n  grants: {s: [read]}\n",
    # approval when coverage
    "version: 1\nroles:\n  r: {tools: [pay]}\napprovals:\n  - {tool: pay, when: {amount: {min: 100}}}\n",
    "version: 1\nroles:\n  r: {}\ntools:\n  pay: {allow: [r], limits: {amount: {max: 500}}, approve: {when: {amount: {min: 100}}}}\n",
    "version: 1\nroles:\n  r: {}\ntools:\n  pay: {allow: [r], limits: {amount: {max: 500, optional: true}}, approve: {when: {amount: {min: 100}}}}\n",
    "version: 1\nroles:\n  r: {tools: [pay]}\napprovals:\n  - {tool: pay, when: {amount: {min: 100, optional: true}}}\n",
    "version: 1\nroles:\n  r: {tools: ['a.*']}\napprovals:\n  - {tool: 'a.*', when: {env: {eq: prod}, n: {min: 1}}}\n",
    "version: 1\nroles:\n  r: {tools: [pay]}\napprovals:\n  - {tool: pay}\n",
]
for p in L:
    add(p)
# the bypass itself is unchanged: the wildcard grant still allows past the per-role limit (documented; lint warns)
add(L[0], call("refund", {"amount": 500}), expect={"decision": A, "rule": "r@{}:*"})
add(L[6], call("refund", {"amount": 500}), expect={"decision": D})

with corpus.open("w", encoding="utf-8", newline="\n") as f:
    for l in base:
        f.write(l + "\n")
    for v in out:
        f.write(json.dumps(v, ensure_ascii=True) + "\n")
print(f"{N0} existing vectors kept; {len(out)} p13 vectors appended ({sum(1 for v in out if 'expect' in v)} with hand-written expectations)")
