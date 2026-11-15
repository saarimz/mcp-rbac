"""Python/PyO3 binding: see bench/core/README.md.  python bench/core/bench.py"""
import json, pathlib, platform, time
import mcp_rbac_core
root = pathlib.Path(__file__).resolve().parents[2]
w = json.loads((root / "bench/core/workload.json").read_text())
e = mcp_rbac_core.Engine((root / w["policy"]).read_text())
out, decisions = {}, {}
def bench(name, f):
    for i in range(w["warmup"]):
        f(i)
    rs = []
    for r in range(w["rounds"]):
        t = time.perf_counter_ns()
        for i in range(w["iterations"]):
            f(w["warmup"] + r * w["iterations"] + i)
        rs.append((time.perf_counter_ns() - t) / w["iterations"])
    out[name] = sorted(rs)[len(rs) // 2]
for name, req in w["requests"].items():
    s = json.dumps(req)
    d = json.loads(e.decide(s)); decisions[name] = d["decision"] + ":" + d["reason"]
    bench(f"decide.{name}", lambda i: e.decide(s))
    bench(f"authorize.{name}", lambda i: e.authorize(s, 1.7e12 + i * 60_000.0))
dj = e.decide(json.dumps(w["redact"]["request"])); res = json.dumps(w["redact"]["result"])
bench("redact.build_log", lambda i: e.redact(res, dj))
print(json.dumps({"binding": "python-pyo3", "runtime": f"CPython {platform.python_version()}", "ns_per_op": out, "decisions": decisions}))
