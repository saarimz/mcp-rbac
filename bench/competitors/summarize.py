"""Merge results/*.json into results/summary.json (the numbers REPORT.md and the Page use). External measurements made
elsewhere this session (Permit Cloud PDP on a real account, local OPA, live Klaviyo) are copied in as summaries without
account identifiers; they are NOT like-for-like with the local loopback runs (cloud numbers include Internet RTT).

    python -m bench.competitors.summarize
"""
from __future__ import annotations

import json
import os
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
R = HERE / "results"
# private research notes (not in the repository); point PERMIT_RESEARCH at them to refresh the external rows
PERMIT = pathlib.Path(os.environ.get("PERMIT_RESEARCH", HERE / "results" / "external" / "private"))


def external() -> dict:
    out = R / "external/permit-opa.json"
    try:
        p = json.loads((PERMIT / "permit-hosted-bench.json").read_text())
        o = json.loads((PERMIT / "opal-opa-bench.json").read_text())
        prop = p["propagation"]
        d = {
            "permit_cloud_pdp": {
                "source": "permit-research/PERMIT-HOSTED-BENCH.md (real Permit account, Development environment)",
                "measured_at": p["measured_at"], "correctness": {k: p["correctness"][k] for k in ("passed", "total")},
                "latency_ms": p["load_cloud_pdp_sequential"]["latency_ms"], "throughput_rps_c1": p["load_cloud_pdp_sequential"]["throughput_rps"],
                "includes_internet_rtt": True,
                "propagation_s": {k: v for k, v in prop.items() if k.endswith("_seconds")},
                "edge_pdp": p["edge_pdp"], "mcp_gateway": {"usable_with_this_key": p["mcp_gateway"]["usable_with_this_key"],
                                                          "reason": "no MCP Gateway API in the public v2 API; app.agent.security gateway/consent flow not set up; api.agent.security health returned 502"},
            },
            "local_opa": {"source": "permit-research/opal-opa-bench.json (OPA 1.22.4 on loopback, OPAL docker stack not started: no Docker)",
                          "measured_at": o["measured_at"], "correctness": o["correctness"], "latency_ms": o["load_sequential"]["latency_ms"]},
        }
        out.write_text(json.dumps(d, indent=1) + "\n")
    except (OSError, KeyError):
        pass
    return json.loads(out.read_text()) if out.exists() else {}


def main() -> None:
    s: dict = {"redteam": {}, "load": {}, "loc": {}, "external": external()}
    for f in sorted(R.glob("redteam-*.json")):
        d = json.loads(f.read_text())
        t = f.stem.removeprefix("redteam-")
        st: dict = {}
        for c in d["checks"]:
            st[c["status"]] = st.get(c["status"], 0) + 1
        s["redteam"][t] = {"label": d.get("label"), "summary": d.get("summary"), "status_counts": st, "total_checks": len(d["checks"])}
    lp = R / "load-summary.json"
    if lp.exists():
        s["load"] = json.loads(lp.read_text())
    lc = R / "loc.json"
    if lc.exists():
        s["loc"] = json.loads(lc.read_text())
    kl = HERE.parents[1] / "examples/klaviyo-e2e/LIVE-RESULTS.md"
    s["external"]["klaviyo_live"] = {"source": "examples/klaviyo-e2e/LIVE-RESULTS.md", "mismatches": 0, "guard_overhead_p50_ms": "2.7 (get_lists) / 11.4 (get_campaigns)",
                                     "note": "real Klaviyo MCP (28 tools), 3 roles; overhead = guarded p50 - direct p50, independent samples"} if kl.exists() else {}
    (R / "summary.json").write_text(json.dumps(s, indent=1) + "\n")
    print("wrote", R / "summary.json")


if __name__ == "__main__":
    main()
