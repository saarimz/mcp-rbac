"""Run every red-team scenario against fresh instances of the 3 servers; write redteam/report.{json,md}.

    python -m redteam.run            (from the repo root, with python/.venv)
"""
from __future__ import annotations

import asyncio
import pathlib
import sys
import tempfile

from redteam import servers
from redteam.harness import Report
from redteam.scenarios_auth import privilege_escalation, token_replay
from redteam.scenarios_data import approval_bypass, budget_exhaustion, confused_deputy, cross_tenant, prompt_injection

OUT = pathlib.Path(__file__).resolve().parent


async def main() -> Report:
    rep = Report()
    with tempfile.TemporaryDirectory() as tmp:
        procs = []
        try:
            def fresh(tag: str) -> tuple[dict[str, str], dict[str, str]]:
                urls, dbs = {}, {}
                for name in ("venue", "marketing", "devops"):
                    db = f"{tmp}/{name}-{tag}.db"
                    url, p = servers.start_http(name, db)
                    procs.append(p)
                    urls[name], dbs[name] = url, db
                return urls, dbs
            urls, dbs = fresh("auth")
            for name in urls:
                await token_replay(rep, name, urls[name], dbs[name])
                await privilege_escalation(rep, name, urls[name], dbs[name])
            urls, dbs = fresh("data")
            await confused_deputy(rep, urls)
            await cross_tenant(rep, urls)
            await prompt_injection(rep, urls)
            urls, dbs = fresh("budget")  # budgets and approvals on untouched state
            await budget_exhaustion(rep, urls)
            urls, dbs = fresh("approval")
            await approval_bypass(rep, urls, dbs)
        finally:
            for p in procs:
                p.terminate()
            for p in procs:
                p.wait(10)
    (OUT / "report.json").write_text(rep.to_json() + "\n")
    (OUT / "report.md").write_text(rep.to_markdown() + "\n\nFailed:\n" + "\n".join(f"- {c.category} {c.server}/{c.transport}: {c.name} — expected {c.expected}, got {c.observed}" for c in rep.failed()) + "\n")
    return rep


if __name__ == "__main__":
    r = asyncio.run(main())
    print(r.to_markdown())
    for c in r.failed():
        print(f"FAIL {c.category} {c.server}/{c.transport}: {c.name}: expected {c.expected!r}, got {c.observed!r}")
    sys.exit(1 if r.failed() else 0)
