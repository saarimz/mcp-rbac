# ITM as the test ground for mcp-rbac agent grants

Several AI agents act for one ITM human, each limited to different actions. Every agent is always ≤ its human.

- `src/`: a local copy of ITM's MCP surface (SQLite mirror of the Prisma slice: Brand, AdminUser, AdminUserBrand OWNER/ADMIN/AGENT, Moment, TicketTier, Ticket/TicketCheckIn, Plan, PlanBudgetLine, PlanChangeProposal, Venue, BrandAgentEmailSendBatch, plus PROPOSED marketplace quotes).
  - It has 19 tools named after the real partner-mcp and itm-agent tools. Argument shapes are inferred.
  - Agent connection grants: `src/grants.ts`. DPoP: `src/dpop.ts`. Consent and OAuth: `src/server.ts`.
- `policy/mcp-rbac.yaml`: the base policy (humans). Each grant renders its own overlay `mcp-rbac.yaml`.
- `test/grants.test.ts`: 33 tests over real HTTP and MCP covering:
  - no escalation and cross-workspace access
  - argument limits; AGENT staff brand-wide by default, with optional moment pinning (`momentPinning`, off by default) tested separately
  - approvals bound to the exact input; v1 is actions-only, so the spend scope and spend budgets are refused by default. Per-agent and per-human spend budgets (Phase 2) are behind `spendBudgets` (off by default) and tested separately
  - revocation, expiry, pause and demotion mid-session
  - DPoP isolation, prompt injection, code replay and audit tampering
- `scripts/demo.ts`: a narrated demo. Output goes to `out/demo-output.txt`, consent screens to `out/consent*.png`.
- `staging/`: an OAuth 2.1 PKCE client (DCR) for **ITM staging** and a live read-only proxy test (`LIVE-RESULTS.md`). Tokens are stored in `.secrets/` (gitignored). The proxy is staging-only and refuses non-staging hosts and non-read-only tools.
- `ADOPTION.md`: how ITM's real backend could ship this (Prisma diff, API, UI, non-admin agents). Spend is in its Phase 2 section.
- `SPEND-RESEARCH.md`: cited prior art (Stripe Issuing, Ramp/Brex, ACP, Visa/Mastercard, AP2, AWS/OpenAI, Shopify/Klaviyo) and the recommended Phase 2 spend-approval model.

```bash
npm test                 # 33 tests (node:test via tsx; uses ../../node_modules)
npm run demo
npm run staging:login    # once, opens the ITM staging consent (sandbox brand)
npm run staging:live     # live read-only run through the mcp-rbac proxy
```
