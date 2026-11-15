# Live Klaviyo e2e results

Run at **2:05 PM America/New_York on 2026-11-15**
(`npx tsx src/driver.ts --mode=live`). The private API key was never printed.
This file is a redacted summary; the raw machine report is gitignored at
`out/report.json`.

The official local package (`uvx klaviyo-mcp-server@latest`) exposed **28
tools** named with a `klaviyo_` prefix, not the 309 hosted-catalog names. The
live matrix is those 28 tools for every role, including expected denials.
Almost every local tool requires `model` (`claude` | `gpt` | `gemini` |
`other`); the driver used `other`.

## Key check (before the matrix)

- `.env` value: present, length 44, `pk_` prefix, charset alphanumeric plus
  underscore, no leading/trailing whitespace or newlines.
- `uvx` was already installed at `/usr/local/bin/uvx`.
- Read-only sanity call: `klaviyo_get_account_details` with `{ model: "other" }`.
- Result: **success** in 339 ms (plus ~1.7 s to start the local MCP server).
- Account public key `UGJTx2`, organization `mcp-rbac test`, timezone
  `America/New_York`. The key works.

## Per-role allow / deny (guard decisions)

0 decision mismatches. Unauthenticated MCP was rejected. Wrong password was
rejected. tools/list visibility had no mismatches.

| Role | Policy allow | Policy deny | Observed allow | Observed deny | Skipped (safety / missing fixture) | Mismatches |
|---|---:|---:|---:|---:|---:|---:|
| owner | 28 | 0 | 17 | 0 | 11 | 0 |
| marketer | 16 | 12 | 14 | 12 | 2 | 0 |
| support | 5 | 23 | 5 | 23 | 0 | 0 |

Owner skips were intentional: `subscribe` / `unsubscribe` (never live),
profile/event/image writes (not in the draft allow-list), and a few get-by-id
or assign calls that needed a fixture the earlier read/create had not
produced (`campaign_id` / `template_id` were only available after later
creates; no flows exist on the account). Marketer skips were `get_flow` (no
flow) and `assign_template_to_campaign_message` (no campaign message id).

Denied calls were rejected by mcp-rbac (`user:no_matching_permission`) and
**did not reach Klaviyo**.

## Upstream (Klaviyo) outcomes for allowed calls

| | Count |
|---|---:|
| Guard-allowed calls forwarded upstream | 36 |
| Succeeded at Klaviyo | 36 |
| Klaviyo errors | 0 |

A first live attempt (not this passing run) failed two `create_campaign` calls
with Klaviyo `400 invalid_send_time` because the driver used a 2099 send
date, which is past Klaviyo's allowed scheduling window. No campaign was
created in that attempt. The driver was changed to schedule ~90 days out,
still as a **Draft** with method `static` (never `immediate`), and this run
created the drafts listed below with 0 upstream errors.

## Audit and OpenTelemetry

| | Count |
|---|---:|
| Audit events (this run only, fresh `data/audit-live.sqlite`) | 104 |
| Hash chain | ok |
| OTel spans with `mcp_rbac.decision` | 104 |

104 = 71 matrix decisions (17 + 14 + 12 + 5 + 23) + 33 guarded latency probes
(11 reps × 3 tools). Direct latency probes do not go through the guard, so
they are not in the audit.

## Guard latency vs calling Klaviyo MCP directly

11 repetitions per tool, 400 ms spacing, after the matrix. **Direct** is a
second `uvx klaviyo-mcp-server` stdio client with the same key. **Guarded** is
the same tool call through Better Auth + mcp-rbac HTTP + the already-running
local MCP. Overhead below is `guarded percentile − direct percentile`
(independent samples, not paired).

| Tool | Direct p50 | Direct p99 | Guarded p50 | Guarded p99 | Overhead p50 | Overhead p99 |
|---|---:|---:|---:|---:|---:|---:|
| `klaviyo_get_lists` | 208.3 ms | 280.7 ms | 211.0 ms | 228.4 ms | **2.7 ms** | −52.3 ms* |
| `klaviyo_get_campaigns` | 360.5 ms | 580.3 ms | 372.0 ms | 634.2 ms | **11.4 ms** | 53.9 ms |
| `klaviyo_get_account_details` | 172.6 ms | 1228.9 ms | 1152.1 ms | 17176.1 ms | 979.5 ms | 15.9 s |

\*Guarded p99 was faster than direct p99 on lists; that is run-to-run variance,
not a negative-cost engine.

Typical policy-engine cost is the lists/campaigns p50: about **3–11 ms** on
top of the Klaviyo call. The account-details tail (max 17.2 s guarded, and a
1.15 s p50) is not representative of the guard; Klaviyo response headers on
this account advertise `ratelimit-limit: 10, 10;w=1, 150;w=60`, and this
probe ran immediately after the matrix. Direct account-details also had a
1.2 s max. Treat the 17 s sample as a stall, not as steady-state overhead.

## Drafts created (please clean these up)

All are named `mcp-rbac-e2e draft do not send`. Campaigns were created as
**status: Draft**, smart sending on, scheduled statically for **2:05 PM
America/New_York on 2027-02-13** (90 days out). Nothing was sent. They
targeted the account's existing list `TFL5g9` (Text Messaging List), which
this test did not create.

| Kind | ID | Created by | Notes |
|---|---|---|---|
| Campaign | `01M7G9K7PGKCJ3Z2FZXWVB7KYS` | owner (this passing run) | Draft; do not send |
| Campaign | `01M7G9KCE1EGTXA6S5XNVF1XYM` | marketer (this passing run) | Draft; do not send |
| Email template | `X9RzEb` | owner (this passing run) | |
| Email template | `TpKhWr` | marketer (this passing run) | |
| Email template | `YyNbzi` | owner (earlier live attempt in this session) | Still on the account |
| Email template | `YpxESw` | marketer (earlier live attempt in this session) | Still on the account |

No profiles, events, images, subscriptions, unsubscribes, or sends were
performed. No lists or segments were created.

## How to reproduce

```sh
cd examples/klaviyo-e2e
# KLAVIYO_PRIVATE_API_KEY already in .env (do not commit it)
npx tsx src/driver.ts --mode=live
```
