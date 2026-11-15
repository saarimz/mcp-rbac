# Klaviyo live re-run with a class-based policy (P10)

Run at **3:53 PM America/New_York on 2026-11-15** with `npx tsx src/class-run.ts`. The private API key was read
from `.env` and never printed. Raw report: `out/class-report.json` (gitignored).

## What changed from the first live run

The first run (`LIVE-RESULTS.md`) used a generated policy that names tools role by role. This run's policy,
[`policy/classes.yaml`](policy/classes.yaml), names **no tools**. Roles are granted side-effect classes, and the
built-in [`klaviyo` pack](../../packs/klaviyo/pack.json) (built from Klaviyo's official tools page) says which
class each tool is in. The guard is `protectWithCore` (the Rust core via WASM) wrapping the official local package
`uvx klaviyo-mcp-server@latest` as an MCP client.

| role | classes granted | rules |
|---|---|---|
| analyst | read | `pii`-labelled tools need owner or marketer |
| marketer | + write | `external-comm` needs owner; a write budget of 2 per hour |
| owner | + send, external-comm, destructive, x-consent, x-discount | send, destructive and x-consent always need approval |

The harness refuses every approval, so `needs_approval` ends as "Approval required" and the call never reaches
Klaviyo.

## Results

The upstream package listed **24 tools** (the first run saw 28; the package has since changed).
All 24 are classified by the pack (`unknownToPack: []`).

Expectations come from an **independent oracle** in the script (pack JSON + the grant table), not from the engine.

| role | tools | expect allow | expect deny | expect approval | observed allow | observed deny | observed approval | skipped (safety / no fixture) | upstream calls | mismatches |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| analyst | 24 | 15 | 9 | 0 | 13 | 9 | 0 | 2 | 13 | 0 |
| marketer | 25 | 21 | 4 | 0 | 15 | 4 | 0 | 6 | 15 | 0 |
| owner | 24 | 22 | 0 | 2 | 14 | 0 | 2 | 8 | 14 | 0 |

(marketer has 25 rows: the 24 tools plus one write-budget probe.)

- **0 mismatches**, and `tools/list` matched the oracle for all three roles
  (analyst 15, marketer 21, owner 24 visible).
- Denials and their reasons: `Approval required` x2, `Denied: class_requires_role:external-comm` x2, `Denied: label_requires_role:pii` x4, `Denied: rate_limited:0` x1, `Denied: user:no_matching_permission` x6.
- **No denied or approval-required call reached Klaviyo.** Every tools/call to the upstream passed a tripwire that
  throws for send / destructive / consent tools; it never fired.
- **Write budget:** the marketer made 2 draft writes (create campaign, create email template); a 3rd draft write
  in the same hour was refused with `Denied: rate_limited:0` before Klaviyo saw it.
- Guard decision time over 57 calls: p50 0.103 ms, p95 0.233 ms, max 0.359 ms.
- Upstream calls in total: 42 (all reads, plus the 2 drafts).

Skipped calls: reads whose required ids had no fixture (`get_flow`: the account has no flows), and writes outside
the live draft plan (profile/event/image writes, and every owner write). `subscribe` / `unsubscribe` were only
sent where the guard would refuse them (deny for analyst and marketer, approval refused for owner).

## Drafts created on the test account

Every draft is named `mcp-rbac-e2e draft do not send`. Nothing was sent, deleted, subscribed or unsubscribed.

| run (ET) | drafts |
|---|---|
| 3:51 PM (first attempt; analyst visibility check failed, see below) | campaign `01M7GFMXXHEGDAA4J2TFQM9P9T`, template `SYhfMT` |
| 3:51-3:53 PM (second attempt; aborted on an upstream MCP request timeout, no report written) | unknown, at most one campaign and one template |
| 3:53 PM (this run) | campaign `01M7GFT7ZFYGHFQ4K2C57X0DP6`, email_template `T5RLcy` |

## Findings from the attempts

1. **`labelRules` filter calls, not `tools/list`.** The first attempt expected pii tools to be hidden from analysts;
   the engine lists them and denies the call (`label_requires_role:pii`). This is the core's existing behaviour in
   all six runners; the oracle now matches it and the gap is documented in `spec/tool-semantics.md`.
2. **The pack over-labelled metrics as pii** (Klaviyo files them under Events). Metric definitions and aggregates are
   not personal data; the generator was fixed, so analysts can now read `get_metrics` / `get_metric`.
3. **One upstream request timed out** (MCP -32001) on the second attempt. The script now records a per-call upstream
   error and keeps going instead of aborting.
