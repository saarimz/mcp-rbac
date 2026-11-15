# Klaviyo MCP e2e (mcp-rbac guard + Better Auth)

Local end-to-end harness: **Better Auth** issues sessions for three seeded
users, **mcp-rbac** sits in front of Klaviyo's official MCP tool catalog, and a
driver signs in as each role and attempts every tool. OpenTelemetry traces and
a hash-chained audit log are written under `out/` and `data/`.

By default the Klaviyo upstream is an **in-process mock** labelled `MOCKED`.
Nothing in this directory creates a Klaviyo account, private API key, or OAuth
app. Live mode starts only when you put a key in `.env`.

## How Klaviyo MCP authentication works

Official docs (retrieved 2026-11-15, America/New_York). See `catalog/SOURCES.md`.

### Remote hosted server (OAuth)

- URL: `https://mcp.klaviyo.com/mcp` (no trailing slash)
- Auth: **OAuth with dynamic client registration**
- Transport: Streamable HTTP
- The connecting Klaviyo user must be an **Owner, Admin, or Manager**
- Query parameters (`read-only`, `core-tools-only`, `toolsets`, `beta`, …) are
  documented on the connect page

Sources:
- https://developers.klaviyo.com/en/docs/connect_to_the_klaviyo_mcp_server
- https://www.klaviyo.com/solutions/ai/klaviyo-mcp-server

The hosted connector (e.g. Claude) asks the user to approve a large OAuth
scope list (accounts, campaigns, profiles, templates, …). That list is in
Klaviyo's Claude FAQ:
https://help.klaviyo.com/hc/en-us/articles/51798102561435

OAuth is the right path for interactive clients (Claude, Cursor, ChatGPT). It
is a poor fit for a headless e2e driver: it needs a browser login as an
Owner/Admin/Manager on the test account. This harness is therefore built
around the **local package + private API key**, and can be pointed at the
hosted URL later if you complete that OAuth flow yourself.

### Local package (private API key)

```json
{
  "mcpServers": {
    "klaviyo": {
      "command": "uvx",
      "args": ["klaviyo-mcp-server@latest"],
      "env": {
        "PRIVATE_API_KEY": "YOUR_API_KEY",
        "READ_ONLY": "false",
        "ALLOW_USER_GENERATED_CONTENT": "false"
      }
    }
  }
}
```

Source: the same connect page. The official env var is `PRIVATE_API_KEY`.
This harness also accepts `KLAVIYO_PRIVATE_API_KEY` and copies it across.

### Tool catalog

309 tools, snapshot in `catalog/klaviyo-tools.json`, from
https://developers.klaviyo.com/en/docs/klaviyo_mcp_server_available_tools

## What I need from you for a live run

Do **not** hand over the Klaviyo account password. Create a **private API key**
on the free test account (`mcp-rbac test`, public site key `UGJTx2`) and put it
in `examples/klaviyo-e2e/.env` as:

```
KLAVIYO_PRIVATE_API_KEY=pk_...
```

In Klaviyo: Settings → API keys → Create private API key. The official
"all available tools" scope table for the local MCP server is:

| Scope | Access |
|---|---|
| Accounts | Read |
| Campaigns | Full |
| Catalogs | Read |
| Events | Full |
| Flows | Read |
| Images | Full |
| List | Read |
| Metrics | Read |
| Profiles | Full |
| Segments | Full |
| Subscriptions | Full |
| Tags | Read |
| Templates | Full |
| Translations | Full |

Source: https://developers.klaviyo.com/en/docs/connect_to_the_klaviyo_mcp_server

Notes:

- That table may not cover every tool on the 309-tool list (for example
  Billing, Webhooks, Brands, Custom Objects). If the official local server
  exposes a tool the key cannot call, the **guard may still allow** it
  (owner has `*`) and Klaviyo will return an API error. The report records
  that as an upstream error, not a fabricated pass.
- For the hosted server instead, use OAuth as an Owner/Admin/Manager and the
  scope list shown on the consent screen (FAQ above). This harness does not
  run that browser flow.
- The public site key `UGJTx2` is **not** sufficient; the local MCP server
  needs a private key.

The driver will not start live mode until the env var is set. It never
creates keys.

## Roles (mcp-rbac policy)

Defined in `src/roles.ts` and generated into `policy/mcp-rbac.yaml`:

| Role | Better Auth user (default) | Allowed tools |
|---|---|---|
| owner | `owner@mcp-rbac.test` | All 309 tools |
| marketer | `marketer@mcp-rbac.test` | Reads in Accounts, Campaigns, Catalogs, Groups, Templates, Flows, Images, Reporting, Tags, Translations (no UGC tools), plus create/update of campaign, template, and segment **drafts**. No deletes, no `send_campaign`, no preview-sends. |
| support | `support@mcp-rbac.test` | Read-only tools in Profiles and Events |

Passwords are generated into `.env` by `src/setup-env.ts` and are never
printed or committed.

## Safety in live mode

Even for owner (who is allowed by policy to send or delete), the driver:

- **Never** calls `send_campaign`, `cancel_campaign_send`,
  `create_template_preview_send_job`, `request_profile_deletion`,
  `unsubscribe_profile_from_marketing`, or any tool whose name looks like a
  delete/remove.
- Only forwards **read** tools and a small allow-list of draft-creating
  writes (`create_campaign`, `create_email_template`, `create_segment`, …)
  with names like `mcp-rbac-e2e draft do not send`.
- Still calls tools that the policy **denies** (marketer/support send and
  delete): the guard rejects them before they reach Klaviyo.

In **mock** mode every tool is invoked, including destructive ones, because
the mock never talks to Klaviyo.

## What has been verified vs what is mocked

See `out/report.json` after a run. The report's `mocked` flag and `label`
must be believed over any earlier claim.

| Check | Mocked run (`--mode=mock`) | Live run (`--mode=live`) |
|---|---|---|
| Policy file loads and `mcp-rbac` accepts it | real | real |
| Better Auth sign-in for three roles, bearer session | real (local) | real (local) |
| Wrong password rejected; unauthenticated MCP rejected | real (local) | real (local) |
| Per-role tools/list filtering | real (guard) | real (guard) |
| Per-role allow/deny on every catalog tool | real (guard), upstream **mocked** | real (guard); allowed reads/drafts hit official `klaviyo-mcp-server`; destructive allows are skipped |
| OTel spans with `mcp_rbac.decision` | real (file exporter; OTLP if `OTEL_EXPORTER_OTLP_ENDPOINT` is set) | same |
| Hash-chained audit log | real (sqlite) | real |
| Talks to Klaviyo's API / hosted `mcp.klaviyo.com` | **no, mocked** | official **local** package only, if a key is supplied |

## How to run

From this directory (tsx comes from the repo root):

```sh
# once
npm install
npx tsx src/setup-env.ts          # writes .env with generated passwords (not printed)
npx tsx src/generate-policy.ts    # refreshes policy/mcp-rbac.yaml from the catalog

# mocked e2e (no Klaviyo credentials)
./scripts/run-mocked.sh
# or:
npx tsx src/driver.ts --mode=mock
```

After you add `KLAVIYO_PRIVATE_API_KEY` to `.env` (and have `uv` / `uvx`):

```sh
npx tsx src/driver.ts --mode=live
```

Outputs (gitignored):

- `out/report.json` — summary, mocked/live label, mismatches
- `out/results.jsonl` — one row per role × tool
- `out/traces.jsonl` — OTel spans
- `data/audit.sqlite` — guard audit (hash-chained)
- `data/better-auth.sqlite` — Better Auth users and sessions

To serve only (driver in another terminal):

```sh
npx tsx src/server.ts              # mock
npx tsx src/server.ts --live       # live, requires the key
npx tsx src/driver.ts --mode=mock --url http://127.0.0.1:8787
```

## Layout

```
catalog/klaviyo-tools.json   official 309-tool snapshot + SOURCES.md
policy/mcp-rbac.yaml         generated portable policy
src/roles.ts                 role classification (source of truth)
src/auth.ts                  Better Auth + seed
src/mock-klaviyo.ts          mocked MCP (every result has mock: true)
src/server.ts                auth + guard + upstream
src/driver.ts                sign-in and per-tool matrix
src/otel.ts                  file + optional OTLP export
```

## Latest mocked verification

Run at 1:54 PM America/New_York on 2026-11-15 (`tsx src/driver.ts --mode=mock`).
This is a **mocked** run: the guard, Better Auth, audit chain and OTel are real;
the Klaviyo upstream is the in-process catalog replica. No Klaviyo API key was
present, and live mode was not started.

| Check | Result |
|---|---|
| Policy accepted by `checkPortablePolicy` | ok, no warnings |
| Unauthenticated MCP | rejected |
| Wrong password | rejected |
| owner | 309 allow, 0 deny, 0 mismatches |
| marketer | 72 allow, 237 deny, 0 mismatches |
| support | 25 allow, 284 deny, 0 mismatches |
| tools/list visibility | no mismatches for any role |
| Audit | 927 events this run, hash chain ok |
| OTel | 927 spans with `mcp_rbac.decision` |
| Live mode without a key | exits 2, refuses to start, creates no keys |

