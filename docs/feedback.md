# Feedback (`--with-feedback`)

An **opt-in** `submit_feedback` tool that lets agents report problems with your MCP server's tools, with a proposed fix,
so the server can improve from real use. It is **off by default**. When on, the guard lists one extra tool next to your
server's own. Your server never sees the call: the guard answers it.

The idea comes from Matt Ambrogi's post about letting agents file feedback on the tools they use. mcp-rbac adds what a
production server needs around it: the policy decides who may file, the report is size-checked and stripped of secrets
and personal data, and it lands in OpenTelemetry and the hash-chained audit log, linked to the trace of the request.

## What the agent sends

| field | required | notes |
|-------|----------|-------|
| `summary` | yes | one line |
| `what_happened` | yes | the call it made and what came back |
| `expected` | no | what it expected instead |
| `proposed_fix` | no | a concrete fix: code, a better description, a missing parameter or tool |
| `tool_name` | no | the tool the report is about |
| `severity` | no | `low`, `medium` (default), `high`, `critical` |
| `session_id`, `trace_id` | no | correlation ids, `[A-Za-z0-9._:/-]`, 1–128 chars |

Any other field rejects the report. The agent gets `Feedback recorded (id …).` or `Feedback rejected: <reason>`, for
example `what_happened:required`, `summary:too_long`, `severity:invalid` or `unknown_field`.

## Turning it on

Pick one of these. Then **grant `submit_feedback` to the roles that may file**. The policy decides, as it does for any
tool, so a role without the grant neither sees nor calls it.

**Policy** (every binding and the proxy read it):

```yaml
roles:
  agent:
    tools: [search, get_doc, submit_feedback]
tools:
  submit_feedback:
    limits:
      severity: {in: [low, medium, high], optional: true}   # agents cannot file "critical"
      summary: {maxLength: 200}
limits:
  - {tool: submit_feedback, max: 5, per: hour}              # rate limit, per user
feedback:                     # present = on (enabled: false turns it off)
  maxFieldChars: 2000         # per text field, UTF-16 code units (default 4000, max 20000)
  maxTotalChars: 8000         # all fields together (default 16000, max 100000)
  pii: strip                  # strip (default): emails and phone numbers removed; keep: only secrets removed
```

**Proxy:** `mcp-rbac proxy --policy mcp-rbac.yaml --role agent --with-feedback -- <server command>`. It needs a portable
policy (the core engine). Reports go to the proxy's audit database (table `core_audit`), and a one-line note goes to
stderr. Add `--otel` to export them through OpenTelemetry (below).

**SDK option** (it wins over the policy block; `false` turns feedback off even when the policy has one):

| | |
|---|---|
| TypeScript | `protectWithCore(server, { policy, feedback: true \| { maxFieldChars, maxTotalChars, pii, otel, onFeedback } })` |
| Python | `CoreGuard(policy, ..., feedback=True \| {"max_field_chars", "max_total_chars", "pii", "otel", "on_feedback"})` |
| Go | `GuardOptions{Feedback: &mcprbac.FeedbackOptions{MaxFieldChars, MaxTotalChars, PII, LoggerProvider, Audit, OnFeedback}}` |
| Rust (rmcp) | `opts.feedback = Some(FeedbackOptions { max_field_chars, max_total_chars, pii, on_feedback, ..Default::default() })` |

## What the guard does with a report

1. **Authorize** it like any tool call: roles, `limits`, rate limits, approvals and the decision audit row. A rejected
   or rate-limited report never reaches the steps below. Malformed reports also count against the rate limit.
2. **Validate and sanitize** it in the Rust core (`mcp_rbac_core::feedback`). The pure TypeScript and Python engines
   are byte-identical ports, and the conformance corpus checks all six runners (`feedbackJson` vectors). It checks
   types, required fields and size limits. Then it replaces these, token by token, with `[REDACTED:secret]`:
   known key prefixes (`sk-`, `sk_live_`, `ghp_`, `github_pat_`, `xox*`, `glpat-`, `AKIA`, `AIza`, …), `key=value` pairs
   whose key ends in `password`, `secret`, `token`, `api_key`, `access_key`, `private_key` or `client_secret`, URL
   credentials (`scheme://user:pass@host`), JWTs, the token after `Bearer`, and long high-entropy strings. With
   `pii: strip` it also replaces emails (`[REDACTED:email]`) and phone numbers (`[REDACTED:phone]`). Redaction is a
   best-effort filter, not a guarantee. Treat feedback as untrusted text written by an agent.
3. **Export** it as one OpenTelemetry log record in the request's trace (below).
4. **Audit** it: one extra row in the hash-chained audit with decision `feedback`, reason `feedback:<severity>`, the
   caller's `sub` and `tenant`, and the sanitized report plus its id under `feedback`. It is hashed into the chain, and
   `mcp-rbac audit-verify` checks it in every language.
5. **Hand it to your hook** (`onFeedback` / `on_feedback` / `OnFeedback`), for example to open an issue. A failing hook
   is logged and never surfaces to the agent.

The report **id** is the SHA-256 of the canonical sanitized report. It is the same in OTel, the audit row, the hook and
across languages, so you can deduplicate on it.

## OpenTelemetry

| | |
|---|---|
| event name | `mcp_rbac.feedback` |
| severity | `INFO` for low and medium, `WARN` for high, `ERROR` for critical |
| body | the canonical sanitized report (JSON) |
| trace context | the request's server span (the `tools/call submit_feedback` span, which also gets `mcp_rbac.feedback.id`) |
| attributes | `gen_ai.tool.name` = `submit_feedback`, `mcp_rbac.feedback.id`, `mcp_rbac.feedback.severity`, `mcp_rbac.feedback.summary`, `mcp_rbac.feedback.target_tool`, `mcp_rbac.feedback.session_id`, `mcp_rbac.feedback.reported_trace_id`, `mcp_rbac.feedback.chars`, `mcp_rbac.feedback.redactions.{email,phone,secret}`, `mcp_rbac.tenant` |

The caller's identity is **never** exported to OpenTelemetry. It goes only to the audit row and your hook.

Export is on when telemetry is on (TS `telemetry` or `audit.otel`, Python `telemetry` or `audit={"otel": …}`, Go
`Telemetry`, Rust `Telemetry` with a logger provider), or when you pass a logger provider in the feedback options. The
rmcp binding also emits a `tracing` event on target `mcp_rbac.feedback`. It has no audit sink of its own, so write rows
from `on_feedback` with `FeedbackEvent::audit_event`.

## Piping it to a collector, Slack or an issue tracker

Point your OTLP exporter at a collector. For the proxy, load an OTel SDK that registers the global tracer and logger
providers, for example [`examples/feedback/otel-register.mjs`](../examples/feedback/otel-register.mjs). It needs
`@opentelemetry/sdk-trace-base`, `sdk-logs`, `context-async-hooks`, `exporter-trace-otlp-http` and
`exporter-logs-otlp-http`.

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 NODE_OPTIONS="--import ./otel-register.mjs" \
  mcp-rbac proxy --policy mcp-rbac.yaml --role agent --with-feedback --otel -- <server command>
```

Then keep only feedback in a dedicated logs pipeline (the full config is
[`examples/feedback/collector.yaml`](../examples/feedback/collector.yaml), tested with otelcol-contrib 0.165.0):

```yaml
# otelcol-contrib
receivers:
  otlp: {protocols: {http: {endpoint: 0.0.0.0:4318}}}
processors:
  filter/feedback:
    logs:
      log_record:
        - 'event_name != "mcp_rbac.feedback"'   # drop everything that is not feedback
exporters:
  otlphttp/triage: {endpoint: https://your-triage-service.example}   # or file, loki, elasticsearch, datadog, …
service:
  pipelines:
    logs/feedback: {receivers: [otlp], processors: [filter/feedback], exporters: [otlphttp/triage]}
```

From there you can forward it to **Slack** (a webhook receiver that posts the summary and severity), to an **issue
tracker** (GitHub, Linear, Jira: open one issue per new `mcp_rbac.feedback.id`), or to a dashboard grouped by
`mcp_rbac.feedback.target_tool`. To skip the collector, do the same from the `onFeedback` hook. mcp-rbac itself never
calls Slack or an issue tracker.
