#!/usr/bin/env python3
"""Generate packs/klaviyo/pack.json from the official Klaviyo MCP tools page snapshot
(examples/klaviyo-e2e/catalog/klaviyo-tools.json, fetched 2026-11-15 from
https://developers.klaviyo.com/en/docs/klaviyo_mcp_server_available_tools).

Every tool keeps Klaviyo's own `readOnly` flag as the base (read vs write). The rest is mcp-rbac's reading of the
documented description, recorded per tool with `source` and `confidence`:
  - send_campaign sends to a whole audience           -> send + external-comm (high)
  - consent changes (subscribe/unsubscribe/suppress)   -> write + x-consent (high: name + description)
  - delete_* / bulk_delete_* / request_profile_deletion / merge_profiles -> destructive (high: irreversible per name)
  - webhooks, upload_image_from_url, sending domains   -> external-comm (data leaves / enters from arbitrary URLs)
  - coupons create/update                              -> x-discount (money-like codes, no direct spend)
  - profile / event / review / custom-object data      -> sensitivity pii (not metric definitions or aggregates);
    hasUserGeneratedContent -> ugc
Run: python3 tools/packs/gen_klaviyo.py  (deterministic; commits the diff)."""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
SNAP = ROOT / "examples/klaviyo-e2e/catalog/klaviyo-tools.json"
OUT = ROOT / "packs/klaviyo/pack.json"
cat = json.loads(SNAP.read_text())
PII_CATS = {"Profiles", "Events", "Reviews", "Data Privacy", "Customer Agent", "Custom Objects"}
CONSENT = {"subscribe_profile_to_marketing", "unsubscribe_profile_from_marketing", "bulk_suppress_profiles", "bulk_unsuppress_profiles"}
EXTERNAL = {"create_webhook", "update_webhook", "upload_image_from_url", "create_sending_domain", "create_sending_domain_activation_job", "create_sending_domain_verification_job"}
RESOURCE_ARGS = {"Campaigns": "$.campaign_id", "Flows": "$.flow_id", "Profiles": "$.profile_id"}

tools = {}
for t in cat["tools"]:
    n, ro, c = t["name"], t["readOnly"], t["category"]
    verb = n.split("_")[0]
    e: dict = {"source": "klaviyo-tools-page", "confidence": "high"}
    notes = []
    if ro:
        classes = ["read"]
    elif verb in ("retrieve",):  # documented as "Get details of …" but flagged non-read-only on the page
        classes = ["read"]
        e["confidence"] = "medium"
        notes.append("page marks readOnly=false; description is a read")
    else:
        classes = ["write"]
    if n == "send_campaign":
        classes = ["send", "external-comm", "write"]
        notes.append("sends the campaign to its configured audience (email/SMS; SMS uses paid credits)")
    if n == "cancel_campaign_send":
        notes.append("reverts a scheduled send")
    if n in CONSENT:
        classes += ["x-consent"]
        notes.append("changes a person's marketing consent")
    if verb == "delete" or n.startswith("bulk_delete_") or n in ("request_profile_deletion", "merge_profiles"):
        classes += ["destructive"]
    if n in EXTERNAL:
        classes += ["external-comm"]
        e["confidence"] = "medium"
        notes.append("data is sent to or fetched from a caller-chosen URL / domain")
    if c == "Coupons" and not ro and verb != "delete":
        classes += ["x-discount"]
        e["confidence"] = "medium"
        notes.append("creates or edits discount codes (money-like, no direct charge)")
    if n == "report_unsupported_task":
        notes.append("sends the model's task description to Klaviyo")
    e["classes"] = classes
    sens = []
    if (c in PII_CATS and "metric" not in n) or "profiles" in n:  # metric definitions/aggregates are not personal data
        sens.append("pii")
    if t["hasUserGeneratedContent"]:
        sens.append("ugc")
    if sens:
        e["sensitivity"] = sens
    if not ro and c in RESOURCE_ARGS and verb not in ("create", "bulk"):
        e["resources"] = [RESOURCE_ARGS[c]]
        notes.append(f"resource arg {RESOURCE_ARGS[c]} as the local package names it (examples/klaviyo-e2e/src/live-args.ts); hosted names unverified")
    if notes:
        e["note"] = "; ".join(notes)
    tools[n] = {k: e[k] for k in ("classes", "spend", "resources", "sensitivity", "source", "confidence", "note") if k in e}

pack = {
    "$schema": "../../spec/mcp-rbac-pack.schema.json",
    "pack": "klaviyo",
    "version": "2026.11.15",
    "title": "Klaviyo MCP server",
    "description": "Side-effect classes and data sensitivity for the 309 tools on Klaviyo's official MCP tools page. "
                   "Tool names are unprefixed (hosted server). The local package (uvx klaviyo-mcp-server) exposes a subset "
                   "with a klaviyo_ prefix: use {name: klaviyo, prefix: klaviyo_}.",
    "server": {"hosted": "https://mcp.klaviyo.com/mcp", "local": "uvx klaviyo-mcp-server@latest", "localPrefix": "klaviyo_"},
    "license": "Apache-2.0",
    "sources": [
        {"id": "klaviyo-tools-page", "url": cat["source"], "retrieved": "2026-11-15", "what": "tool names, categories, readOnly and user-generated-content flags"},
        {"id": "klaviyo-connect", "url": "https://developers.klaviyo.com/en/docs/connect_to_the_klaviyo_mcp_server", "retrieved": "2026-11-15", "what": "hosted URL, local package, READ_ONLY flag"},
        {"id": "local-run", "url": "examples/klaviyo-e2e/LIVE-RESULTS.md", "retrieved": "2026-11-15", "what": "28 klaviyo_-prefixed tools observed on the local package"},
    ],
    "tools": tools,
}
OUT.write_text(json.dumps(pack, indent=1, ensure_ascii=False) + "\n")
print(f"wrote {OUT.relative_to(ROOT)}: {len(tools)} tools")
