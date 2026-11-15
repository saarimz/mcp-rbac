#!/usr/bin/env python3
"""Generate packs/github/pack.json from github/github-mcp-server's own tool snapshots (pkg/github/__toolsnaps__/*.snap),
which carry each tool's MCP ToolAnnotations and inputSchema.

  python3 tools/packs/gen_github.py /path/to/github-mcp-server   # refresh the snapshot, then generate
  python3 tools/packs/gen_github.py                             # generate from tools/packs/snapshots/github.json

Base classes come from the server's annotations (readOnlyHint -> read, else write; destructiveHint -> destructive).
openWorldHint is NOT copied as external-comm: the server sets it on reactions and sub-issue edits, which stay inside
GitHub. mcp-rbac refinements (recorded per tool in `note`, confidence medium unless stated):
  - posts that notify other people (issues, comments, PRs, reviews, review requests) -> send
  - code changes on a branch (push_files, create_or_update_file, delete_file, update_pull_request_branch) -> x-code-change
  - merge_pull_request -> x-merge (high)
  - repo administration (create/delete/fork repo, rulesets, custom properties) -> x-admin (high)
  - actions_run_trigger -> x-compute (runs CI on GitHub-hosted runners, can bill Actions minutes)
  - Copilot coding agent assignment / review -> x-compute (consumes Copilot premium requests)
  - public gists -> external-comm
  - secret scanning tools -> sensitivity secrets; code/file/log reads -> sensitivity source-code
  - resources: $.owner and $.repo when the tool takes both."""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SNAP = ROOT / "tools/packs/snapshots/github.json"
OUT = ROOT / "packs/github/pack.json"

if len(sys.argv) > 1:
    repo = pathlib.Path(sys.argv[1])
    commit = subprocess.check_output(["git", "-C", str(repo), "log", "-1", "--format=%H"], text=True).strip()
    date = subprocess.check_output(["git", "-C", str(repo), "log", "-1", "--format=%cs"], text=True).strip()
    tools = {}
    for f in sorted((repo / "pkg/github/__toolsnaps__").glob("*.snap")):
        d = json.loads(f.read_text())
        if not isinstance(d.get("annotations"), dict) or "name" not in d:
            continue  # *_output.snap files are output-schema snapshots, not tools
        props = sorted(((d.get("inputSchema") or {}).get("properties") or {}).keys())
        tools[d["name"]] = {"annotations": {k: v for k, v in d["annotations"].items() if k.endswith("Hint")}, "args": props}
    SNAP.write_text(json.dumps({"repo": "https://github.com/github/github-mcp-server", "commit": commit, "date": date, "tools": tools}, indent=1) + "\n")
snap = json.loads(SNAP.read_text())

NOTIFY = {"add_issue_comment", "add_reply_to_pull_request_comment", "create_issue", "create_pull_request", "create_pull_request_review",
          "submit_pending_pull_request_review", "pull_request_review_write", "request_pull_request_reviewers", "discussion_comment_write",
          "issue_write", "update_issue_comment", "add_pull_request_review_comment"}
CODE = {"push_files", "create_or_update_file", "delete_file", "update_pull_request_branch", "create_branch"}
ADMIN = {"create_repository", "delete_repository", "fork_repository", "create_repository_ruleset", "custom_properties_write"}
COMPUTE = {"actions_run_trigger": "runs or reruns GitHub Actions workflows (can bill Actions minutes)",
           "assign_copilot_to_issue": "starts the Copilot coding agent (consumes premium requests)",
           "assign_copilot_to_issue_with_intent": "starts the Copilot coding agent (consumes premium requests)",
           "request_copilot_review": "requests a Copilot review (consumes premium requests)"}
SECRETS = {"get_secret_scanning_alert", "list_secret_scanning_alerts"}
CODE_READ = {"get_file_contents", "search_code", "get_file_blame", "get_commit", "get_job_logs", "get_job_logs_actions", "get_repository_tree", "pull_request_read"}

out = {}
for name, t in sorted(snap["tools"].items()):
    a = t["annotations"]
    classes = ["read"] if a.get("readOnlyHint") is True else ["write"]
    if a.get("destructiveHint") is True:
        classes.append("destructive")
    notes, conf = [], "high"
    if name in NOTIFY:
        classes.append("send"); notes.append("posts content that notifies other people"); conf = "medium"
    if name in CODE:
        classes.append("x-code-change"); notes.append("changes repository contents")
    if name == "merge_pull_request":
        classes.append("x-merge")
    if name in ADMIN:
        classes.append("x-admin")
    if name in COMPUTE:
        classes.append("x-compute"); notes.append(COMPUTE[name]); conf = "medium"
    if name in ("create_gist", "update_gist"):
        classes.append("external-comm"); notes.append("a public gist publishes content to anyone"); conf = "medium"
    e: dict = {"classes": classes}
    if "owner" in t["args"] and "repo" in t["args"]:
        e["resources"] = ["$.owner", "$.repo"]
    sens = (["secrets"] if name in SECRETS else []) + (["source-code"] if name in CODE_READ else [])
    if sens:
        e["sensitivity"] = sens
    e["source"] = "github-toolsnaps"
    e["confidence"] = conf
    if notes:
        e["note"] = "; ".join(notes)
    out[name] = e

pack = {
    "$schema": "../../spec/mcp-rbac-pack.schema.json",
    "pack": "github",
    "version": snap["date"].replace("-", "."),
    "title": "GitHub MCP server (github/github-mcp-server)",
    "description": f"Side-effect classes for the {len(out)} tools in github-mcp-server's tool snapshots at {snap['commit'][:12]}. "
                   "Base classes are the server's own ToolAnnotations; refinements are listed per tool.",
    "server": {"hosted": "https://api.githubcopilot.com/mcp/", "local": "ghcr.io/github/github-mcp-server", "repo": snap["repo"], "commit": snap["commit"]},
    "license": "Apache-2.0",
    "sources": [
        {"id": "github-toolsnaps", "url": f"{snap['repo']}/tree/{snap['commit']}/pkg/github/__toolsnaps__", "retrieved": "2026-11-15",
         "what": "tool names, ToolAnnotations (readOnlyHint, destructiveHint, openWorldHint), inputSchema argument names"},
        {"id": "github-readme", "url": f"{snap['repo']}/blob/{snap['commit']}/README.md", "retrieved": "2026-11-15", "what": "toolsets, tool descriptions, OAuth scopes per tool"},
    ],
    "tools": out,
}
OUT.write_text(json.dumps(pack, indent=1, ensure_ascii=False) + "\n")
print(f"wrote {OUT.relative_to(ROOT)}: {len(out)} tools from {snap['commit'][:12]}")
