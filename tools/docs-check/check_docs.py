#!/usr/bin/env python3
"""Docs consistency checks used by tools/docs-check.sh:
  sync   : every `<!-- snippet: path -->` block in the Markdown docs equals the file it names (--fix rewrites the docs)
  llms   : every relative link in llms.txt exists
  packs  : TS, Python and Go resolve the same policy with packs to the same (order-preserving) JSON"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
BLOCK = re.compile(r"<!-- snippet: (?P<path>[^ ]+) -->\n```(?P<lang>[a-z]*)\n(?P<body>.*?)\n```", re.S)


def docs():
    yield from [ROOT / "README.md", ROOT / "AGENTS.md"]
    yield from sorted((ROOT / "docs").glob("*.md"))
    yield ROOT / "spec/tool-semantics.md"


def sync(fix: bool) -> int:
    bad = n = 0
    for f in docs():
        text = f.read_text()

        def repl(m):
            nonlocal bad, n
            n += 1
            want = (ROOT / m["path"]).read_text().rstrip()
            if m["body"] != want:
                bad += 1
                print(f"  {f.relative_to(ROOT)}: snippet {m['path']} is out of date")
            return f"<!-- snippet: {m['path']} -->\n```{m['lang']}\n{want}\n```"

        new = BLOCK.sub(repl, text)
        if fix and new != text:
            f.write_text(new)
    print(f"snippet blocks: {n} checked, {bad} out of date{' (fixed)' if fix and bad else ''}")
    return 0 if fix or not bad else 1


def llms() -> int:
    links = re.findall(r"\]\(([^)]+)\)", (ROOT / "llms.txt").read_text())
    missing = [l for l in links if not re.match(r"[a-z]+:", l) and not (ROOT / l.split("#")[0]).exists()]
    print(f"llms.txt links: {len(links)}, missing {len(missing)} {missing if missing else ''}")
    return 1 if missing else 0


def packs() -> int:
    policy = "version: 1\nroles:\n  r: {}\nsemantics:\n  tools:\n    \"zz*\": {classes: [write]}\n    get_me: {classes: [write]}\n  packs: [{name: klaviyo, prefix: klaviyo_}, github, stripe, ./x.pack.json]\n  grants: {r: [read]}\n"
    tmp = ROOT / "tools/docs-check/.tmp"
    tmp.mkdir(exist_ok=True)
    (tmp / "p.yaml").write_text(policy)
    (tmp / "x.pack.json").write_text('{"pack":"x","tools":{"zeta":{"classes":["read"]},"alpha":{"classes":["spend"]}}}')
    ts = subprocess.run(["npx", "tsx", "-e", f"import {{ loadPolicyWithPacks }} from './src/packs.ts'; process.stdout.write(loadPolicyWithPacks({json.dumps(str(tmp / 'p.yaml'))}))"],
                        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    py = subprocess.run([str(ROOT / "python/.venv/bin/python"), "-c", f"from mcp_rbac import load_policy_with_packs; print(load_policy_with_packs({json.dumps(str(tmp / 'p.yaml'))}), end='')"],
                        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    gosrc = tmp / "gopacks"
    gosrc.mkdir(exist_ok=True)
    (gosrc / "main.go").write_text('package main\nimport ("context";"fmt";"os";m "github.com/saarimz/mcp-rbac/go")\nfunc main(){ctx:=context.Background();rt,_:=m.NewRuntime(ctx);s,err:=rt.LoadPolicyWithPacks(ctx,os.Args[1],m.PackOptions{});if err!=nil{panic(err)};fmt.Print(s)}\n')
    go = subprocess.run(["go", "run", str(gosrc / "main.go"), str(tmp / "p.yaml")], cwd=ROOT / "go", capture_output=True, text=True, check=True).stdout
    a, b, c = (json.loads(x, object_pairs_hook=lambda kv: kv) for x in (ts, py, go))
    ok = a == b == c
    tools = json.loads(ts)["semantics"]["tools"]
    print(f"pack resolution TS == Python == Go: {ok} ({len(tools)} tools, first {list(tools)[:2]}, local pack last: {list(tools)[-2:]})")
    return 0 if ok else 1


if __name__ == "__main__":
    cmd = sys.argv[1]
    sys.exit({"sync": lambda: sync("--fix" in sys.argv), "llms": llms, "packs": packs}[cmd]())
