"""Python + PyO3 binding runner (Rust core through PyO3): same contract as `mcp-rbac-core vectors`."""
import json
import pathlib
import sys

import mcp_rbac_core as core

path = sys.argv[1] if len(sys.argv) > 1 else str(pathlib.Path(__file__).resolve().parent / "corpus.jsonl")
cache: dict = {}
out = []
with open(path, encoding="utf-8") as f:
    for line in f:
        if not line.strip():
            continue
        v = json.loads(line)
        if "yamlDoc" in v:
            out.append(core.yaml_to_json(v["yamlDoc"]))
            continue
        key = ("y" + v["policyYaml"]) if "policyYaml" in v else ("j" + v["policyJson"])
        if key not in cache:
            try:
                cache[key] = core.Engine(v["policyYaml"]) if "policyYaml" in v else core.Engine.from_json(v["policyJson"])
            except ValueError:
                cache[key] = None
        e = cache[key]
        if e is None:
            out.append('{"error":"policy_invalid"}')
        elif "requestJson" in v:
            out.append(e.decide(v["requestJson"]))
        elif "visibleJson" in v:
            out.append(e.visible(v["visibleJson"]))
        else:
            out.append('{"ok":true,"warnings":' + e.warnings() + "}")
sys.stdout.buffer.write(("\n".join(out) + "\n").encode("utf-8", "surrogatepass"))
