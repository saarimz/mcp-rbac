"""Python pure runner: corpus.jsonl -> one result line per vector (same contract as `mcp-rbac-core vectors`)."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "python/src"))
from mcp_rbac.portable import PolicyError, canonical, load_yaml, decide_json, load_policy_json, load_policy_yaml, visible_json, cost_json  # noqa: E402

path = sys.argv[1] if len(sys.argv) > 1 else str(pathlib.Path(__file__).resolve().parent / "corpus.jsonl")
cache: dict = {}
out = []
with open(path, encoding="utf-8") as f:
    for line in f:
        if not line.strip():
            continue
        v = json.loads(line)
        if "yamlDoc" in v:
            try:
                out.append(canonical({"doc": load_yaml(v["yamlDoc"])}))
            except PolicyError:
                out.append('{"error":"yaml_invalid"}')
            continue
        if "costJson" in v:
            out.append(cost_json(v["costJson"]))
            continue
        key = ("y" + v["policyYaml"]) if "policyYaml" in v else ("j" + v["policyJson"])
        if key not in cache:
            try:
                cache[key] = load_policy_yaml(v["policyYaml"]) if "policyYaml" in v else load_policy_json(v["policyJson"])
            except PolicyError:
                cache[key] = None
            except Exception as e:  # anything else is a bug: report it, don't hide it as policy_invalid
                cache[key] = e
        p = cache[key]
        if p is None:
            out.append('{"error":"policy_invalid"}')
            continue
        if isinstance(p, Exception):
            out.append(json.dumps({"harness_error": f"{type(p).__name__}: {p}"}))
            continue
        try:
            if "requestJson" in v:
                out.append(decide_json(p, v["requestJson"]))
            elif "visibleJson" in v:
                out.append(visible_json(p, v["visibleJson"]))
            else:
                out.append(canonical({"ok": True, "warnings": p.warnings}))
        except Exception as e:
            out.append(json.dumps({"harness_error": f"{type(e).__name__}: {e}"}))
sys.stdout.write("\n".join(out) + "\n")
