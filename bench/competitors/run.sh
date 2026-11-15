#!/usr/bin/env bash
# Re-run the P9 competitor benchmark (local only). Writes bench/competitors/results/*.json.
#   bench/competitors/run.sh [redteam|load|loc|all]
# Needs: /opt/tools/competitors/{cerbos,agentgateway,pomerium,oha}, /opt/tools/openfga/openfga, node 24, python/.venv,
#        `npm ci` in bench/competitors, and for Pomerium these /etc/hosts entries:
#        127.0.0.1 authenticate.mcpbench.test venue.mcpbench.test marketing.mcpbench.test idp.mcpbench.test
set -euo pipefail
cd "$(dirname "$0")/../.."
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
PY=python/.venv/bin/python
what="${1:-all}"
for h in authenticate venue marketing idp; do
  getent hosts "$h.mcpbench.test" | grep -q '^127\.0\.0\.1' || { echo "missing /etc/hosts entry for $h.mcpbench.test (Pomerium target)"; exit 1; }
done
(cd bench/competitors && [ -d node_modules ] || npm ci --no-audit --no-fund)
if [[ $what == redteam || $what == all ]]; then
  $PY -m bench.competitors.redteam_compare mcp-rbac baseline cerbos openfga policy-guard agentgateway pomerium
  $PY -m bench.competitors.protect_probe
fi
if [[ $what == load || $what == all ]]; then
  rm -f bench/competitors/results/load-summary.json
  $PY -m bench.competitors.load baseline mcp-rbac mcp-rbac-noaudit cerbos openfga policy-guard agentgateway pomerium protect-mcp
fi
if [[ $what == loc || $what == all ]]; then
  $PY -m bench.competitors.loc
fi
$PY -m bench.competitors.summarize
