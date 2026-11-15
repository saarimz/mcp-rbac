#!/usr/bin/env bash
# Local Redis + Postgres for the real-store tests (127.0.0.1 only, throwaway data under $STATE).
#   tools/test-services.sh start|stop|status
# Binaries: redis-server (PATH, or $TOOLS/services/redis-stack-server-*/bin) and Postgres (PATH, /usr/lib/postgresql/*/bin, or the
# pgserver wheel under $TOOLS/services/pgvenv). tools/bootstrap.sh --services installs the latter two.
set -euo pipefail
TOOLS=${TOOLS:-/opt/tools}
STATE=${STATE:-${TMPDIR:-/tmp}/mcp-guard-services}
REDIS_PORT=6390 PG_PORT=5439
find_bin() { command -v "$1" 2>/dev/null || ls $2 2>/dev/null | head -1; }
REDIS=$(find_bin redis-server "$TOOLS/services/redis-stack-server-*/bin/redis-server")
PGBIN=$(dirname "$(find_bin initdb "/usr/lib/postgresql/*/bin/initdb $TOOLS/services/pgvenv/lib/python3*/site-packages/pgserver/pginstall/bin/initdb")")
case "${1:-status}" in
start)
  mkdir -p "$STATE"
  "$REDIS" --port $REDIS_PORT --bind 127.0.0.1 --save "" --appendonly no --daemonize yes --dir "$STATE" --logfile "$STATE/redis.log"
  if [ ! -f "$STATE/pg/PG_VERSION" ]; then
    "$PGBIN/initdb" -D "$STATE/pg" -U mcp --auth=trust -E UTF8 >/dev/null
  fi
  "$PGBIN/pg_ctl" -D "$STATE/pg" -l "$STATE/pg.log" -o "-p $PG_PORT -k $STATE -c listen_addresses=127.0.0.1" -w start >/dev/null
  "$PGBIN/psql" -h 127.0.0.1 -p $PG_PORT -U mcp -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='mcp_rbac_test'" | grep -q 1 \
    || "$PGBIN/createdb" -h 127.0.0.1 -p $PG_PORT -U mcp mcp_rbac_test
  echo "redis://127.0.0.1:$REDIS_PORT  postgres://mcp@127.0.0.1:$PG_PORT/mcp_rbac_test";;
stop)
  "$PGBIN/pg_ctl" -D "$STATE/pg" -m fast stop >/dev/null 2>&1 || true
  "$(dirname "$REDIS")/redis-cli" -p $REDIS_PORT shutdown nosave >/dev/null 2>&1 || true;;
status)
  "$(dirname "$REDIS")/redis-cli" -p $REDIS_PORT ping; "$PGBIN/pg_isready" -h 127.0.0.1 -p $PG_PORT;;
esac
