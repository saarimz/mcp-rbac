import json
import os
import signal
import sqlite3
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from mcp_rbac import SqliteAuditSink, audit_record_from_decision, verify_audit_table

ROOT = Path(__file__).resolve().parents[2]


def rec(i):
    return {"at": f"2026-11-15T00:00:{i % 60:02d}.000Z", "tool": f"t{i % 7}", "decision": "allow" if i % 3 else "deny",
            "reason": "ok" if i % 3 else "no_role", "sub": f"u{i % 5}", "tenant": "acme" if i % 2 else None,
            "approved": i % 11 == 0, "durationMs": i / 7}


def count(p, table="audit"):
    return sqlite3.connect(p).execute(f"SELECT count(*) FROM {table}").fetchone()[0]


@pytest.mark.parametrize("mode", ["sync", "batched"])
def test_write_chain_verify_restart(tmp_path, mode):
    p = str(tmp_path / "a.db")
    s = SqliteAuditSink(p, mode=mode, shutdown_hooks=False, max_batch=50)
    for i in range(1000):
        s.write(rec(i))
    s.close()
    assert s.stats()["written"] == 1000
    s2 = SqliteAuditSink(p, mode=mode, shutdown_hooks=False)
    for i in range(1000, 1100):
        s2.write(rec(i))
    s2.close()
    assert verify_audit_table(p) == {"ok": True, "head": s2.head_hash(), "count": 1100}


def test_batched_group_commit_and_flush_ordering(tmp_path):
    p = str(tmp_path / "a.db")
    s = SqliteAuditSink(p, shutdown_hooks=False, max_batch=100, flush_interval_s=0.5)
    for i in range(10):
        s.write(rec(i))
    assert count(p) == 0  # still queued (interval not reached)
    assert s.flush()
    assert count(p) == 10
    rows = [r[0] for r in sqlite3.connect(p).execute("SELECT tool FROM audit ORDER BY id")]
    assert rows == [rec(i)["tool"] for i in range(10)]
    s.close()


def test_concurrent_writers_keep_chain_valid(tmp_path):
    p = str(tmp_path / "a.db")
    s = SqliteAuditSink(p, shutdown_hooks=False, max_queue=64, max_batch=32)
    def w(k):
        for i in range(500):
            s.write(rec(k * 1000 + i))
    ts = [threading.Thread(target=w, args=(k,)) for k in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    s.close()
    assert s.stats()["max_queued"] <= 64
    assert verify_audit_table(p)["count"] == 4000 and verify_audit_table(p)["ok"]


def test_drop_overflow_counts_and_chain_valid(tmp_path):
    p = str(tmp_path / "a.db")
    s = SqliteAuditSink(p, shutdown_hooks=False, max_queue=5, max_batch=2, flush_interval_s=0.0, overflow="drop")
    s._lock.acquire()  # stall the writer's commit so the queue fills
    try:
        for i in range(50):
            s.write(rec(i))
            time.sleep(0.001)
    finally:
        s._lock.release()
    s.close()
    st = s.stats()
    assert st["dropped"] > 0 and st["written"] + st["dropped"] == 50
    assert verify_audit_table(p) == {"ok": True, "head": s.head_hash(), "count": st["written"]}


def test_failed_commit_rolls_back_batch(tmp_path):
    p = str(tmp_path / "a.db")
    errs = []
    s = SqliteAuditSink(p, mode="sync", shutdown_hooks=False, on_error=errs.append)
    s.write(rec(1))
    o = sqlite3.connect(p)
    o.execute("CREATE TRIGGER boom BEFORE INSERT ON audit WHEN NEW.tool = 'bad' BEGIN SELECT RAISE(ABORT, 'disk full'); END")
    o.commit()
    with pytest.raises(RuntimeError, match="not committed"):  # sync: the caller learns the record was not written
        s.write({**rec(2), "tool": "bad"})
    o.execute("DROP TRIGGER boom")
    o.commit()
    s.write(rec(3))
    s.close()
    assert len(errs) == 1 and s.stats()["dropped"] == 1
    assert verify_audit_table(p)["count"] == 2


def test_tamper_detected_and_bad_args(tmp_path):
    p = str(tmp_path / "a.db")
    s = SqliteAuditSink(p, shutdown_hooks=False)
    for i in range(20):
        s.write(rec(i))
    s.close()
    db = sqlite3.connect(p)
    db.execute("""UPDATE audit SET event = replace(event, '"deny"', '"allow"') WHERE id = 4""")
    db.commit()
    assert verify_audit_table(p) == {"ok": False, "id": 4, "reason": "hash_mismatch"}
    with pytest.raises(ValueError):
        SqliteAuditSink(p, table="x; drop")
    with pytest.raises(ValueError):
        SqliteAuditSink(p, mode="nope")
    with pytest.raises(RuntimeError):
        s.write(rec(1))


def test_record_from_decision():
    r = audit_record_from_decision({"tool": "x", "identity": {"id": "pat", "tenant": "bk"},
                                    "decision": {"decision": "deny", "reason": "no_role", "tenant": None, "rule": None},
                                    "duration_ms": 0.5, "approved": False}, at="T")
    assert r == {"at": "T", "tool": "x", "decision": "deny", "reason": "no_role", "sub": "pat", "tenant": "bk", "rule": None,
                 "approved": False, "durationMs": 0.5}


CHILD = """
import sys, time
sys.path.insert(0, {src!r})
from mcp_rbac import SqliteAuditSink
s = SqliteAuditSink({db!r}, max_batch=64, flush_interval_s=60.0)
for i in range(1000):
    s.write({{"at": "t", "tool": "x%d" % i, "decision": "allow", "reason": "ok"}})
{tail}
"""


def _child(tmp_path, tail):
    db = str(tmp_path / "a.db")
    code = CHILD.format(src=str(ROOT / "python/src"), db=db, tail=textwrap.dedent(tail))
    return db, subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE)


def test_crash_safety(tmp_path):
    (tmp_path / "exit").mkdir()
    db, p = _child(tmp_path / "exit", "")  # normal interpreter exit without close(): atexit flushes
    assert p.wait(30) == 0
    v = verify_audit_table(db)
    assert v["ok"] and v["count"] == 1000
    for sig in (signal.SIGTERM, signal.SIGKILL):
        d = tmp_path / sig.name
        d.mkdir()
        db, p = _child(d, 'time.sleep(0.5); print("ready", flush=True); time.sleep(60)')
        assert p.stdout.readline().strip() == b"ready"
        p.send_signal(sig)
        p.wait(30)
        v = verify_audit_table(db)
        assert v["ok"]
        if sig == signal.SIGTERM:
            assert v["count"] == 1000
        else:
            # 15 full batches of 64 were committed by the writer thread; only the 40 still batching are lost
            assert v["count"] == 960, v


def test_cross_language_table(tmp_path):
    """A table written by the TS sink verifies in Python and vice versa (same event, canonical JSON and hash)."""
    p = str(tmp_path / "x.db")
    s = SqliteAuditSink(p, shutdown_hooks=False)
    for i in range(50):
        s.write(rec(i))
    s.close()
    script = (f"import {{ verifyAuditTable, SqliteAuditSink }} from {json.dumps(str(ROOT / 'src/audit-sink.ts'))};"
              f"const s = new SqliteAuditSink({json.dumps(p)}, {{ shutdownHooks: false }});"
              "for (let i = 50; i < 100; i++) s.write({ at: 't', tool: 't' + (i % 7), decision: 'allow', reason: 'ok', sub: 'u', approved: i % 2 === 0, durationMs: i / 7 });"
              f"s.close(); console.log(JSON.stringify(verifyAuditTable({json.dumps(p)})));")
    out = subprocess.run([str(ROOT / "node_modules/.bin/tsx"), "-e", script], capture_output=True, text=True, timeout=60, cwd=ROOT)
    assert out.returncode == 0, out.stderr
    ts = json.loads(out.stdout.strip().splitlines()[-1])
    assert ts["ok"] and ts["count"] == 100
    assert verify_audit_table(p) == ts
