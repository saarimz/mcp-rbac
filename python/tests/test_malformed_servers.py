"""P8c: malformed / hostile input and a session soak against the three real servers over Streamable HTTP
(redteam/malformed.py; the full-size run is `python -m redteam.malformed`)."""
from __future__ import annotations

import base64
import json
import pathlib
import sys
from typing import Any

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import redteam.malformed as malformed  # noqa: E402
from redteam import servers  # noqa: E402
from redteam.malformed import MAX_LATE_RSS_GROWTH, MAX_SLOPE_B_PER_SESSION, TEST_CHECKPOINTS, _fit_slope, check_server  # noqa: E402

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("server", ["venue", "marketing", "devops"])
async def test_hostile_input_never_crashes_or_succeeds_and_sessions_do_not_leak(server: str) -> None:
    # session soak: post-GC heap read by the server itself every 250 sessions up to 2000 after a 1000-session warm-up;
    # gate on the late slope (a fit over 1000..2000), not on one RSS reading (`python -m redteam.malformed`: 2k..16k)
    r = await check_server(server, warm=1000, checkpoints=TEST_CHECKPOINTS)
    sk = r["soak"]
    assert r["failures"] == [], r
    assert r["alive_after"]
    assert sk["sequential_ok"] == 2000 and sk["concurrent_ok"] == 64, sk
    assert sk["post_gc"], sk
    assert sk["late_slope_b_per_session"] <= MAX_SLOPE_B_PER_SESSION, sk
    assert sk["late_rss_growth_bytes"] is None or sk["late_rss_growth_bytes"] < MAX_LATE_RSS_GROWTH, sk
    assert any(c["case"] == "2 MiB body" and c["status"] == 413 for c in r["transport"])
    # parser differential probe: the forbidden tool named last (last key wins everywhere) is denied
    dup = next(c for c in r["protocol"] if c["case"].startswith("duplicate name"))
    assert dup["isError"]


def test_late_slope_is_a_fit_over_the_second_half() -> None:
    pts = lambda f: [{"sessions": x, "heap": f(x)} for x in (0, *TEST_CHECKPOINTS)]  # noqa: E731
    assert _fit_slope(pts(lambda x: 10_000_000 + 2048 * x)) == 2048.0  # a real leak is a constant slope: caught
    assert _fit_slope(pts(lambda x: 10_000_000 if x >= 500 else 4 * x * 1024)) == 0.0  # early growth, then plateau
    # +-1 MiB tracemalloc jitter around a plateau: a two-point slope on the last 250 sessions would read ~8 KiB/session
    jitter = lambda x: 10_000_000 + (1 << 20) * (1 if (x // 250) % 2 else -1)  # noqa: E731
    assert abs(_fit_slope(pts(jitter))) <= 1024
    assert _fit_slope(pts(lambda x: 10_000_000 + 1100 * x + (1 << 20) * (1 if (x // 250) % 2 else -1))) > 1024  # noisy leak


@pytest.mark.parametrize("server", ["venue", "marketing", "devops"])
async def test_liveness_check_does_not_reuse_the_pre_soak_token(server: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # regression: the full soak (2k+16k sessions) outlives the 15-minute demo token minted before it, and the
    # liveness session reused that token -> 401 -> MCPError in initialize (soak.rc=1, 2026-11-16 23:55 ET). Stand in
    # for expiry by revoking the pre-soak token's jti during a stubbed soak: the liveness check must still pass.
    seen: dict[str, Any] = {"tokens": []}
    real_start, real_token = servers.start_http, servers.token

    def start_http(srv: str, db: str) -> Any:
        seen["db"] = db
        return real_start(srv, db)

    def token(srv: str, **claims: Any) -> str:
        t = real_token(srv, **claims)
        seen["tokens"].append(t)
        return t

    async def fake_soak(url: str, srv: str, *_: Any, **__: Any) -> dict[str, Any]:
        first = seen["tokens"][0]
        jti = json.loads(base64.urlsafe_b64decode(first.split(".")[1] + "==="))["jti"]
        servers.admin(srv, seen["db"], "revoke", jti)
        return {"ok": True}

    monkeypatch.setattr(servers, "start_http", start_http)
    monkeypatch.setattr(servers, "token", token)
    monkeypatch.setattr(malformed, "soak", fake_soak)
    r = await check_server(server, warm=0, checkpoints=(1,))
    assert r["alive_after"] and r["failures"] == [], r
    assert len(seen["tokens"]) >= 2  # the liveness session minted its own token
