"""P8c: malformed / hostile input and a session soak against the three real servers over Streamable HTTP
(redteam/malformed.py; the full-size run is `python -m redteam.malformed`)."""
from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
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
