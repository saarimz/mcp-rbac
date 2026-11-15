"""P8c: malformed / hostile input and a session soak against the three real servers over Streamable HTTP
(redteam/malformed.py; the full-size run is `python -m redteam.malformed`)."""
from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from redteam.malformed import check_server  # noqa: E402

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("server", ["venue", "marketing", "devops"])
async def test_hostile_input_never_crashes_or_succeeds_and_sessions_do_not_leak(server: str) -> None:
    r = await check_server(server, warm=100, n=500)
    assert r["failures"] == [], r
    assert r["alive_after"]
    assert r["soak"]["sequential_ok"] == 500 and r["soak"]["concurrent_ok"] == 64, r["soak"]
    assert any(c["case"] == "2 MiB body" and c["status"] == 413 for c in r["transport"])
    # parser differential probe: the forbidden tool named last (last key wins everywhere) is denied
    dup = next(c for c in r["protocol"] if c["case"].startswith("duplicate name"))
    assert dup["isError"]
