"""The full red-team matrix (redteam/run.py): 7 categories × 3 servers, HTTP + stdio, fresh servers per phase."""
from __future__ import annotations

import pathlib
import sys

import pytest

pytest.importorskip("mcp_rbac_core")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from redteam import run  # noqa: E402
from redteam.harness import CATEGORIES  # noqa: E402

pytestmark = pytest.mark.anyio


async def test_red_team_matrix() -> None:
    rep = await run.main()
    s = rep.summary()
    assert all(s[c]["checks"] > 0 for c in CATEGORIES), s
    assert not rep.failed(), [(c.category, c.server, c.name, c.expected, c.observed) for c in rep.failed()]
