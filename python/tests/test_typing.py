"""Typed roles: a misspelled role name in allow=[...] is a static type error (mypy --strict)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent / "typing_cases"


def _mypy(f: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "mypy", "--strict", "--no-incremental", str(HERE / f)], capture_output=True, text=True, timeout=240)


def test_valid_roles_typecheck() -> None:
    r = _mypy("good.py")
    assert r.returncode == 0, r.stdout


def test_misspelled_role_is_a_type_error() -> None:
    r = _mypy("bad.py")
    assert r.returncode == 1 and "manger" in r.stdout and "bad.py:10" in r.stdout, r.stdout
