"""mcp-rbac test / test_policy: fixture runner for portable policies."""
from __future__ import annotations

from pathlib import Path

import pytest

from mcp_rbac.portable import PolicyError
from mcp_rbac.testing import assert_policy, format_policy_test_report, parse_policy_tests, test_policy as run_policy_tests

ROOT = Path(__file__).resolve().parents[2]
VENUE = (ROOT / "examples/policies/venue.yaml").read_text()
VENUE_TESTS = (ROOT / "examples/policies/venue.test.yaml").read_text()
QUICKSTART = (ROOT / "docs/snippets/mcp-rbac.yaml").read_text()
QUICKSTART_TESTS = (ROOT / "docs/snippets/mcp-rbac.test.yaml").read_text()


def test_venue_fixtures_pass() -> None:
    report = run_policy_tests(VENUE, VENUE_TESTS)
    assert report["ok"], format_policy_test_report(report)
    assert report["failed"] == 0
    assert report["passed"] == 30


def test_quickstart_fixtures_pass() -> None:
    report = run_policy_tests(QUICKSTART, QUICKSTART_TESTS)
    assert report["ok"], format_policy_test_report(report)
    assert report["passed"] == 9


def test_mismatch_includes_reason_and_assert_raises() -> None:
    tests = "tests:\n  - name: staff cannot refund\n    as: {roles: [staff]}\n    call: {tool: refund, args: {amount: 20}}\n    expect: allow\n"
    report = run_policy_tests(QUICKSTART, tests)
    assert report["ok"] is False
    assert report["failed"] == 1
    assert report["results"][0]["actual"] == "deny"
    assert report["results"][0]["reason"] == "user:no_matching_permission"
    text = format_policy_test_report(report)
    assert "FAIL  staff cannot refund" in text
    assert "expected allow, got deny (reason: user:no_matching_permission)" in text
    with pytest.raises(PolicyError, match="expected allow, got deny"):
        assert_policy(QUICKSTART, tests)


def test_visible_mismatch() -> None:
    tests = "tests:\n  - as: {roles: [staff]}\n    visible: [list_events]\n"
    report = run_policy_tests(QUICKSTART, tests)
    assert report["ok"] is False
    assert report["results"][0]["message"] == "visible: unexpected checkin"


def test_needs_approval_alias() -> None:
    tests = "tests:\n  - as: {roles: [owner]}\n    call: {tool: refund, args: {amount: 250}}\n    expect: needs_approval\n"
    report = run_policy_tests(QUICKSTART, tests)
    assert report["ok"], format_policy_test_report(report)
    assert report["results"][0]["actual"] == "approval"


def test_malformed_tests_file() -> None:
    with pytest.raises(PolicyError, match=r"tests\[0\]: must be a map"):
        parse_policy_tests("tests: [1]\n")
    with pytest.raises(PolicyError, match="unknown key"):
        parse_policy_tests("version: 1\n")
    with pytest.raises(PolicyError, match="call needs expect"):
        parse_policy_tests("tests:\n  - as: {roles: [staff]}\n    call: {tool: refund}\n")


def test_cli_venue_fixtures(tmp_path: Path) -> None:
    import subprocess
    import sys

    r = subprocess.run(
        [sys.executable, "-m", "mcp_rbac", "test", str(ROOT / "examples/policies/venue.yaml"), str(ROOT / "examples/policies/venue.test.yaml")],
        check=False,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.endswith("30 passed, 0 failed\n")

    bad = tmp_path / "t.yaml"
    bad.write_text("tests:\n  - name: staff cannot refund\n    as: {roles: [staff]}\n    call: {tool: refund, args: {amount: 20}}\n    expect: allow\n")
    r = subprocess.run(
        [sys.executable, "-m", "mcp_rbac", "test", str(ROOT / "docs/snippets/mcp-rbac.yaml"), str(bad)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 1
    assert "FAIL  staff cannot refund" in r.stdout
    assert "expected allow, got deny (reason: user:no_matching_permission)" in r.stdout
