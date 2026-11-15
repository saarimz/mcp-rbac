"""Portable evaluator unit tests (byte-level parity is covered by the shared conformance corpus)."""
from __future__ import annotations

import pathlib

import pytest

from mcp_rbac.audit import _num
from mcp_rbac.portable import (
    PolicyError,
    canonical,
    check_policy,
    decide_json,
    js_number,
    load_policy_json,
    load_policy_yaml,
    load_yaml,
    visible_json,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
VENUE = (ROOT / "examples/policies/venue.yaml").read_text()


@pytest.mark.parametrize("x,s", [(1e-5, "0.00001"), (1e-7, "1e-7"), (1e21, "1e+21"), (1e20, "100000000000000000000"), (-0.0, "0"), (0.1, "0.1"), (5e-324, "5e-324"), (123.456, "123.456")])
def test_js_number(x: float, s: str) -> None:
    assert js_number(x) == s


def test_audit_num_matches_js() -> None:  # regression: repr() gave "1e-05"/"1e-5" where JS prints 0.00001
    assert _num(1e-5) == "0.00001"
    assert _num(10**21) == "1e+21"
    assert _num(10**400) == "null"
    assert _num(True) == "true"


def test_canonical_sorting_and_numbers() -> None:
    assert canonical({"b": 1, "a": [1.5, None, True], "é": "x"}) == '{"a":[1.5,null,true],"b":1,"é":"x"}'


@pytest.mark.parametrize("src", ["a: &x 1\nb: *x\n", "a: !!str 1\n", "<<: {a: 1}\n", '"<<": 1\n', "a: 1\na: 2\n", "? [1]\n: 2\n", "a: 1\n---\nb: 2\n", "a: .inf\n", "1: x\n"[0:0] + "{" * 65 + "}" * 65])
def test_strict_yaml_rejects(src: str) -> None:
    with pytest.raises(PolicyError):
        load_yaml(src)


def test_yaml_core_schema() -> None:
    assert load_yaml("a: yes\nb: 0x10\nc: 0o7\nd: ~\ne: '1'\nf: 1e3\ng: True\n") == {"a": "yes", "b": 16.0, "c": 7.0, "d": None, "e": "1", "f": 1000.0, "g": True}


def test_digit_keys_rejected() -> None:
    assert '"policy_invalid"' in check_policy("version: 1\nroles:\n  r: {tools: [a]}\ntools:\n  a: {limits: {'1': {max: 1}}}\n")


def test_venue_checks_and_decides() -> None:
    assert check_policy(VENUE) == '{"ok":true,"warnings":[]}'
    p = load_policy_yaml(VENUE)
    ok = decide_json(p, '{"tool":"refund_ticket","args":{"amount":100,"ticket_id":"t1"},"identity":{"id":"u","roles":["project_manager"],"tenant":"v1"}}')
    assert '"decision":"allow"' in ok or '"decision":"deny"' in ok
    assert decide_json(p, '{"tool":"x","identity":') == decide_json(p, "[" * 100)
    assert '"invalid_input"' in decide_json(p, '{"tool":"\\ud800"}')
    assert '"unauthenticated"' in decide_json(p, '{"tool":"check_in_guest","identity":{"id":"u","admin":true}}')
    assert visible_json(p, '{"identity":{"id":"u","roles":["door_staff"]},"tools":["check_in_guest","refund_ticket"]}').startswith('{"visible":[')


def test_json_policy_numbers_are_doubles() -> None:
    with pytest.raises(PolicyError):  # 1e400 overflows to inf: a non-finite limit is invalid (same in Rust/TS)
        load_policy_json('{"version":1,"roles":{"r":{"tools":[{"name":"t","limits":{"n":{"max":1e400}}}]}}}')
    p = load_policy_json('{"version":1,"roles":{"r":{"tools":[{"name":"t","limits":{"n":{"max":10}}}]}}}')
    assert 'not_a_finite_number:n"' in decide_json(p, '{"tool":"t","args":{"n":1e400},"identity":{"id":"u","roles":["r"]}}')
    assert '"decision":"allow"' in decide_json(p, '{"tool":"t","args":{"n":10.0},"identity":{"id":"u","roles":["r"]}}')
