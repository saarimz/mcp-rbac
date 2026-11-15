"""v0.5 scope cut: experimental features live in mcp_rbac.experimental only."""
import mcp_rbac
from mcp_rbac import experimental

MOVED = ["AuthZenClient", "AuthZenEngine", "PdpError", "pdp_app", "to_authzen", "validate_evaluation", "ActorPolicy",
         "DelegationError", "DelegationOptions", "actors_from_claims", "may_act", "OrgDirectory", "OrgRole", "custom_role",
         "org_assignments"]


def test_moved_names() -> None:
    for n in MOVED:
        assert n not in mcp_rbac.__all__, n
        assert hasattr(experimental, n), n


def test_experimental_features() -> None:
    assert experimental.experimental_features("version: 1\nroles: {a: {tools: [x]}}\n") == []
    assert experimental.experimental_features("version: 1\nroles: {}\ndelegation: {unknownActors: deny}\ntenants: {accounts: {a: {}}}\n") == [
        "tenants (org directory)", "delegation (RFC 8693 actors)"]
    assert experimental.experimental_features(
        '{"version":1,"roles":{},"semantics":{"budgets":[{"class":"spend","max":5,"per":"day","currency":"USD"}]}}') == [
        "spend budgets (semantics.budgets[].currency)"]
