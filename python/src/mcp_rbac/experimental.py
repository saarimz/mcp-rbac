"""mcp_rbac.experimental: tested features that are NOT part of the v0.5 stable surface (their API and policy keys may
change in a minor release). See docs/experimental/README.md.

- org directories, permission sets and custom roles (tenants)
- RFC 8693 delegation (actor ceilings)
- the AuthZEN 1.0 client, engine and PDP app
"""
from .authzen import AuthZenClient, AuthZenEngine, PdpError, pdp_app, to_authzen, validate_evaluation
from .delegation import ActorPolicy, DelegationError, DelegationOptions, actors_from_claims, may_act
from .tenants import OrgDirectory, OrgRole, custom_role, org_assignments

_TOP = {"tenants": "tenants (org directory)", "permissionSets": "permission sets", "customRoles": "custom roles",
        "delegation": "delegation (RFC 8693 actors)"}


def experimental_features(policy_text: str) -> list[str]:
    """Which experimental features a policy file uses (same labels as the TypeScript CLI's `check` note)."""
    import json

    import yaml

    try:
        doc = json.loads(policy_text) if policy_text.lstrip().startswith("{") else yaml.safe_load(policy_text)
    except Exception:  # noqa: BLE001 - an invalid file gets the loader's own error elsewhere
        return []
    if not isinstance(doc, dict):
        return []
    out = [label for k, label in _TOP.items() if k in doc]
    sem = doc.get("semantics")
    if isinstance(sem, dict):
        budgets = sem.get("budgets")
        if isinstance(budgets, list) and any(isinstance(b, dict) and "currency" in b for b in budgets):
            out.append("spend budgets (semantics.budgets[].currency)")
        tools = sem.get("tools")
        if isinstance(tools, dict) and any(isinstance(t, dict) and "spend" in t for t in tools.values()):
            out.append("spend declarations (semantics.tools.*.spend)")
    return out

__all__ = ["AuthZenClient", "AuthZenEngine", "PdpError", "pdp_app", "to_authzen", "validate_evaluation", "ActorPolicy",
           "DelegationError", "DelegationOptions", "actors_from_claims", "may_act", "OrgDirectory", "OrgRole", "custom_role",
           "org_assignments", "experimental_features"]
