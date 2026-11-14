"""mcp_rbac: authorization for Python MCP servers (roles, scopes, tenants, delegation, approvals, budgets,
redaction, tamper-evident audit) and an AuthZEN 1.0 client/PDP. Same model and wire formats as the TypeScript
``mcp-rbac`` package."""
from .audit import GENESIS, canonical_json, chain_event, hash_event, to_jsonl, verify_audit_chain
from .authzen import AuthZenClient, AuthZenEngine, PdpError, pdp_app, to_authzen, validate_evaluation
from .constraints import Constraint, c, check_constraints, narrow
from .delegation import ActorPolicy, DelegationError, DelegationOptions, actors_from_claims, may_act
from .guard import ApprovalRequest, Approver, Decision, Guard, Limit, LimitStatus, ToolRule
from .output import LABELS_META_KEY, LabelRule, OutputPolicy, RedactionRule, redact_fields
from .patterns import covers, is_valid_tool_name, matches
from .roles import Assignment, BuiltinEngine, DecisionInput, EngineDecision, Identity, Permission, Role, load_policy, narrow_identity, scope_allows
from .scopes import ScopePolicy, Toolsets, insufficient_scope_challenge, parse_toolsets, scope_satisfied
from .stores import ConsumeItem, MemoryStore, PostgresStore, RedisStore
from .tenants import OrgDirectory, OrgRole, custom_role, org_assignments

__version__ = "0.3.0"

__all__ = [
    "GENESIS", "LABELS_META_KEY", "ActorPolicy", "ApprovalRequest", "Approver", "Assignment", "AuthZenClient", "AuthZenEngine",
    "BuiltinEngine", "Constraint", "ConsumeItem", "Decision", "DecisionInput", "DelegationError", "DelegationOptions",
    "EngineDecision", "Guard", "Identity", "LabelRule", "Limit", "LimitStatus", "MemoryStore", "OrgDirectory", "OrgRole",
    "OutputPolicy", "PdpError", "Permission", "PostgresStore", "RedactionRule", "RedisStore", "Role", "ScopePolicy", "ToolRule",
    "Toolsets", "actors_from_claims", "c", "canonical_json", "chain_event", "check_constraints", "covers", "custom_role",
    "hash_event", "insufficient_scope_challenge", "is_valid_tool_name", "load_policy", "matches", "may_act", "narrow",
    "narrow_identity", "org_assignments", "parse_toolsets", "pdp_app", "redact_fields", "scope_allows", "scope_satisfied",
    "to_authzen", "to_jsonl", "validate_evaluation", "verify_audit_chain",
]
