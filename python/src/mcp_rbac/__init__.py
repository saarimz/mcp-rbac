"""mcp_rbac: authorization for Python MCP servers: one policy file (roles, argument limits, approvals bound to the exact
arguments, rate limits, redaction) and a hash-chained audit trail. Same decisions and wire formats as the TypeScript
``mcp-rbac`` package. Experimental features (tenants, delegation, AuthZEN) live in ``mcp_rbac.experimental``."""
from .audit import GENESIS, canonical_json, chain_event, hash_event, to_jsonl, verify_audit_chain
from .audit_sink import SqliteAuditSink, audit_record_from_decision, verify_audit_table
from .constraints import Constraint, c, check_constraints, narrow
from .guard import ApprovalRequest, Approver, Decision, Guard, Limit, LimitStatus, ToolRule
from .output import LABELS_META_KEY, LabelRule, OutputPolicy, RedactionRule, redact_fields
from .policy_diff import diff_policies, format_diff, summarize
from .policy_io import PortableEngine, export_policy, guard_from_policy, guard_kwargs_from_policy, identity_from_dict, roles_from_policy
from .packs import load_policy_with_packs, resolve_packs, validate_pack
from .portable import CompiledPolicy, PolicyError, check_policy, compile_policy, cost_json, decide, decide_json, load_policy_json, load_policy_yaml, visible, visible_json
from .testing import assert_policy, format_policy_test_report, parse_policy_tests, test_policy
from .patterns import covers, is_valid_tool_name, matches
from .roles import Assignment, BuiltinEngine, DecisionInput, EngineDecision, Identity, Permission, Role, load_policy, narrow_identity, scope_allows
from .scopes import ScopePolicy, Toolsets, insufficient_scope_challenge, parse_toolsets, scope_satisfied
from .stores import ConsumeItem, MemoryStore, PostgresStore, RedisStore

__version__ = "0.5.0"

__all__ = ["load_policy_with_packs", "resolve_packs", "validate_pack", "cost_json", 
    "GENESIS", "LABELS_META_KEY", "ApprovalRequest", "Approver", "Assignment", "BuiltinEngine", "Constraint", "ConsumeItem", "Decision", "DecisionInput", "EngineDecision", "Guard", "Identity", "LabelRule", "Limit", "LimitStatus", "MemoryStore", "OutputPolicy", "Permission", "PostgresStore", "RedactionRule", "RedisStore", "Role", "ScopePolicy", "ToolRule",
    "SqliteAuditSink", "Toolsets", "audit_record_from_decision", "verify_audit_table", "c", "canonical_json", "chain_event", "check_constraints", "covers", "hash_event", "insufficient_scope_challenge", "is_valid_tool_name", "load_policy", "matches", "narrow",
    "narrow_identity", "parse_toolsets", "redact_fields", "scope_allows", "scope_satisfied",
    "to_jsonl", "verify_audit_chain",
    "CompiledPolicy", "PolicyError", "PortableEngine", "check_policy", "compile_policy", "decide", "decide_json", "diff_policies",
    "export_policy", "format_diff", "guard_from_policy", "guard_kwargs_from_policy", "identity_from_dict", "load_policy_json",
    "load_policy_yaml", "roles_from_policy", "summarize", "visible", "visible_json",
    "assert_policy", "format_policy_test_report", "parse_policy_tests", "test_policy",
]
