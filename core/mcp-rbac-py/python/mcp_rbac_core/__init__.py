"""Rust decision core for mcp-rbac portable policies (PyO3). Same engine as the WASM, Go and Rust bindings."""
from ._native import Engine, __version__, check, yaml_to_json

__all__ = ["Engine", "check", "yaml_to_json", "__version__"]
