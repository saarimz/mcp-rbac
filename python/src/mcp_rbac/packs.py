"""Policy packs (spec/tool-semantics.md "Policy packs"): resolve ``semantics.packs`` into ``semantics.tools``.

The engine does no IO and rejects a policy that still lists ``packs``; hosts call ``load_policy_with_packs`` (or
``resolve_packs``) first. Merge order: inline ``semantics.tools`` first (they win and match first), then each pack's
tools in list order (the first pack that classifies a tool wins). Same rules as ``src/packs.ts``.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
from typing import Any, Optional

from .portable import is_json_document, load_yaml, parse_json

PACK_KEYS = ("$schema", "pack", "version", "title", "description", "server", "sources", "tools", "license")
# packs_data/ ships in the wheel (tools/sync-packs.sh copies the repo's packs/ there); the repo copy is the fallback.
_HERE = pathlib.Path(__file__).resolve().parent
BUILTIN = _HERE / "packs_data" if (_HERE / "packs_data").is_dir() else _HERE.parents[2] / "packs"
_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_PREFIX = re.compile(r"[A-Za-z0-9_.-]{0,32}")


def validate_pack(doc: Any, where: str = "pack") -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise ValueError(f"{where}: must be a JSON object")
    for k in doc:
        if k not in PACK_KEYS:
            raise ValueError(f"{where}: unknown key {json.dumps(k)}")
    if not isinstance(doc.get("pack"), str) or not _NAME.fullmatch(doc["pack"]):
        raise ValueError(f'{where}: "pack" must be a lowercase name')
    if not isinstance(doc.get("tools"), dict) or not all(isinstance(t, dict) for t in doc["tools"].values()):
        raise ValueError(f'{where}: "tools" must be an object of objects')
    return doc


def _ref(v: Any, i: int) -> dict[str, Any]:
    r = _ref0(v, i)
    if "name" in r and not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", r["name"]):
        raise ValueError(f"semantics.packs[{i}]: invalid pack name {json.dumps(r['name'])}")
    return r


def _ref0(v: Any, i: int) -> dict[str, Any]:
    if isinstance(v, str):
        return {"path": v} if re.search(r"[/\\]|\.json$", v) else {"name": v}
    if isinstance(v, dict):
        for k in v:
            if k not in ("name", "path", "prefix"):
                raise ValueError(f"semantics.packs[{i}]: unknown key {json.dumps(k)}")
        if isinstance(v.get("name"), str) == isinstance(v.get("path"), str):
            raise ValueError(f"semantics.packs[{i}]: needs exactly one of name | path")
        if "prefix" in v and (not isinstance(v["prefix"], str) or not _PREFIX.fullmatch(v["prefix"])):
            raise ValueError(f"semantics.packs[{i}].prefix: invalid")
        return v
    raise ValueError(f"semantics.packs[{i}]: must be a pack name, a path, or {{name|path, prefix}}")


def _find(ref: dict[str, Any], base_dir: Optional[pathlib.Path], search: list[str], packs: dict[str, Any]) -> dict[str, Any]:
    name = ref.get("name")
    if name and name in packs:
        return validate_pack(packs[name], f"pack {name}")
    if "path" in ref:
        f = pathlib.Path(ref["path"])
        if not f.is_absolute():
            f = (base_dir or pathlib.Path.cwd()) / f
    else:
        assert name is not None
        dirs = ([base_dir / "packs"] if base_dir else []) + [pathlib.Path(p) for p in search] \
            + [pathlib.Path(p) for p in os.environ.get("MCP_RBAC_PACKS_PATH", "").split(":") if p] + [BUILTIN]
        found = next((d / name / "pack.json" for d in dirs if (d / name / "pack.json").exists()), None)
        if found is None:
            raise ValueError(f"pack {json.dumps(name)} not found (looked in {', '.join(map(str, dirs))})")
        f = found
    return validate_pack(parse_json(f.read_text(encoding="utf-8")), str(f))


def resolve_packs_doc(doc: Any, base_dir: Optional[pathlib.Path] = None, search_paths: Optional[list[str]] = None, packs: Optional[dict[str, Any]] = None) -> Any:
    if not isinstance(doc, dict) or not isinstance(doc.get("semantics"), dict) or "packs" not in doc["semantics"]:
        return doc
    sem = dict(doc["semantics"])
    if not isinstance(sem["packs"], list):
        raise ValueError("semantics.packs: must be a list")
    tools: dict[str, Any] = dict(sem["tools"]) if isinstance(sem.get("tools"), dict) else {}
    for i, p in enumerate(sem["packs"]):
        ref = _ref(p, i)
        pack = _find(ref, base_dir, search_paths or [], packs or {})
        for n, t in pack["tools"].items():
            name = ref.get("prefix", "") + n
            if name not in tools:
                tools[name] = t
    del sem["packs"]
    sem["tools"] = tools
    return {**doc, "semantics": sem}


def resolve_packs(policy_text: str, base_dir: Optional[pathlib.Path] = None, search_paths: Optional[list[str]] = None, packs: Optional[dict[str, Any]] = None) -> str:
    doc = parse_json(policy_text.removeprefix("\ufeff")) if is_json_document(policy_text) else load_yaml(policy_text)
    out = resolve_packs_doc(doc, base_dir, search_paths, packs)
    return policy_text if out is doc else json.dumps(_ints(out))


def _ints(v: Any) -> Any:
    """The JSON model reads every number as a float; write integral ones as integers (1, not 1.0) like TS and Go."""
    if isinstance(v, float) and v.is_integer() and abs(v) < 2**53:
        return int(v)
    if isinstance(v, dict):
        return {k: _ints(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_ints(x) for x in v]
    return v


def load_policy_with_packs(path: str | os.PathLike[str], search_paths: Optional[list[str]] = None) -> str:
    p = pathlib.Path(path).resolve()
    return resolve_packs(p.read_text(encoding="utf-8"), p.parent, search_paths)
