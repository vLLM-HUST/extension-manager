"""Validate that every release failure cell names an executable pytest case."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs/failure-permission-matrix.json"
REQUIRED_CATEGORIES = {
    "host_failure",
    "permission_denial",
    "partial_evidence",
    "observer_failure",
    "process_cleanup",
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_matrix(root: Path = ROOT) -> list[str]:
    payload = _load(root / "docs/failure-permission-matrix.json")
    errors: list[str] = []
    cases = payload.get("cases", [])
    ids = [case.get("id") for case in cases]
    if len(ids) != len(set(ids)):
        errors.append("case ids must be unique")
    categories = {case.get("category") for case in cases}
    missing = REQUIRED_CATEGORIES - categories
    if missing:
        errors.append(f"missing required categories: {sorted(missing)}")
    if not any(case.get("resource_leak_assertion") for case in cases):
        errors.append("at least one case must assert Manager-owned resource cleanup")

    for case in cases:
        node = case.get("test_node", "")
        if not isinstance(node, str) or node.count("::") != 1:
            errors.append(f"{case.get('id')}: invalid pytest node")
            continue
        relative, function_name = node.split("::")
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or not (root / path).is_file():
            errors.append(f"{case.get('id')}: unsafe or missing test path")
            continue
        tree = ast.parse((root / path).read_text(encoding="utf-8"))
        functions = {
            item.name
            for item in tree.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if function_name not in functions:
            errors.append(f"{case.get('id')}: test function does not exist")
        if not isinstance(case.get("expected"), str) or not case["expected"].strip():
            errors.append(f"{case.get('id')}: expected result is empty")
    return errors


def main() -> int:
    errors = validate_matrix()
    if errors:
        for error in errors:
            print(f"failure-permission-matrix: {error}")
        return 1
    payload = _load(MATRIX)
    print(f"failure-permission-matrix: {len(payload['cases'])} executable cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
