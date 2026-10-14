"""Portable source contacts, not a runtime/GPU/attention receipt."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path


def verify_sources(root=None):
    root = Path(root) if root is not None else Path(__file__).with_name("source")
    binding = json.loads((root / "attention-source-binding.json").read_text())
    result = []
    for item in binding["source_files"]:
        raw = (root / item["snapshot"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("frozen source bytes differ")
        parsed = ast.parse(raw)
        for contact in item["contacts"]:
            if not any(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == contact["name"]
                and node.lineno == contact["line"]
                and node.end_lineno == contact["end_line"]
                for node in ast.walk(parsed)
            ):
                raise ValueError("frozen source contact differs")
        result.append({"path": item["path"], "sha256": item["sha256"]})
    return {
        "classification": "CPU_SOURCE_CANDIDATE_ONLY",
        "source_contacts_verified": result,
        "materialization_hook_candidate": True,
        "attention_hook_implemented": False,
        "authenticated_artifact_transport_implemented": False,
        "GPU_qualification": None,
        "attention_consumption": None,
        "formal_registration": False,
    }


def main():
    print(json.dumps(verify_sources(), sort_keys=True))


if __name__ == "__main__":
    main()
