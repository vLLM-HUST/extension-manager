#!/usr/bin/env python3
"""Verify the local source inputs for the bounded H1 Host/Ascend candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

DEFAULT_CANDIDATE = (
    Path(__file__).parent
    / "deployment-candidates"
    / "h1-exact-pair-support-20261013.json"
)


def _git(repo: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode:
        raise ValueError(process.stderr.strip() or "git command failed")
    return process.stdout.strip()


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def verify_repository(name: str, record: dict[str, Any], repo: Path) -> list[str]:
    errors: list[str] = []
    commit_key = "artifact_source_commit" if name == "manager" else "commit"
    tree_key = "artifact_source_tree" if name == "manager" else "tree"
    commit = record[commit_key]
    try:
        actual_tree = _git(repo, "show", "-s", "--format=%T", commit)
    except ValueError as exc:
        return [f"{name}: cannot resolve {commit}: {exc}"]
    if actual_tree != record[tree_key]:
        errors.append(f"{name}: tree {actual_tree} != {record[tree_key]}")

    for probe in record.get("contract_probes", []):
        try:
            source = _git(repo, "show", f"{commit}:{probe['path']}")
        except ValueError as exc:
            errors.append(f"{name}: cannot read {probe['path']}: {exc}")
            continue
        if probe["contains"] not in source:
            errors.append(
                f"{name}: {probe['path']} lacks required token {probe['contains']!r}"
            )

    if name == "manager":
        current = record["current_main_commit"]
        try:
            _git(repo, "merge-base", "--is-ancestor", commit, current)
        except ValueError:
            errors.append(f"manager: {commit} is not an ancestor of {current}")
    return errors


def verify_evidence(candidate: dict[str, Any], evidence_root: Path) -> list[str]:
    errors: list[str] = []
    evidence = {
        "bounded_contract_subset": "hostb093-ascendfd70-h1-contract-subset.log",
        "full_cpu_suite": "hostb093-ascendfd70-full-cpu-ut.log",
    }
    for key, filename in evidence.items():
        path = evidence_root / filename
        if not path.is_file():
            errors.append(f"evidence: missing {path}")
            continue
        expected = candidate["validation"][key]["log_sha256"]
        actual = _sha256(path)
        if actual != expected:
            errors.append(f"evidence: {filename} digest {actual} != {expected}")
    return errors


def verify_invariants(candidate: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    failures = candidate["validation"]["full_cpu_suite"]
    if failures["status"] != "failed":
        errors.append("candidate must preserve the failed full-suite status")
    if sum(failures["failed_file_counts"].values()) != failures["failed_count"]:
        errors.append("full-suite failed-file counts do not sum to failed_count")
    qualification = candidate["qualification"]
    if qualification["eligible_for_formal_h1"] is not False:
        errors.append("unreviewed candidate must not be formal-H1 eligible")
    if qualification["formal_h1_starts"] != 0:
        errors.append("unregistered preflights must contribute zero H1 starts")
    if not qualification["blockers"]:
        errors.append("candidate must retain its qualification blockers")
    return errors


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, default=DEFAULT_CANDIDATE)
    parser.add_argument("--host-repo", type=Path, required=True)
    parser.add_argument("--ascend-repo", type=Path, required=True)
    parser.add_argument("--manager-repo", type=Path, required=True)
    parser.add_argument("--mod-repo", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    candidate = json.loads(args.candidate.read_text())
    repositories = {
        "host": args.host_repo,
        "accelerator_plugin": args.ascend_repo,
        "manager": args.manager_repo,
        "mod": args.mod_repo,
    }
    errors = verify_invariants(candidate)
    for name, repo in repositories.items():
        errors.extend(verify_repository(name, candidate["sources"][name], repo))
    if args.evidence_root is not None:
        errors.extend(verify_evidence(candidate, args.evidence_root))

    result = {
        "schema": "ecpa-h1-exact-pair-check/v1",
        "candidate": str(args.candidate),
        "local_inputs_match": not errors,
        "formal_h1_eligible": False,
        "formal_h1_starts": 0,
        "errors": errors,
        "qualification_blockers": candidate["qualification"]["blockers"],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
