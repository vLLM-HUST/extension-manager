"""Validate the superseded local Git-object and bundle receipt.

The receipt deliberately does not assert remote reachability.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

from harness import canonical, digest_file

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE / "deployment-candidates/h1-formal-registration-commands-20261013.json"
SCHEMA = "ecpa-h1-source-reachability-receipt/v1"
CLASSIFICATION = "local-object-and-archive-verification-only"
SUPERSEDED_CANDIDATE_SHA256 = (
    "sha256:c94e4531e4a84d07f02a95cadc24a763d7a2147b8049127137efbb76d985c955"
)
SUPERSEDED_IDENTITIES = {
    "runtime": {
        "repository": "vLLM-HUST/vllm-hust",
        "commit": "b093ae0096a4ee801064f7a3673d42383e89f5c7",
        "tree": "dd66f7b4b1844a19211894706786832aef63d5ff",
    },
    "mod": {
        "repository": "vLLM-HUST/vllm-hust-kv-materialization-arrival-control",
        "commit": "9728ccd9df68c654aaf541bb7565c0bd3f85b983",
        "tree": "ea6911c6e0b8a0d7ff66d3078397dd4c615a3364",
    },
    "accelerator_plugin": {
        "repository": "vLLM-HUST/vllm-ascend-hust",
        "commit": "fd70a5c818363ee4357604e637e36fb52860ccca",
        "tree": "40760a184f20adbc9b7993f72940028ec229626c",
    },
}


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _bundle_heads(bundle: Path) -> dict[str, str]:
    completed = subprocess.run(
        ["git", "bundle", "list-heads", str(bundle)],
        check=True,
        capture_output=True,
        text=True,
    )
    heads: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        commit, ref = line.split(" ", 1)
        heads[ref] = commit
    return heads


def _bundle_prerequisites(bundle: Path) -> list[str]:
    prerequisites: list[str] = []
    with bundle.open("rb") as stream:
        if not stream.readline().startswith(b"# v"):
            raise ValueError("source archive lacks a Git bundle header")
        for raw in stream:
            if raw in (b"\n", b"\r\n"):
                break
            if raw.startswith(b"-"):
                prerequisites.append(raw[1:41].decode("ascii"))
    return sorted(prerequisites)


def inspect_source(
    name: str,
    identity: dict[str, str],
    repository: Path,
    bundle: Path,
) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    bundle = bundle.resolve(strict=True)
    commit = identity["commit"]
    tree = identity["tree"]
    object_type = _git(repository, "cat-file", "-t", commit)
    actual_tree = _git(repository, "rev-parse", f"{commit}^{{tree}}")
    origin = _git(repository, "remote", "get-url", "origin")
    clean = not _git(repository, "status", "--porcelain")
    heads = _bundle_heads(bundle)
    prerequisites = _bundle_prerequisites(bundle)
    verify = subprocess.run(
        ["git", "-C", str(repository), "bundle", "verify", str(bundle)],
        capture_output=True,
        text=True,
    )
    exact_heads = sorted(ref for ref, value in heads.items() if value == commit)
    local_exact = object_type == "commit" and actual_tree == tree
    archive_exact = verify.returncode == 0 and bool(exact_heads)
    try:
        archive_path = str(bundle.relative_to(HERE))
    except ValueError:
        archive_path = str(bundle)
    return {
        "name": name,
        "declared_identity": identity,
        "local_repository": {
            "path": str(repository),
            "origin_url": origin,
            "clean": clean,
            "object_type": object_type,
            "commit_tree": actual_tree,
            "exact_identity_verified": local_exact,
        },
        "archive": {
            "path": archive_path,
            "sha256": digest_file(bundle),
            "bytes": bundle.stat().st_size,
            "heads": heads,
            "prerequisite_commits": prerequisites,
            "self_contained": not prerequisites,
            "exact_commit_refs": exact_heads,
            "verifies_against_local_repository": verify.returncode == 0,
            "exact_identity_exported": archive_exact,
        },
        "remote_reachability": {
            "checked": False,
            "reachable": None,
            "reason": "offline receipt deliberately performs no remote query",
        },
        "formal_registration_eligible": False,
    }


def validate_receipt(value: dict[str, Any], *, live: bool = False) -> None:
    if value.get("schema") != SCHEMA or value.get("classification") != CLASSIFICATION:
        raise ValueError("source receipt identity drifted")
    sources = value.get("sources")
    if not isinstance(sources, list) or [row.get("name") for row in sources] != [
        "runtime",
        "mod",
        "accelerator_plugin",
    ]:
        raise ValueError("source receipt does not cover the exact H1 source tuple")
    candidate = json.loads(CANDIDATE.read_text())
    if value.get("candidate_status") != "superseded-by-reachable-source-candidate":
        raise ValueError("source receipt supersession status drifted")
    if value.get("candidate_sha256") != SUPERSEDED_CANDIDATE_SHA256:
        raise ValueError("superseded candidate digest drifted")
    declared_sources = candidate["declared_identity"]["software"]
    for row in sources:
        identity = row.get("declared_identity", {})
        if identity != SUPERSEDED_IDENTITIES[row["name"]]:
            raise ValueError("source receipt identity differs from archived candidate")
        current_identity = declared_sources[row["name"]]
        if identity == current_identity or not current_identity.get(
            "repository_reachable"
        ):
            raise ValueError(
                "superseded local identity was not replaced by a reachable candidate"
            )
        local = row.get("local_repository", {})
        archive = row.get("archive", {})
        remote = row.get("remote_reachability", {})
        if local.get("object_type") != "commit" or local.get(
            "commit_tree"
        ) != identity.get("tree"):
            raise ValueError("source local object does not match the declared identity")
        if not local.get("exact_identity_verified"):
            raise ValueError("source local identity was not verified")
        if not archive.get("verifies_against_local_repository") or not archive.get(
            "exact_identity_exported"
        ):
            raise ValueError("source archive does not export the exact commit")
        if identity.get("commit") not in archive.get("heads", {}).values():
            raise ValueError("source archive head does not contain the declared commit")
        prerequisites = archive.get("prerequisite_commits")
        if not isinstance(prerequisites, list) or not prerequisites:
            raise ValueError(
                "incremental source archive prerequisites are not recorded"
            )
        if archive.get("self_contained") is not False:
            raise ValueError(
                "incremental source archive was mislabeled as self-contained"
            )
        if remote != {
            "checked": False,
            "reachable": None,
            "reason": "offline receipt deliberately performs no remote query",
        }:
            raise ValueError("local receipt must not imply remote reachability")
        if row.get("formal_registration_eligible") is not False:
            raise ValueError("local archive cannot authorize formal registration")
        expected_origin = f"https://github.com/{identity['repository']}.git"
        if local.get("origin_url") != expected_origin:
            raise ValueError("source local origin differs from the declared repository")
        if live:
            archive_path = Path(archive["path"])
            if not archive_path.is_absolute():
                archive_path = HERE / archive_path
            refreshed = inspect_source(
                row["name"],
                identity,
                Path(local["path"]),
                archive_path,
            )
            if refreshed != row:
                raise ValueError(
                    "source receipt differs from live objects or archive bytes"
                )
    summary = value.get("summary", {})
    if summary != {
        "all_local_objects_exact": True,
        "all_archives_exact": True,
        "remote_repositories_verified": False,
        "repository_reachability_blocker_cleared": False,
        "formal_registration_eligible": False,
    }:
        raise ValueError("source receipt qualification boundary drifted")


def build_receipt(specifications: list[tuple[str, Path, Path]]) -> dict[str, Any]:
    sources = [
        inspect_source(name, SUPERSEDED_IDENTITIES[name], repository, bundle)
        for name, repository, bundle in specifications
    ]
    receipt = {
        "schema": SCHEMA,
        "classification": CLASSIFICATION,
        "candidate_sha256": SUPERSEDED_CANDIDATE_SHA256,
        "candidate_status": "superseded-by-reachable-source-candidate",
        "sources": sources,
        "summary": {
            "all_local_objects_exact": all(
                row["local_repository"]["exact_identity_verified"] for row in sources
            ),
            "all_archives_exact": all(
                row["archive"]["exact_identity_exported"] for row in sources
            ),
            "remote_repositories_verified": False,
            "repository_reachability_blocker_cleared": False,
            "formal_registration_eligible": False,
        },
        "non_claims": [
            (
                "Local Git objects and bundle heads do not prove a commit is "
                "reachable from a remote repository ref."
            ),
            "This receipt covers the superseded local source candidate only.",
            "This receipt is not producer admission or independent review.",
            "The incremental bundles require their recorded prerequisite commits.",
        ],
    }
    validate_receipt(receipt, live=True)
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-repository", type=Path, required=True)
    parser.add_argument("--runtime-bundle", type=Path, required=True)
    parser.add_argument("--mod-repository", type=Path, required=True)
    parser.add_argument("--mod-bundle", type=Path, required=True)
    parser.add_argument("--accelerator-repository", type=Path, required=True)
    parser.add_argument("--accelerator-bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = build_receipt(
        [
            ("runtime", args.runtime_repository, args.runtime_bundle),
            ("mod", args.mod_repository, args.mod_bundle),
            (
                "accelerator_plugin",
                args.accelerator_repository,
                args.accelerator_bundle,
            ),
        ]
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical(receipt) + b"\n")


if __name__ == "__main__":
    main()
