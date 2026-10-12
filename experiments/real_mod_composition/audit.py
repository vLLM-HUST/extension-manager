#!/usr/bin/env python3
"""Verify pinned real-MOD manifests and report a narrow static preflight.

This is neither an independent ownership oracle nor a runtime experiment.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from vllm_hust_ext.manifest import BundleManifest, parse_manifest

HERE = Path(__file__).resolve().parent


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return cast(dict[str, Any], value)


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def load_sources() -> dict[str, BundleManifest]:
    index = _load(HERE / "sources.json")
    sources = index["sources"]
    if len({source["id"] for source in sources}) != len(sources):
        raise ValueError("duplicate source id")
    manifests: dict[str, BundleManifest] = {}
    for source in sources:
        path = HERE / source["snapshot_path"]
        if path.parent != HERE / "source_manifests" or path.is_symlink():
            raise ValueError(f"unsafe source snapshot path: {path}")
        data = path.read_bytes()
        if _git_blob_sha1(data) != source["manifest_blob"]:
            raise ValueError(f"source snapshot Git blob mismatch: {source['id']}")
        manifest = parse_manifest(json.loads(data))
        if not manifest.schema_version.startswith("0.3"):
            raise ValueError(f"non-0.3 manifest: {source['id']}")
        manifests[source["id"]] = manifest
    return manifests


def audit() -> list[dict[str, Any]]:
    manifests = load_sources()
    cases = _load(HERE / "cases.json")["cases"]
    if len({case["id"] for case in cases}) != len(cases):
        raise ValueError("duplicate case id")
    results: list[dict[str, Any]] = []
    for case in cases:
        host = case["host"]
        version = Version(host["version"])
        mismatches = []
        declared_conflicts = []
        owners: dict[tuple[str, str], tuple[str, str]] = {}
        for member in case["members"]:
            manifest = manifests[member]
            spec = manifest.host
            if (spec.provider, spec.name) != (host["provider"], host["name"]):
                mismatches.append({"member": member, "reason": "host-identity"})
            elif not SpecifierSet(spec.version_range).contains(
                version, prereleases=True
            ):
                mismatches.append({"member": member, "reason": "host-version"})
            for claim in manifest.resource_claims:
                key = (claim.scope, claim.resource)
                previous = owners.get(key)
                if previous and (
                    previous[1] == "exclusive" or claim.mode == "exclusive"
                ):
                    declared_conflicts.append(
                        {
                            "owners": [previous[0], member],
                            "scope": claim.scope,
                            "resource": claim.resource,
                        }
                    )
                owners[key] = (member, claim.mode)
        results.append(
            {
                "case_id": case["id"],
                "members": case["members"],
                "host": host,
                "host_mismatches": mismatches,
                "same_name_resource_conflicts": declared_conflicts,
                "preflight_result": (
                    "reject-declared"
                    if mismatches or declared_conflicts
                    else "candidate-only"
                ),
                "runtime_effective": "unmeasured",
                "performance_benefit": "unmeasured",
            }
        )
    return results


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2, sort_keys=True))
