"""Read actual installed payloads before binding a fresh semantic execution Plan."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Sequence
from importlib import metadata
from pathlib import Path
from typing import Any

from .contract_compiler import compile_contracts, parse_contract
from .discovery import InstalledBundle
from .ecpa_model import PluginIdentity, canonical_bytes
from .semantic_obligations import compile_native_semantic_plan

SCHEMA = "ecpa-native-semantic-launch-spec/v1"
CONTEXT_ENV = {
    "ECPA_SEMANTIC_LAUNCH_SPEC",
    "ECPA_SEMANTIC_EXECUTION_PLAN_ID",
    "ECPA_SEMANTIC_CONTROLLER_INSTANCE",
    "ECPA_SEMANTIC_CANDIDATE_GENERATION",
    "ECPA_SEMANTIC_MEMBERSHIP_EPOCH",
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate semantic artifact JSON field")
        value[key] = item
    return value


def _private(path: str | Path) -> bytes:
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path or path.is_symlink():
        raise ValueError("semantic artifact requires canonical absolute path")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise ValueError("semantic artifact must be private and owned")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def artifact_reference(path: str | Path) -> dict[str, str]:
    """Freeze a private artifact reference from its actual bytes."""
    return {"path": str(Path(path)), "sha256": _sha(_private(path))}


def _reference(value: Any) -> bytes:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise ValueError("semantic artifact reference fields differ")
    raw = _private(value["path"])
    if _sha(raw) != value["sha256"]:
        raise ValueError("semantic artifact bytes differ")
    return raw


def installed_bundle_snapshot(bundle: InstalledBundle) -> dict[str, Any]:
    """Hash real distribution payloads; never trust RECORD's supplied hashes.

    Bytecode, generated console wrappers and mutable installation receipts are
    outside the payload inventory. Stable distribution metadata is included.
    Editable registrations are rejected: this profile requires installed wheels.
    """
    dist = metadata.distribution(bundle.distribution_name)
    name = dist.metadata["Name"]
    if name != bundle.distribution_name or dist.version != bundle.distribution_version:
        raise ValueError("actual distribution identity differs from enabled bundle")
    direct = dist.read_text("direct_url.json")
    if direct and json.loads(direct).get("dir_info", {}).get("editable"):
        raise ValueError("semantic launch requires a noneditable installed payload")
    rows: list[dict[str, Any]] = []
    manifest = bundle.manifest_path.resolve(strict=True)
    manifest_seen = False
    for entry in dist.files or ():
        relative = str(entry)
        parts = Path(relative).parts
        if (
            ".." in parts
            or "__pycache__" in parts
            or relative.endswith((".pyc", ".pyo"))
        ):
            continue
        if any(part.endswith(".dist-info") for part in parts) and Path(
            relative
        ).name in {"RECORD", "INSTALLER", "direct_url.json", "REQUESTED"}:
            continue
        path = Path(str(dist.locate_file(entry)))
        if path.is_symlink() or not path.is_file():
            raise ValueError("installed payload is absent or a symbolic link")
        raw = path.read_bytes()
        manifest_seen |= path.resolve() == manifest
        rows.append({"path": relative, "sha256": _sha(raw), "size": len(raw)})
    rows.sort(key=lambda row: row["path"])
    if not rows or len({row["path"] for row in rows}) != len(rows) or not manifest_seen:
        raise ValueError("installed payload inventory does not cover bundle manifest")
    raw_manifest = manifest.read_bytes()
    return {
        "bundle_id": bundle.bundle_id,
        "distribution_name": name,
        "distribution_version": dist.version,
        "manifest_sha256": _sha(raw_manifest),
        "files": rows,
    }


def plugin_identity_from_snapshot(snapshot: dict[str, Any]) -> PluginIdentity:
    namespace, separator, name = snapshot["bundle_id"].rpartition(".")
    if not separator:
        raise ValueError("semantic bundle requires a namespaced identity")
    return PluginIdentity(
        namespace,
        name,
        snapshot["distribution_version"],
        _sha(canonical_bytes(snapshot)),
    )


def installed_plugin_identities(
    bundles: Sequence[InstalledBundle],
) -> tuple[tuple[PluginIdentity, ...], list[dict[str, Any]]]:
    """Owner helper: actual PluginIdentity tuple and snapshot list, sorted by bundle."""
    ordered = sorted(bundles, key=lambda bundle: bundle.bundle_id)
    if not ordered or len({bundle.bundle_id for bundle in ordered}) != len(ordered):
        raise ValueError("enabled semantic bundles are empty or duplicated")
    snapshots = [installed_bundle_snapshot(bundle) for bundle in ordered]
    return tuple(
        plugin_identity_from_snapshot(snapshot) for snapshot in snapshots
    ), snapshots


def validate_semantic_launch_spec(
    path: str | Path,
    bundles: Sequence[InstalledBundle],
) -> dict[str, Any]:
    """Recompute contracts, Plan, binding and installed payload before Host launch."""
    spec = json.loads(_private(path), object_pairs_hook=_unique)
    fields = {
        "schema",
        "base_plan",
        "plan",
        "binding",
        "contracts",
        "plugin_map",
        "enabled_bundles",
        "execution_plan_id",
        "native_plan_id",
        "controller_instance",
        "candidate_generation",
        "membership_epoch",
    }
    if not isinstance(spec, dict) or set(spec) != fields or spec["schema"] != SCHEMA:
        raise ValueError("semantic launch spec schema/fields differ")
    plugins, snapshots = installed_plugin_identities(bundles)
    if spec["enabled_bundles"] != snapshots:
        raise ValueError("enabled bundle payload snapshot differs")
    from .plan_artifact import parse_plan_artifact

    base = parse_plan_artifact(_reference(spec["base_plan"]))
    plan = parse_plan_artifact(_reference(spec["plan"]))
    binding = json.loads(_reference(spec["binding"]), object_pairs_hook=_unique)
    if set(base.plugins) != set(plugins) or len(base.plugins) != len(plugins):
        raise ValueError("execution Plan plugins differ from actual enabled bundles")
    if not isinstance(spec["contracts"], list) or not spec["contracts"]:
        raise ValueError("semantic contracts are missing")
    contracts = tuple(
        parse_contract(json.loads(_reference(ref), object_pairs_hook=_unique))
        for ref in spec["contracts"]
    )
    mapping = json.loads(_reference(spec["plugin_map"]), object_pairs_hook=_unique)
    actual_mapping = {
        snapshot["bundle_id"]: plugin.id
        for snapshot, plugin in zip(snapshots, plugins, strict=True)
    }
    if (
        not isinstance(mapping, dict)
        or not mapping
        or any(actual_mapping.get(key) != value for key, value in mapping.items())
    ):
        raise ValueError("semantic provider identity differs from enabled bundle")
    compiled = compile_contracts(
        contracts, host_runtime=base.host.runtime, host_version=base.host.version
    )
    expected, expected_binding = compile_native_semantic_plan(
        base, compiled, extension_plugin_ids=mapping, required_worker_ordinals=(0, 1)
    )
    if plan != expected or binding != expected_binding:
        raise ValueError("semantic Plan or compiled binding differs")
    if (
        spec["execution_plan_id"] != plan.plan_id
        or spec["native_plan_id"] != plan.plan_id.rsplit(":", 1)[-1]
    ):
        raise ValueError("semantic execution/native Plan identity differs")
    native = spec["native_plan_id"]
    if len(native) != 64 or any(char not in "0123456789abcdef" for char in native):
        raise ValueError("native Plan identity is not a SHA256 suffix")
    controller = spec["controller_instance"]
    if (
        not isinstance(controller, str)
        or not controller.startswith("controller:")
        or controller == "controller:"
        or any(c.isspace() for c in controller)
    ):
        raise ValueError("semantic controller instance is invalid")
    for field in ("candidate_generation", "membership_epoch"):
        if type(spec[field]) is not int or spec[field] < (
            1 if field == "candidate_generation" else 0
        ):
            raise ValueError("semantic generation/membership epoch is invalid")
    return spec


def semantic_context_environment(
    spec_path: str | Path,
    spec: dict[str, Any],
) -> dict[str, str]:
    """Extra context is separate from the unchanged five-field v1 handoff."""
    conflicts = CONTEXT_ENV.intersection(os.environ)
    if conflicts:
        raise ValueError(
            "Manager owns semantic context environment: " + ", ".join(sorted(conflicts))
        )
    return {
        "ECPA_SEMANTIC_LAUNCH_SPEC": str(spec_path),
        "ECPA_SEMANTIC_EXECUTION_PLAN_ID": spec["execution_plan_id"],
        "ECPA_SEMANTIC_CONTROLLER_INSTANCE": spec["controller_instance"],
        "ECPA_SEMANTIC_CANDIDATE_GENERATION": str(spec["candidate_generation"]),
        "ECPA_SEMANTIC_MEMBERSHIP_EPOCH": str(spec["membership_epoch"]),
    }


def make_semantic_launch_spec(
    bundles: Sequence[InstalledBundle],
    *,
    base_plan_path: str | Path,
    plan_path: str | Path,
    binding_path: str | Path,
    contract_paths: Sequence[str | Path],
    plugin_map_path: str | Path,
    controller_instance: str,
    candidate_generation: int,
    membership_epoch: int,
) -> dict[str, Any]:
    """Owner helper; reads installed bytes and artifact refs without launching."""
    from .plan_artifact import parse_plan_artifact

    _, snapshots = installed_plugin_identities(bundles)
    plan = parse_plan_artifact(_private(plan_path))
    return {
        "schema": SCHEMA,
        "base_plan": artifact_reference(base_plan_path),
        "plan": artifact_reference(plan_path),
        "binding": artifact_reference(binding_path),
        "contracts": [artifact_reference(path) for path in contract_paths],
        "plugin_map": artifact_reference(plugin_map_path),
        "enabled_bundles": snapshots,
        "execution_plan_id": plan.plan_id,
        "native_plan_id": plan.plan_id.rsplit(":", 1)[-1],
        "controller_instance": controller_instance,
        "candidate_generation": candidate_generation,
        "membership_epoch": membership_epoch,
    }
