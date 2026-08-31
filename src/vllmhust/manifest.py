"""Static Bundle v1 manifest model and validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

HOST_API_VERSION = Version("1.0")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
_IMPLEMENTATION = re.compile(
    r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$"
)
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "bundle_id",
    "bundle_version",
    "host_api_range",
    "components",
    "activation",
}
_COMPONENT_FIELDS = {
    "component_id",
    "contracts",
    "execution_planes",
    "isolation",
    "implementation_ref",
    "permissions",
}
_ISOLATIONS = {"trusted_in_process", "process_isolated", "sandboxed_process"}
_PLANES = {"api", "scheduler", "worker", "native", "device", "bridge"}
_PERMISSIONS = {
    "device_access",
    "filesystem_read",
    "filesystem_write",
    "ipc",
    "network_egress",
    "shared_memory",
    "subprocess",
}


class ManifestError(ValueError):
    """A Bundle manifest is malformed or incompatible."""


@dataclass(frozen=True, slots=True)
class ActivationEntryPoint:
    group: str
    name: str


@dataclass(frozen=True, slots=True)
class BundleActivation:
    entry_points: tuple[ActivationEntryPoint, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    additional_config: tuple[tuple[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class BundleComponent:
    component_id: str
    contracts: tuple[str, ...]
    execution_planes: tuple[str, ...]
    isolation: str
    implementation_ref: str
    permissions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BundleManifest:
    bundle_id: str
    bundle_version: str
    host_api_range: str
    components: tuple[BundleComponent, ...]
    activation: BundleActivation


def _object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise ManifestError(f"{location} must be an object with string keys")
    return value


def _string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{location} must be a non-empty string")
    return value


def _strings(value: Any, location: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ManifestError(f"{location} must be an array of strings")
    result = tuple(value)
    if len(result) != len(set(result)):
        raise ManifestError(f"{location} must not contain duplicates")
    return result


def _known(values: tuple[str, ...], allowed: set[str], location: str) -> None:
    unknown = set(values) - allowed
    if unknown:
        raise ManifestError(
            f"{location} contains unsupported values: {sorted(unknown)}"
        )


def _parse_activation(value: Any) -> BundleActivation:
    if value is None:
        return BundleActivation()
    activation = _object(value, "activation")
    unknown = activation.keys() - {"entry_points", "environment", "additional_config"}
    if unknown:
        raise ManifestError(f"activation contains unknown fields: {sorted(unknown)}")
    entries: list[ActivationEntryPoint] = []
    for index, raw in enumerate(activation.get("entry_points", [])):
        item = _object(raw, f"activation.entry_points[{index}]")
        if item.keys() != {"group", "name"}:
            raise ManifestError(
                f"activation.entry_points[{index}] requires group and name"
            )
        entries.append(
            ActivationEntryPoint(
                _string(item["group"], f"activation.entry_points[{index}].group"),
                _string(item["name"], f"activation.entry_points[{index}].name"),
            )
        )
    environment = _object(activation.get("environment", {}), "activation.environment")
    if not all(isinstance(v, str) for v in environment.values()):
        raise ManifestError("activation.environment values must be strings")
    additional = _object(
        activation.get("additional_config", {}), "activation.additional_config"
    )
    return BundleActivation(
        entry_points=tuple(entries),
        environment=tuple(sorted(environment.items())),
        additional_config=tuple(sorted(additional.items())),
    )


def parse_manifest(payload: Any) -> BundleManifest:
    manifest = _object(payload, "manifest")
    unknown = manifest.keys() - _TOP_LEVEL_FIELDS
    if unknown:
        raise ManifestError(f"manifest contains unknown fields: {sorted(unknown)}")
    required = _TOP_LEVEL_FIELDS - {"activation"}
    missing = required - manifest.keys()
    if missing:
        raise ManifestError(f"manifest is missing fields: {sorted(missing)}")
    if manifest["schema_version"] != "1.0":
        raise ManifestError("unsupported schema_version")

    bundle_id = _string(manifest["bundle_id"], "bundle_id")
    if not _IDENTIFIER.fullmatch(bundle_id):
        raise ManifestError(
            "bundle_id must use lowercase letters, digits, dots, or hyphens"
        )
    bundle_version = _string(manifest["bundle_version"], "bundle_version")
    try:
        Version(bundle_version)
    except InvalidVersion as error:
        raise ManifestError("bundle_version is not a valid version") from error
    host_api_range = _string(manifest["host_api_range"], "host_api_range")
    try:
        compatible = HOST_API_VERSION in SpecifierSet(host_api_range)
    except InvalidSpecifier as error:
        raise ManifestError("host_api_range is not a valid specifier") from error
    if not compatible:
        raise ManifestError(
            f"bundle requires host API {host_api_range}, "
            f"host provides {HOST_API_VERSION}"
        )

    raw_components = manifest["components"]
    if not isinstance(raw_components, list) or not raw_components:
        raise ManifestError("components must be a non-empty array")
    components: list[BundleComponent] = []
    for index, raw in enumerate(raw_components):
        item = _object(raw, f"components[{index}]")
        unknown = item.keys() - _COMPONENT_FIELDS
        missing = (_COMPONENT_FIELDS - {"permissions"}) - item.keys()
        if unknown or missing:
            raise ManifestError(
                f"components[{index}] has unknown={sorted(unknown)} "
                f"missing={sorted(missing)}"
            )
        component_id = _string(
            item["component_id"], f"components[{index}].component_id"
        )
        if not _IDENTIFIER.fullmatch(component_id):
            raise ManifestError(f"components[{index}].component_id is invalid")
        contracts = _strings(item["contracts"], f"components[{index}].contracts")
        if not contracts or not all(
            contract.startswith("vllm.") for contract in contracts
        ):
            raise ManifestError(f"components[{index}].contracts is invalid")
        planes = _strings(
            item["execution_planes"], f"components[{index}].execution_planes"
        )
        _known(planes, _PLANES, f"components[{index}].execution_planes")
        isolation = _string(item["isolation"], f"components[{index}].isolation")
        _known((isolation,), _ISOLATIONS, f"components[{index}].isolation")
        implementation = _string(
            item["implementation_ref"], f"components[{index}].implementation_ref"
        )
        if not _IMPLEMENTATION.fullmatch(implementation):
            raise ManifestError(f"components[{index}].implementation_ref is invalid")
        permissions = _strings(
            item.get("permissions", []), f"components[{index}].permissions"
        )
        _known(permissions, _PERMISSIONS, f"components[{index}].permissions")
        components.append(
            BundleComponent(
                component_id,
                contracts,
                planes,
                isolation,
                implementation,
                permissions,
            )
        )
    ids = [component.component_id for component in components]
    if len(ids) != len(set(ids)):
        raise ManifestError("component_id values must be unique")
    return BundleManifest(
        bundle_id,
        bundle_version,
        host_api_range,
        tuple(components),
        _parse_activation(manifest.get("activation")),
    )


def load_manifest(path: Path) -> BundleManifest:
    if path.is_symlink() or not path.is_file():
        raise ManifestError("manifest must be a regular non-symlink file")
    try:
        return parse_manifest(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ManifestError("manifest cannot be read as JSON") from error
