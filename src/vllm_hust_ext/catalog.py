"""Strict machine-readable organization extension catalog feed."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

CATALOG_SCHEMA = "vllm-hust.extension-catalog/v1"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
_MATURITY = {"qualified", "experimental", "preview", "external"}
_AVAILABILITY = {"available", "preview", "external"}
_FUNCTIONAL = {"passed", "unverified", "failed", "not-applicable", "external"}
_RECOVERY = {"passed", "unverified", "failed", "not-applicable"}
_EFFECT = {
    "beneficial",
    "neutral",
    "inconclusive",
    "not-recommended-for-tested-cell",
}
_SCENARIO = {"verified", "unverified", "not-applicable"}
_TOP = {"schema", "generated_at", "source", "policy", "extensions"}
_ENTRY = {
    "id",
    "name",
    "repository",
    "source",
    "maturity",
    "availability",
    "installation",
    "enablement",
    "runtime_requirements",
    "functional_qualification",
    "tested_effects",
    "expected_scenarios",
    "recommendation",
    "resource_tradeoff",
    "conflicts",
    "rollback",
}


class CatalogError(ValueError):
    """Catalog feed is malformed or violates admission policy."""


def _object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise CatalogError(f"{location} must be an object")
    return value


def _string(value: Any, location: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value.strip()):
        raise CatalogError(f"{location} must be a non-empty string")
    return value


def _exact(value: Any, expected: set[str], location: str) -> dict[str, Any]:
    result = _object(value, location)
    if set(result) != expected:
        raise CatalogError(
            f"{location} has unknown={sorted(set(result) - expected)} "
            f"missing={sorted(expected - set(result))}"
        )
    return result


def _strings(value: Any, location: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CatalogError(f"{location} must be an array of strings")
    if len(value) != len(set(value)):
        raise CatalogError(f"{location} must not contain duplicates")
    return value


def _evidence(value: Any, location: str, required: bool) -> list[str]:
    result = _strings(value, location)
    if required and not result:
        raise CatalogError(f"{location} requires at least one evidence locator")
    return result


def _source(value: Any, location: str) -> dict[str, Any]:
    result = _exact(value, {"ref", "commit"}, location)
    _string(result["ref"], f"{location}.ref")
    if not _SHA.fullmatch(_string(result["commit"], f"{location}.commit")):
        raise CatalogError(f"{location}.commit must be a full Git SHA")
    return result


def _installation(value: Any, location: str) -> dict[str, Any] | None:
    if value is None:
        return None
    result = _exact(
        value,
        {
            "type",
            "repository",
            "commit",
            "manifest_path",
            "manifest_sha256",
            "source_subdir",
            "entrypoint",
        },
        location,
    )
    if result["type"] != "python-source":
        raise CatalogError(f"{location}.type must be python-source")
    _string(result["repository"], f"{location}.repository")
    if not _SHA.fullmatch(_string(result["commit"], f"{location}.commit")):
        raise CatalogError(f"{location}.commit must be a full Git SHA")
    _string(result["manifest_path"], f"{location}.manifest_path")
    if not _DIGEST.fullmatch(
        _string(result["manifest_sha256"], f"{location}.manifest_sha256")
    ):
        raise CatalogError(f"{location}.manifest_sha256 must be sha256:<hex>")
    _string(result["source_subdir"], f"{location}.source_subdir", empty=True)
    entrypoint = _exact(
        result["entrypoint"], {"group", "name"}, f"{location}.entrypoint"
    )
    _string(entrypoint["group"], f"{location}.entrypoint.group")
    _string(entrypoint["name"], f"{location}.entrypoint.name")
    return result


def _runtime_requirements(value: Any, location: str) -> None:
    result = _exact(
        value,
        {
            "models",
            "hardware",
            "topologies",
            "core",
            "ascend",
            "additional_models",
            "storage",
            "hbm",
            "environment",
        },
        location,
    )
    for field in ("models", "hardware", "topologies"):
        _strings(result[field], f"{location}.{field}")
    for field in ("core", "ascend", "storage", "hbm"):
        _string(result[field], f"{location}.{field}")
    environment = _object(result["environment"], f"{location}.environment")
    if not all(
        isinstance(key, str) and isinstance(item, str)
        for key, item in environment.items()
    ):
        raise CatalogError(f"{location}.environment must map strings to strings")
    if not isinstance(result["additional_models"], list):
        raise CatalogError(f"{location}.additional_models must be an array")
    for index, raw in enumerate(result["additional_models"]):
        item = _exact(
            raw,
            {"model", "sha256", "required"},
            f"{location}.additional_models[{index}]",
        )
        _string(item["model"], f"{location}.additional_models[{index}].model")
        if not _DIGEST.fullmatch(
            _string(item["sha256"], f"{location}.additional_models[{index}].sha256")
        ):
            raise CatalogError(
                f"{location}.additional_models[{index}].sha256 is invalid"
            )
        if not isinstance(item["required"], bool):
            raise CatalogError(
                f"{location}.additional_models[{index}].required must be boolean"
            )


def _validate_entry(entry: Any, index: int) -> dict[str, Any]:
    location = f"extensions[{index}]"
    item = _exact(entry, _ENTRY, location)
    extension_id = _string(item["id"], f"{location}.id")
    if not _ID.fullmatch(extension_id):
        raise CatalogError(f"{location}.id is invalid")
    for field in ("name", "repository"):
        _string(item[field], f"{location}.{field}")
    _source(item["source"], f"{location}.source")
    maturity = _string(item["maturity"], f"{location}.maturity")
    availability = _string(item["availability"], f"{location}.availability")
    if maturity not in _MATURITY or availability not in _AVAILABILITY:
        raise CatalogError(f"{location} has unsupported maturity or availability")
    installation = _installation(item["installation"], f"{location}.installation")
    enablement = _exact(
        item["enablement"], {"allowed", "blocker"}, f"{location}.enablement"
    )
    if not isinstance(enablement["allowed"], bool):
        raise CatalogError(f"{location}.enablement.allowed must be boolean")
    if enablement["blocker"] is not None:
        _string(enablement["blocker"], f"{location}.enablement.blocker")
    _runtime_requirements(
        item["runtime_requirements"], f"{location}.runtime_requirements"
    )
    functional = _exact(
        item["functional_qualification"],
        {"status", "scope", "recovery", "evidence"},
        f"{location}.functional_qualification",
    )
    functional_status = _string(
        functional["status"], f"{location}.functional_qualification.status"
    )
    recovery = _string(
        functional["recovery"], f"{location}.functional_qualification.recovery"
    )
    if functional_status not in _FUNCTIONAL or recovery not in _RECOVERY:
        raise CatalogError(
            f"{location}.functional_qualification has unsupported status"
        )
    _string(functional["scope"], f"{location}.functional_qualification.scope")
    _evidence(
        functional["evidence"],
        f"{location}.functional_qualification.evidence",
        functional_status == "passed",
    )

    if not isinstance(item["tested_effects"], list):
        raise CatalogError(f"{location}.tested_effects must be an array")
    for effect_index, raw in enumerate(item["tested_effects"]):
        effect = _exact(
            raw,
            {"status", "cell", "summary", "evidence"},
            f"{location}.tested_effects[{effect_index}]",
        )
        if (
            _string(
                effect["status"], f"{location}.tested_effects[{effect_index}].status"
            )
            not in _EFFECT
        ):
            raise CatalogError(
                f"{location}.tested_effects[{effect_index}].status is unsupported"
            )
        _string(effect["cell"], f"{location}.tested_effects[{effect_index}].cell")
        _string(effect["summary"], f"{location}.tested_effects[{effect_index}].summary")
        _evidence(
            effect["evidence"],
            f"{location}.tested_effects[{effect_index}].evidence",
            True,
        )

    if not isinstance(item["expected_scenarios"], list):
        raise CatalogError(f"{location}.expected_scenarios must be an array")
    for scenario_index, raw in enumerate(item["expected_scenarios"]):
        scenario = _exact(
            raw,
            {"id", "description", "status", "evidence"},
            f"{location}.expected_scenarios[{scenario_index}]",
        )
        _string(scenario["id"], f"{location}.expected_scenarios[{scenario_index}].id")
        _string(
            scenario["description"],
            f"{location}.expected_scenarios[{scenario_index}].description",
        )
        status = _string(
            scenario["status"],
            f"{location}.expected_scenarios[{scenario_index}].status",
        )
        if status not in _SCENARIO:
            raise CatalogError(
                f"{location}.expected_scenarios[{scenario_index}].status is unsupported"
            )
        _evidence(
            scenario["evidence"],
            f"{location}.expected_scenarios[{scenario_index}].evidence",
            status == "verified",
        )

    recommendation = _exact(
        item["recommendation"], {"level", "reason"}, f"{location}.recommendation"
    )
    _string(recommendation["level"], f"{location}.recommendation.level")
    _string(recommendation["reason"], f"{location}.recommendation.reason")
    tradeoff = _exact(
        item["resource_tradeoff"], {"benefit", "cost"}, f"{location}.resource_tradeoff"
    )
    _string(tradeoff["benefit"], f"{location}.resource_tradeoff.benefit")
    _string(tradeoff["cost"], f"{location}.resource_tradeoff.cost")
    if not isinstance(item["conflicts"], list):
        raise CatalogError(f"{location}.conflicts must be an array")
    for conflict_index, raw in enumerate(item["conflicts"]):
        conflict = _exact(
            raw, {"id", "reason"}, f"{location}.conflicts[{conflict_index}]"
        )
        _string(conflict["id"], f"{location}.conflicts[{conflict_index}].id")
        _string(conflict["reason"], f"{location}.conflicts[{conflict_index}].reason")
    rollback = _exact(item["rollback"], {"owner", "steps"}, f"{location}.rollback")
    _string(rollback["owner"], f"{location}.rollback.owner")
    if not _strings(rollback["steps"], f"{location}.rollback.steps"):
        raise CatalogError(f"{location}.rollback.steps must not be empty")

    if maturity == "qualified" and (
        functional_status != "passed" or recovery != "passed"
    ):
        raise CatalogError(
            f"{location}: qualified requires passed function and recovery"
        )
    if maturity == "qualified" and (
        installation is None or availability != "available" or not enablement["allowed"]
    ):
        raise CatalogError(f"{location}: qualified must be installable and available")
    if maturity == "preview" and (availability != "preview" or enablement["allowed"]):
        raise CatalogError(f"{location}: preview must be non-enableable")
    if maturity == "external" and (availability != "external" or enablement["allowed"]):
        raise CatalogError(f"{location}: external must be externally managed")
    if functional_status in {"failed", "unverified"} and enablement["allowed"]:
        raise CatalogError(f"{location}: failed/unverified function cannot be enabled")
    if recovery in {"failed", "unverified"} and enablement["allowed"]:
        raise CatalogError(f"{location}: failed/unverified recovery cannot be enabled")
    if enablement["allowed"] and installation is None:
        raise CatalogError(f"{location}: enableable entry requires installation")
    return item


def parse_catalog(payload: Any) -> dict[str, Any]:
    catalog = _exact(payload, _TOP, "catalog")
    if catalog["schema"] != CATALOG_SCHEMA:
        raise CatalogError("unsupported catalog schema")
    _string(catalog["generated_at"], "catalog.generated_at")
    _source(catalog["source"], "catalog.source")
    policy = _exact(
        catalog["policy"],
        {"availability", "performance", "preview", "runtime_state"},
        "catalog.policy",
    )
    for key, value in policy.items():
        _string(value, f"catalog.policy.{key}")
    extensions = catalog["extensions"]
    if not isinstance(extensions, list) or not extensions:
        raise CatalogError("catalog.extensions must be a non-empty array")
    parsed = [_validate_entry(entry, index) for index, entry in enumerate(extensions)]
    ids = [entry["id"] for entry in parsed]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise CatalogError("catalog extension IDs must be unique and sorted")
    return catalog


def load_catalog(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CatalogError("catalog must be a regular non-symlink file")
    try:
        return parse_catalog(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CatalogError("catalog cannot be read as JSON") from error


def activation_blocker(entry: dict[str, Any]) -> str | None:
    enablement = entry["enablement"]
    if enablement["allowed"]:
        return None
    return str(enablement["blocker"] or "catalog entry is not enableable")
