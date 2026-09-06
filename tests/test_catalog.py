from __future__ import annotations

import copy

import pytest

from vllm_hust_ext.catalog import CatalogError, activation_blocker, parse_catalog


def _entry() -> dict[str, object]:
    return {
        "id": "org.vllm-hust.example",
        "name": "Example",
        "repository": "https://github.com/vLLM-HUST/example",
        "source": {"ref": "main", "commit": "a" * 40},
        "maturity": "qualified",
        "availability": "available",
        "installation": {
            "type": "python-source",
            "repository": "https://github.com/vLLM-HUST/example",
            "commit": "a" * 40,
            "manifest_path": ".vllm-hust/optimization.json",
            "manifest_sha256": "sha256:" + "b" * 64,
            "source_subdir": "",
            "entrypoint": {"group": "vllm_hust.extension_bundles", "name": "example"},
        },
        "enablement": {"allowed": True, "blocker": None},
        "runtime_requirements": {
            "models": ["Qwen/Qwen3.8-27B"],
            "hardware": ["Ascend NPU"],
            "topologies": ["TP4 graph"],
            "core": "0.28.1rc1.dev319@762f85b3",
            "ascend": "0.25.1rc1@4e57439e",
            "additional_models": [],
            "storage": "none",
            "hbm": "no incremental allocation measured",
            "environment": {},
        },
        "functional_qualification": {
            "status": "passed",
            "scope": "TP4 graph correctness and recovery",
            "recovery": "passed",
            "evidence": ["evidence/run.json"],
        },
        "tested_effects": [
            {
                "status": "not-recommended-for-tested-cell",
                "cell": "interactive short output",
                "summary": "Correct but slower than baseline in this cell.",
                "evidence": ["evidence/effect.json"],
            }
        ],
        "expected_scenarios": [
            {
                "id": "high-pressure",
                "description": "High KV pressure",
                "status": "unverified",
                "evidence": [],
            }
        ],
        "recommendation": {
            "level": "not-recommended-for-tested-cell",
            "reason": (
                "Availability is independent from this scoped performance result."
            ),
        },
        "resource_tradeoff": {
            "benefit": "scenario dependent",
            "cost": "policy overhead",
        },
        "conflicts": [],
        "rollback": {
            "owner": "operator",
            "steps": ["Disable the extension and restart."],
        },
    }


def _catalog(entry: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "schema": "vllm-hust.extension-catalog/v1",
        "generated_at": "2026-09-06T00:00:00Z",
        "source": {"ref": "main", "commit": "c" * 40},
        "policy": {
            "availability": "Function and recovery gates determine availability.",
            "performance": (
                "Negative performance is scoped, not an availability blocker."
            ),
            "preview": "Unverified function or recovery is not enableable.",
            "runtime_state": (
                "Installed, configured, enabled, and effective are distinct."
            ),
        },
        "extensions": [entry or _entry()],
    }


def test_negative_performance_does_not_block_qualified_availability() -> None:
    parsed = parse_catalog(_catalog())
    entry = parsed["extensions"][0]
    assert entry["availability"] == "available"
    assert activation_blocker(entry) is None


@pytest.mark.parametrize("field", ["function", "recovery"])
def test_unverified_qualification_cannot_enable(field: str) -> None:
    entry = _entry()
    entry["maturity"] = "preview"
    entry["availability"] = "preview"
    entry["enablement"] = {"allowed": False, "blocker": "qualification pending"}
    qualification = entry["functional_qualification"]
    if field == "function":
        qualification["status"] = "unverified"
        qualification["evidence"] = []
    else:
        qualification["recovery"] = "unverified"
    parsed = parse_catalog(_catalog(entry))
    assert activation_blocker(parsed["extensions"][0]) == "qualification pending"


def test_unverified_function_fails_open_enablement() -> None:
    entry = _entry()
    entry["maturity"] = "experimental"
    entry["functional_qualification"]["status"] = "unverified"
    entry["functional_qualification"]["evidence"] = []
    with pytest.raises(CatalogError, match="cannot be enabled"):
        parse_catalog(_catalog(entry))


def test_short_source_sha_is_rejected() -> None:
    entry = copy.deepcopy(_entry())
    entry["source"]["commit"] = "deadbeef"
    with pytest.raises(CatalogError, match="full Git SHA"):
        parse_catalog(_catalog(entry))
