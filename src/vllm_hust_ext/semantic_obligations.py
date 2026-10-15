"""Prospective typed execution obligations; invocation is never this effect."""

from __future__ import annotations

from dataclasses import asdict, replace
from typing import Any

from .contract_compiler import ContractPlan, compile_contracts
from .ecpa_model import EvidenceObligation, Plan, content_id
from .plan_artifact import parse_plan_artifact, plan_artifact_bytes

EVENT = "selected-kv-native-arguments-completed"
SCOPE = "selected-logical-KV-reference-gather-destination-native-entry-completion/v1"


def compile_native_semantic_plan(
    base: Plan,
    compiled: ContractPlan,
    *,
    extension_plugin_ids: dict[str, str],
    required_worker_ordinals: tuple[int, ...],
) -> tuple[Plan, dict[str, Any]]:
    """Construct a new content-addressed Plan, preserving old artifacts unchanged.

    Explicit runtime/all worker contracts only. This links intent to a required
    bounded effect; it does not register a producer, prove bytes, or expose traffic.
    """
    if required_worker_ordinals != (0, 1) or any(
        type(ordinal) is not int for ordinal in required_worker_ordinals
    ):
        raise ValueError("native semantic source currently supports explicit TP2 only")
    parse_plan_artifact(plan_artifact_bytes(base))
    if (base.host.runtime, base.host.version) != (
        compiled.host_runtime,
        compiled.host_version,
    ):
        raise ValueError("compiled contracts and execution Plan target different hosts")
    checked = compile_contracts(
        compiled.ordered_contracts,
        host_runtime=compiled.host_runtime,
        host_version=compiled.host_version,
    )
    if checked != compiled:
        raise ValueError("compiled contract bindings do not match their contracts")
    if any(item.event == EVENT for item in base.obligations):
        raise ValueError("semantic Plan already compiled; no posthoc rebinding")
    plugins = {plugin.id: plugin for plugin in base.plugins}
    contracts = {
        contract.extension_id: contract for contract in compiled.ordered_contracts
    }
    semantic = [
        binding for binding in compiled.obligation_bindings if binding.event == EVENT
    ]
    if not semantic:
        raise ValueError(
            "compiled contracts have no explicit native semantic obligation"
        )
    if set(extension_plugin_ids) != {binding.extension_id for binding in semantic}:
        raise ValueError("semantic extension/plugin identity mapping is incomplete")
    if len(set(extension_plugin_ids.values())) != len(extension_plugin_ids):
        raise ValueError(
            "distinct semantic extensions require distinct plugin artifacts"
        )
    obligations = list(base.obligations)
    bindings = []
    for binding in semantic:
        if (
            binding.role != "worker"
            or binding.authority != "runtime"
            or binding.completion != "all"
            or binding.quorum is not None
        ):
            raise ValueError(
                "native semantic source requires all current runtime workers"
            )
        plugin_id = extension_plugin_ids[binding.extension_id]
        if plugin_id not in plugins:
            raise ValueError("semantic provider artifact is outside execution Plan")
        contract = contracts[binding.extension_id]
        if contract.version != plugins[plugin_id].version:
            raise ValueError("semantic contract/plugin artifact versions differ")
        material = {
            "base_execution_plan_id": base.plan_id,
            "compiled_contract_plan_id": compiled.plan_id,
            "compiled_obligation": asdict(binding),
            "contract_manifest_sha256": contract.manifest_sha256,
            "plugin_id": plugin_id,
            "scope": SCOPE,
            "required_worker_ordinals": list(required_worker_ordinals),
        }
        obligation_id = content_id("semantic-obligation", material)
        obligations.append(
            EvidenceObligation(obligation_id, "worker", EVENT, required_worker_ordinals)
        )
        bindings.append(dict(material, obligation_id=obligation_id))
    if len({item.obligation_id for item in obligations}) != len(obligations):
        raise ValueError("ambiguous semantic execution obligations")
    plan = replace(base, obligations=tuple(obligations))
    return plan, {
        "schema": "ecpa-compiled-native-semantic-execution-binding/v1",
        "execution_plan_id": plan.plan_id,
        "base_execution_plan_id": base.plan_id,
        "compiled_contract_plan_id": compiled.plan_id,
        "bindings": bindings,
        "scope": SCOPE,
        "formal_producer_registration": False,
    }


def compile_artifacts(
    base_path: str,
    contract_paths: list[str],
    plugin_map_path: str,
    output_directory: str,
) -> dict[str, Any]:
    """Publish a fresh prospective Plan and its binding, without launching code."""
    import json
    import os
    import shutil
    from pathlib import Path

    from .contract_compiler import parse_contract
    from .ecpa_model import canonical_bytes
    from .plan_artifact import read_plan_artifact

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON field in semantic compilation input")
            value[key] = item
        return value

    base = read_plan_artifact(base_path).plan
    contracts = tuple(
        parse_contract(
            json.loads(Path(path).read_bytes(), object_pairs_hook=unique_object)
        )
        for path in contract_paths
    )
    mapping = json.loads(
        Path(plugin_map_path).read_bytes(), object_pairs_hook=unique_object
    )
    if not isinstance(mapping, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in mapping.items()
    ):
        raise ValueError("extension/plugin map must contain string identities")
    compiled = compile_contracts(
        contracts, host_runtime=base.host.runtime, host_version=base.host.version
    )
    plan, binding = compile_native_semantic_plan(
        base, compiled, extension_plugin_ids=mapping, required_worker_ordinals=(0, 1)
    )
    output = Path(output_directory)
    if not output.is_absolute() or output.parent.resolve() != output.parent:
        raise ValueError("output directory must have an absolute canonical parent")
    output.mkdir(mode=0o700, exist_ok=False)
    try:
        for name, raw in (
            ("plan.json", plan_artifact_bytes(plan)),
            ("binding.json", canonical_bytes(binding) + b"\n"),
        ):
            descriptor = os.open(
                output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        shutil.rmtree(output)
        raise
    return binding
