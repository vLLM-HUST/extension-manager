"""Compile actual installed KV+profiler identities without dropping KV effects."""

from __future__ import annotations

from dataclasses import replace

from vllm_hust_ext import contract_compiler, semantic_obligations
from vllm_hust_ext.ecpa_model import EvidenceObligation, content_id
from vllm_hust_ext.semantic_runtime_binding import installed_plugin_identities

KV = "org.vllm-hust.ascend-kvcompress"
PROFILER = "org.vllm-hust.request-lifecycle-profiler"
IDS = frozenset((KV, PROFILER))
CAPABILITY = "org.vllm-hust.request-lifecycle-profiler-loader"
SCHEMA = "ecpa-installed-kv-profiler-binding/v1"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def profiler_contract(version, host_version, roles):
    """Declare loader invocation only; typed effective callbacks stay separate."""
    require(
        roles and all(type(r) is str and r for r in roles),
        "actual profiler roles missing",
    )

    def grant(role):
        return dict(
            role=role,
            event="invoked",
            capability_direction="provides",
            capability=CAPABILITY,
        )

    return {
        "schema": "ecpa-manifest/0.1-draft",
        "id": PROFILER,
        "version": version,
        "host": {"runtime": "vllm", "version": "==" + host_version},
        "capabilities": {
            "provides": [{"name": CAPABILITY, "version": "1"}],
            "requires": [],
        },
        "resources": [],
        "authority": {
            "runtime": [grant(r) for r in sorted(roles)],
            "provider": [],
            "external": [],
        },
        "process_obligations": [
            {**grant(r), "completion": "all", "authority": "runtime"}
            for r in sorted(roles)
        ],
        "rollback": {
            "manager_owned": ["closed response-authority route"],
            "external_operator_owned": ["model state and external services"],
        },
    }


def compile_pair_plan(base, bundles, kv_contract, *, profiler_slots):
    """Use real distribution payload snapshots and retain every base obligation.

    Slots are prospective required roles, not observations of a running process.
    The authority must independently join them to the actual Host roster.
    """
    ordered = sorted(bundles, key=lambda b: b.bundle_id)
    require(
        len(ordered) == 2 and {b.bundle_id for b in ordered} == IDS,
        "exact actual KV+profiler bundles required",
    )
    plugins, snapshots = installed_plugin_identities(ordered)
    identities = {s["bundle_id"]: p for s, p in zip(snapshots, plugins, strict=True)}
    require(
        base.plugins == (identities[KV],),
        "base must retain the actual original KV artifact",
    )
    require(
        not any(o.event == semantic_obligations.EVENT for o in base.obligations),
        "compile from original base, never strip an executed semantic Plan",
    )
    slots = {}
    for role, ordinals in profiler_slots.items():
        require(
            type(role) is str and role and type(ordinals) in (tuple, list) and ordinals,
            "profiler role/ordinals missing",
        )
        require(
            all(type(n) is int and n >= 0 for n in ordinals)
            and len(set(ordinals)) == len(ordinals),
            "profiler ordinals invalid",
        )
        slots[role] = tuple(sorted(ordinals))
    require(slots, "actual prospective profiler slots missing")
    require(
        kv_contract["id"] == KV and kv_contract["version"] == identities[KV].version,
        "original KV contract identity differs",
    )
    profiler = profiler_contract(identities[PROFILER].version, base.host.version, slots)
    contracts = tuple(
        contract_compiler.parse_contract(c) for c in (kv_contract, profiler)
    )
    compiled = contract_compiler.compile_contracts(
        contracts, host_runtime=base.host.runtime, host_version=base.host.version
    )
    old_compiled = contract_compiler.compile_contracts(
        (contracts[0],), host_runtime=base.host.runtime, host_version=base.host.version
    )
    original, original_binding = semantic_obligations.compile_native_semantic_plan(
        base,
        old_compiled,
        extension_plugin_ids={KV: identities[KV].id},
        required_worker_ordinals=(0, 1),
    )
    obligations = list(base.obligations)
    loader_bindings = []
    for role, ordinals in sorted(slots.items()):
        material = dict(
            plugin_id=identities[PROFILER].id,
            role=role,
            event="invoked",
            required_ordinals=list(ordinals),
            authority="runtime",
            observation_kind="loader_lifecycle",
        )
        oid = content_id("pair-loader-obligation", material)
        obligations.append(EvidenceObligation(oid, role, "invoked", ordinals))
        loader_bindings.append(dict(material, obligation_id=oid))
    pair_base = replace(base, plugins=tuple(plugins), obligations=tuple(obligations))
    pair, native_binding = semantic_obligations.compile_native_semantic_plan(
        pair_base,
        compiled,
        extension_plugin_ids={KV: identities[KV].id},
        required_worker_ordinals=(0, 1),
    )
    # Identity changes legitimately create a new content-addressed semantic id;
    # prove the entire original KV obligation semantics, not a weaker event.
    before = original_binding["bindings"][0]
    after = native_binding["bindings"][0]
    for field in ("plugin_id", "scope", "required_worker_ordinals"):
        require(before[field] == after[field], "KV native obligation was weakened")
    require(
        before["compiled_obligation"] == after["compiled_obligation"],
        "KV authority/capability/completion changed",
    )
    require(
        set(base.obligations).issubset(pair.obligations),
        "original base obligation removed",
    )
    return (
        pair_base,
        pair,
        native_binding,
        {
            "schema": SCHEMA,
            "execution_plan_id": pair.plan_id,
            "original_kv_execution_plan_id": original.plan_id,
            "enabled_bundles": snapshots,
            "plugin_identities": {k: v.id for k, v in identities.items()},
            "profiler_contract": profiler,
            "profiler_loader_bindings": loader_bindings,
            "native_semantic_binding": native_binding,
            "original_kv_native_binding": original_binding,
            "formal_result": False,
            "runtime_observed": False,
        },
    )
