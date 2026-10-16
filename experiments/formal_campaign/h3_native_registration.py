"""Independent native-domain registration; no old receipt or completion projection.

The issuer observes sources and inputs itself. Native readiness permits private
forwarding only; every public response still needs original native completion.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from pathlib import Path

from experiments.formal_campaign import h3_dynamic_registration as common
from experiments.formal_campaign.h3_dynamic_authority import canonical, require
from experiments.formal_campaign.h3_owned_worker_carrier import checked_reference, load

HERE = Path(__file__).resolve().parent
DOMAIN = "ecpa-h3-native-campaign/v1"
RECEIPT = "ecpa-h3-native-deployment-receipt/v1"
CAMPAIGN_SCHEMA = "h3-native-campaign.schema.json"
AUTHORITY_SOURCE = "h3_native_authority.py"
# Pure substitution only; both APIs retain exact frozen intent and schema.
materialize_recipe = common.materialize_recipe
validate_materialization = common.validate_materialization
PROTOCOL_FILES = (
    "h3_native_registration.py",
    "h3-native-campaign.schema.json",
    "h3-native-policy.schema.json",
    "h3-native-worker-recipe.schema.json",
    "h3_native_authority.py",
    "h3_native_client.py",
    "h3_native_http.py",
    "h3_native_collector.py",
    "h3_native_bootstrap.py",
    "h3_native_verifier.py",
    "h3_native_delivery.py",
    "h3_native_plan_guard.py",
    "h3_native_source_scope.py",
)
# The complete source guard imports these published helpers, in addition to the
# unchanged dynamic-domain protocol inventory. Bind all of them, not only H3.
EXTERNAL_PROTOCOL_FILES = tuple(
    str(path.relative_to(common.ROOT))
    for package in (
        "exposure_gate",
        "native_attention_candidate",
        "native_kv_tensor_candidate",
        "native_kv_candidate",
        "pair_semantic_candidate",
    )
    for path in sorted((common.ROOT / "experiments" / package).glob("*.py"))
)


def _profile():
    return sys.modules[__name__]


def validate_policy(policy):
    from jsonschema import Draft7Validator

    from experiments.formal_campaign.h3_native_authority import NativeAuthority

    Draft7Validator(load(HERE / "h3-native-policy.schema.json")).validate(policy)
    NativeAuthority.policy_validator(policy)


def scope_digest(original_ref, start):
    return common._scope_digest(original_ref, start, DOMAIN)


def authority_arguments(spec_path, start):
    require(spec_path is not None, "native authority needs actual campaign path")
    return [
        "--campaign",
        str(Path(spec_path).resolve()),
        "--start-id",
        start["start_id"],
        "--receipt",
        start["authority"]["receipt_path"],
    ]


def validate_receipt_destination(spec, output):
    require(
        all(s["authority"]["receipt_path"] == str(output) for s in spec["starts"]),
        "native command must bind the actual independently issued receipt path",
    )


def _phases(start):
    recipe = load(checked_reference(start["recipe_template"]))
    return recipe["arms"][start["arm"]]["phases"]


def source_artifacts(start):
    result = []
    for phase in _phases(start):
        policy = load(checked_reference(phase["native_guard"]))
        launch = load(checked_reference(phase["semantic_launch_spec"]))
        result.append(
            {
                # SDK semantic references use raw hex; the H3 source-admission
                # boundary requires its exact sha256:-prefixed reference ABI.
                "contracts": [
                    dict(ref, sha256="sha256:" + ref["sha256"])
                    for ref in launch["contracts"]
                ],
                "bundle_ids": policy["bundle_ids"],
            }
        )
    return result


def _native_wheel_payloads(audit):
    """Independently reobserve all original seven wheels; no digest admission."""
    from experiments.native_attention_candidate import live_route_reader as routes

    result = {}
    fresh = routes.audit_cell_inputs(audit["config"]["path"], audit["recipe"]["path"])
    require(
        canonical(fresh) == canonical(audit),
        "native wheel input audit differs from fresh observation",
    )
    states = {}
    config_path = routes._path(fresh["config"]["path"])
    config_raw = config_path.read_bytes()
    require(
        routes.registry.sha(config_raw) == fresh["config"]["sha256"],
        "native audited wheel configuration changed",
    )
    wheels = json.loads(config_raw)["wheel_artifacts"]
    require(
        set(wheels) == set(routes.DISTRIBUTIONS)
        and set(fresh["wheel_sha256"]) == set(routes.DISTRIBUTIONS),
        "native original seven wheel roles differ",
    )
    installed = {}
    for role, distribution in routes.DISTRIBUTIONS.items():
        wheel = wheels[role]
        require(
            routes._hash(wheel["path"], states)
            == fresh["wheel_sha256"][role]
            == wheel["sha256"],
            "native genuine wheel bytes changed after independent audit",
        )
        installed[role] = routes._installed_payload(wheel, distribution, states)
    require(
        routes.registry.sha(routes.registry.canonical(installed))
        == fresh["installed_payload_sha256"],
        "native actual seven-wheel payload inventory changed",
    )
    routes._check_file_states(states)
    require(
        config_path.read_bytes() == config_raw,
        "native audited wheel configuration changed during capture",
    )
    for payload in installed.values():
        for path, sha in payload.items():
            require(
                path not in result or result[path] == sha,
                "native audited wheel source collision",
            )
            result[path] = sha
    return fresh, result


def installed_payloads(spec, original, *, _starts=None):
    from experiments.formal_campaign.h3_runtime_source_closure import (
        verify_runtime_source_closure,
    )

    result, audited = {}, {}
    for start in spec["starts"] if _starts is None else _starts:
        for phase in _phases(start):
            closure = verify_runtime_source_closure(
                phase,
                original["fixed_identity"],
                spec["repositories"],
                spec["runtime_wheels"],
            )
            for dist in closure["actual_runtime"]["distributions"].values():
                for path, sha in dist["payload"].items():
                    require(
                        path not in result or result[path] == sha,
                        "runtime payload source collision",
                    )
                    result[path] = sha
            # This map lives only in this invocation. Every identical audited
            # config/recipe reference pair gets one independent seven-wheel
            # observation; no caller digest or earlier invocation seeds it.
            guard = load(checked_reference(phase["native_guard"]))
            audits = guard["source_arguments"]["input_audits"]
            require(
                type(audits) is dict and audits,
                "native independent input audits absent",
            )
            for audit in audits.values():
                key = canonical({"config": audit["config"], "recipe": audit["recipe"]})
                if key not in audited:
                    audited[key] = _native_wheel_payloads(audit)
                fresh, payload = audited[key]
                require(
                    canonical(fresh) == canonical(audit),
                    "native wheel audit claim changed for identical input refs",
                )
                for path, sha in payload.items():
                    require(
                        path not in result or result[path] == sha,
                        "native wheel and source closure payload collision",
                    )
                    result[path] = sha
    return result


def verify_contract_source(spec, path, bundle_ids):
    from experiments.pair_semantic_candidate.binding import (
        KV,
        PROFILER,
        PROFILER_SLOTS,
        profiler_contract,
    )
    from vllm_hust_ext.discovery import discover_bundles

    raw = path.read_bytes()
    value = json.loads(raw)
    if value["id"] == KV:
        require(
            raw
            == checked_reference(
                spec["original_native_intent"]["kv_contract"]
            ).read_bytes(),
            "native KV contract changed independently registered original intent",
        )
    else:
        require(
            value["id"] == PROFILER and PROFILER in bundle_ids,
            "native contract has no admitted actual MOD",
        )
        base, _ = _intent_roots(spec)
        bundles = discover_bundles((PROFILER,))
        require(
            len(bundles) == 1
            and value
            == profiler_contract(
                bundles[0].distribution_version, base.host.version, PROFILER_SLOTS
            ),
            "profiler contract differs from original source-owned role slots",
        )


def preflight_native_spec(phase):
    """Bound final declared paths and all60 IDs before any Host/collector Popen."""
    from experiments.exposure_gate import native_semantic_collector as native
    from experiments.formal_campaign.h3_native_source_scope import (
        native_spec_size_upper_bound,
        scope_native_senders,
    )

    boot = phase["native_bootstrap"]
    sources = boot["source_files"]
    phase_ids = {p["phase_id"] for p in boot["phases"]}
    require(
        len(phase_ids) == 60 and set(boot["tensor_requirements"]) == phase_ids,
        "native tensor requirements must cover every original60 request",
    )
    for phase_id, req in boot["tensor_requirements"].items():
        require(
            set(req) == {"layer_indices", "semantic_anchor", "physical_anchor"}
            and type(req["layer_indices"]) is list
            and req["layer_indices"]
            and all(type(i) is int and i >= 0 for i in req["layer_indices"])
            and len(set(req["layer_indices"])) == len(req["layer_indices"])
            and type(req["semantic_anchor"]) is int
            and type(req["physical_anchor"]) is int
            and 0 < req["physical_anchor"] < req["semantic_anchor"]
            and all(
                req[k] == boot["kv_requirements"][phase_id][k]
                for k in ("semantic_anchor", "physical_anchor")
            ),
            "native tensor inventory/anchors differ from original KV requirements",
        )
    senders = []
    for role, ordinal in (("api-server", 0), ("worker", 0), ("worker", 1)):
        senders.append(
            {
                "process": {
                    "role": role,
                    "ordinal": ordinal,
                    "host": socket.gethostname(),
                    "assignment_source": "host",
                    "pid": 1,
                    "session": 1,
                    "start_ticks": 1,
                    "process_epoch": 1,
                    "start_identity": "pid:1:start_ticks:1",
                    "boot_id": "00000000-0000-0000-0000-000000000000",
                },
                "cmdline_sha256": "0" * 64,
                "peer_uid": os.getuid(),
                "peer_gid": os.getgid(),
                "source_files": sources,
            }
        )
    scoped, _ = scope_native_senders(senders, sources)
    plan = load(checked_reference(phase["semantic_launch_spec"]))
    return native_spec_size_upper_bound(
        {
            "schema": native.KV_SPEC_V2,
            "classification": "CPU_REVIEW_CANDIDATE_ONLY",
            "formal_producer_registration": False,
            "native_plan_id": plan["execution_plan_id"],
            "native_launch_id": "00000000-0000-4000-8000-000000000000",
            "frozen_monotonic_ns": 1,
            "max_event_age_ns": 5_000_000_000,
            "max_uploads_per_rank": 256,
            "senders": scoped,
            "phases": boot["phases"],
            "kv_requirements": boot["kv_requirements"],
        }
    )


def validate_start(spec, original, start, recipe, policy):
    phases = recipe["arms"][start["arm"]]["phases"]
    admitted = {
        (r["path"], r["sha256"].removeprefix("sha256:")) for r in policy["source_refs"]
    }
    expected_rids = {f"{start['start_id']}/request-{i:05d}" for i in range(60)}
    launches = [load(checked_reference(p["semantic_launch_spec"])) for p in phases]
    require(
        len(launches) == 2
        and [p["candidate_generation"] for p in launches] == [1, 2]
        and all(
            type(p["candidate_generation"]) is int
            and type(p["membership_epoch"]) is int
            and p["membership_epoch"] >= 0
            for p in launches
        )
        and launches[1]["membership_epoch"] > launches[0]["membership_epoch"]
        and type(launches[0]["controller_instance"]) is str
        and bool(launches[0]["controller_instance"])
        and launches[0]["controller_instance"] == launches[1]["controller_instance"],
        "native replacement must advance original semantic generation/membership",
    )
    for phase in phases:
        guard = load(checked_reference(phase["native_guard"]))
        require(
            guard["native_launch_spec"] == phase["semantic_launch_spec"],
            "native guard must bind this actual semantic launch spec",
        )
        require(
            guard["origin"]
            == ("installed-manager" if start["arm"] == "ecpa" else "host-baseline"),
            "native guard publisher origin differs",
        )
        args = guard["source_arguments"]
        require(
            args["fixed"] == original["fixed_identity"]
            and args["policy"] == spec["source_policy"],
            "native guard full source tuple/policy differs",
        )
        boot = phase["native_bootstrap"]
        require(
            {p["client_request_id"] for p in boot["phases"]} == expected_rids,
            "native bootstrap must retain all60 exact original client request IDs",
        )
        require(
            all((r["path"], r["sha256"]) in admitted for r in boot["source_files"]),
            "native producer/receiver source outside full authority source closure",
        )
        for key in ("output", "native_context_path", "tensor_context_path"):
            path = Path(boot[key])
            require(
                path.is_absolute() and path.resolve() == path,
                "native bootstrap path is not canonical",
            )
        preflight_native_spec(phase)


def extra_fresh_paths(start, recipe):
    return [
        phase["native_bootstrap"][key]
        for phase in recipe["arms"][start["arm"]]["phases"]
        for key in ("output", "native_context_path", "tensor_context_path")
    ]


def _intent_roots(spec):
    from experiments.pair_semantic_candidate.binding import KV
    from vllm_hust_ext.discovery import discover_bundles
    from vllm_hust_ext.plan_artifact import parse_plan_artifact
    from vllm_hust_ext.semantic_runtime_binding import installed_plugin_identities

    intent = spec["original_native_intent"]
    base = parse_plan_artifact(checked_reference(intent["base_plan"]).read_bytes())
    contract_raw = checked_reference(intent["kv_contract"]).read_bytes()
    contract = json.loads(contract_raw)
    plugins, _ = installed_plugin_identities(discover_bundles((KV,)))
    require(
        base.plugins == plugins,
        "original KV base must retain actual installed KV identity",
    )
    require(
        any(
            o.role == "worker"
            and o.event == "invoked"
            and tuple(o.required_ordinals) == (0, 1)
            for o in base.obligations
        ),
        "original KV base must retain both workers' invoked obligation",
    )
    require(
        contract["id"] == KV, "original native contract must belong to actual KV MOD"
    )
    return base, contract_raw


def build_plan_guards(spec, original, receipt, start, *, trusted_manager_handoffs):
    """Reobserve actual inputs; root sets never come from per-phase digest claims."""
    from experiments.formal_campaign.h3_native_plan_guard import NativePlanGuard
    from experiments.native_attention_candidate import live_route_reader as routes
    from experiments.pair_semantic_candidate import authority as pair
    from vllm_hust_ext.plan_artifact import parse_plan_artifact

    base, contract_raw = _intent_roots(spec)
    observation = receipt["source_observation"]
    guards = []
    for phase in _phases(start):
        policy = load(checked_reference(phase["native_guard"]))
        args = policy["source_arguments"]
        require(
            args["observation"] == observation,
            "native source observation differs from independent receipt",
        )
        claimed_base = parse_plan_artifact(
            checked_reference(args["original_kv_base"]).read_bytes()
        )
        require(
            claimed_base == base
            and checked_reference(args["kv_contract"]).read_bytes() == contract_raw,
            "native guard changed independently registered original KV intent",
        )
        roots = set()
        for audit in args["input_audits"].values():
            fresh = routes.audit_cell_inputs(
                audit["config"]["path"], audit["recipe"]["path"]
            )
            require(
                fresh == audit,
                "native input audit differs from independent fresh observation",
            )
            for ref in (args["original_kv_base"], args["kv_contract"]):
                require(
                    fresh["source_files"].get(ref["path"])
                    == ref["sha256"].removeprefix("sha256:"),
                    "original native intent absent from fresh input source inventory",
                )
            roots.add(pair.sha(pair.canonical(fresh)))
        if args["pair_inputs"] is not None:
            p = args["pair_inputs"]
            require(
                p["native_inputs"] in args["input_audits"].values(),
                "pair audit lost original complete native input",
            )
            current = pair.audit_pair_inputs(
                p["native_inputs"],
                p["wheels"],
                plugin_commits=p["plugin_commits"],
                bundles=__import__(
                    "vllm_hust_ext.discovery", fromlist=["discover_bundles"]
                ).discover_bundles(policy["bundle_ids"]),
            )
            require(
                current == p, "pair actual installed source/input observation differs"
            )
            roots.add(pair.sha(pair.canonical(current)))
        guard = NativePlanGuard(
            policy=policy,
            trusted_source_observations={
                common.source_provenance.digest(canonical(observation))
            },
            trusted_input_digests=roots,
            trusted_manager_handoffs=trusted_manager_handoffs,
            trusted_base_plan_ids={base.plan_id},
            trusted_contract_digests={pair.sha(contract_raw)},
        )
        guard.verify_plan_current()
        guards.append(guard)
    authority_policy = load(checked_reference(start["policy"]))
    plans = {guard.verify_plan_current()[0].plan_id for guard in guards}
    declared = {
        parse_plan_artifact(checked_reference(ref).read_bytes()).plan_id
        for ref in authority_policy["plan_artifacts"]
    }
    expected_bindings = {
        canonical(
            {
                "execution_plan_id": plan_id,
                "runtime_plan_id": plan_id.rsplit(":", 1)[-1],
            }
        )
        for plan_id in plans
    }
    require(
        plans == declared
        and {canonical(value) for value in authority_policy["native_plan_bindings"]}
        == expected_bindings,
        "native policy Plan/binding inventory differs from both actual semantic epochs",
    )
    return guards


def verify_native_plans(spec, original, observation, *, _starts=None):
    receipt = {"source_observation": observation}
    for start in spec["starts"] if _starts is None else _starts:
        build_plan_guards(
            spec, original, receipt, start, trusted_manager_handoffs=set()
        )


def validate_campaign(spec, *, spec_path):
    return common._validate_campaign(spec, profile=_profile(), spec_path=spec_path)


def issue(spec_path, output):
    return common._issue(spec_path, output, profile=_profile())


def validate_receipt(spec_path, receipt_path, *, check_remote=False):
    return common._validate_receipt(
        spec_path, receipt_path, check_remote=check_remote, profile=_profile()
    )


_START_SCOPE_ISSUER = object()


class _ValidatedNativeStart:
    """One independently fresh start, never a whole-campaign validity result."""

    schema = "ecpa-h3-native-start-validation/v1"
    __slots__ = ("_raw",)

    def __init__(self, *, spec, original, receipt, start_id, _issuer=None):
        require(_issuer is _START_SCOPE_ISSUER, "native start scope is not issued")
        start = next(s for s in spec["starts"] if s["start_id"] == start_id)
        row = next(s for s in receipt["starts"] if s["start_id"] == start_id)
        object.__setattr__(
            self,
            "_raw",
            canonical(
                {
                    "start_id": start_id,
                    "start": start,
                    "context": {k: v for k, v in spec.items() if k != "starts"},
                    "original": original,
                    "authority_binding": row,
                    "source_observation": receipt["source_observation"],
                }
            ),
        )

    def __setattr__(self, name, value):
        raise AttributeError("native start scope is immutable")

    def _value(self, start_id):
        value = json.loads(self._raw)
        require(value["start_id"] == start_id, "validated native start scope differs")
        return value

    def selected(self, start_id):
        value = self._value(start_id)
        return value["context"], value["original"], value["start"]

    def authority_binding(self, start_id):
        return self._value(start_id)["authority_binding"]

    def guard_receipt(self, start_id):
        return {"source_observation": self._value(start_id)["source_observation"]}


def validate_receipt_for_start(
    spec_path, receipt_path, start_id, *, check_remote=False
):
    require(type(start_id) is str and bool(start_id), "selected start ID missing")
    spec, original, receipt = common._validate_receipt(
        spec_path,
        receipt_path,
        check_remote=check_remote,
        profile=_profile(),
        _selected_start_id=start_id,
    )
    return _ValidatedNativeStart(
        spec=spec,
        original=original,
        receipt=receipt,
        start_id=start_id,
        _issuer=_START_SCOPE_ISSUER,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    issue(args.campaign, args.output)


if __name__ == "__main__":
    main()
