"""Actual installed native Plan/source guard; no traffic or native-proof issuer.

Static trust roots are independent inputs. Real publisher/Host kernels are bound
only after Popen and authenticated handoff. Native report tokens must originate
from the full native verifier and have already been consumed exactly once.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

from experiments.formal_campaign import source_provenance
from experiments.native_attention_candidate import live_route_reader as routes
from experiments.native_attention_candidate import (
    request_semantic_authority as original,
)
from experiments.native_attention_candidate import (
    semantic_producer_registry as registry,
)
from experiments.pair_semantic_candidate import authority as pair
from experiments.pair_semantic_candidate.binding import (
    IDS,
    KV,
    PROFILER,
    PROFILER_SLOTS,
)
from vllm_hust_ext import host_evidence
from vllm_hust_ext import semantic_runtime_binding as runtime
from vllm_hust_ext.discovery import discover_bundles
from vllm_hust_ext.plan_artifact import parse_plan_artifact
from vllm_hust_ext.runtime_phase_handoff import manager_source_digests
from vllm_hust_ext.semantic_obligations import EVENT, SCOPE

SCHEMA = "ecpa-h3-native-source-guard-policy/v1"
CONTEXT = (
    "execution_plan_id",
    "controller_instance",
    "candidate_generation",
    "membership_epoch",
)
ENV_CONTEXT = (
    "ECPA_SEMANTIC_EXECUTION_PLAN_ID",
    "ECPA_SEMANTIC_CONTROLLER_INSTANCE",
    "ECPA_SEMANTIC_CANDIDATE_GENERATION",
    "ECPA_SEMANTIC_MEMBERSHIP_EPOCH",
)
require, canonical, sha = pair.require, pair.canonical, pair.sha


def _trusted(raw_digest, roots):
    return raw_digest in roots or "sha256:" + raw_digest in roots


def _ref(ref):
    require(
        type(ref) is dict and set(ref) == {"path", "sha256"},
        "exact source guard artifact reference required",
    )
    raw = pair._regular(ref["path"])
    require(_trusted(sha(raw), {ref["sha256"]}), "source guard artifact bytes changed")
    return raw


def _argv(pid):
    return [
        p.decode() for p in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if p
    ]


def _environment(pid):
    return dict(
        p.split(b"=", 1)
        for p in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
        if b"=" in p
    )


def _semantic_context(value, launch):
    require(
        type(value) is dict and set(value) == set(CONTEXT),
        "actual semantic context fields differ",
    )
    require(
        type(value["execution_plan_id"]) is str
        and type(value["controller_instance"]) is str
        and type(value["candidate_generation"]) is int
        and type(value["membership_epoch"]) is int,
        "semantic context must keep original integer domain",
    )
    require(
        value == {key: launch[key] for key in CONTEXT},
        "actual semantic context differs; dynamic membership is a separate domain",
    )


def _require_original_kv_invocations(base):
    workers = {
        n
        for item in base.obligations
        if item.role == "worker" and item.event == "invoked"
        for n in item.required_ordinals
    }
    require(
        workers == {0, 1},
        "original KV base must retain both TP2 worker loader obligations",
    )


class _SourceSnapshot:
    __slots__ = ("_owner", "_raw", "plan_id", "native_launch_id")

    def __init__(self, owner, raw, plan_id, native_launch_id):
        self._owner, self._raw = owner, raw
        self.plan_id, self.native_launch_id = plan_id, native_launch_id


class NativePlanGuard:
    def __init__(
        self,
        *,
        policy,
        trusted_source_observations,
        trusted_input_digests,
        trusted_manager_handoffs,
        trusted_base_plan_ids,
        trusted_contract_digests,
    ):
        require(
            set(policy)
            == {
                "schema",
                "origin",
                "native_launch_spec",
                "bundle_ids",
                "source_arguments",
            }
            and policy["schema"] == SCHEMA,
            "strict native source guard policy required",
        )
        require(
            policy["origin"] in {"installed-manager", "host-baseline"},
            "native publisher origin unsupported",
        )
        require(
            type(policy["bundle_ids"]) is list
            and len(set(policy["bundle_ids"])) == len(policy["bundle_ids"])
            and set(policy["bundle_ids"]) in ({KV}, IDS),
            "only actual single KV or actual KV+profiler source tuple supported",
        )
        args = policy["source_arguments"]
        require(
            set(args)
            == {
                "fixed",
                "policy",
                "observation",
                "input_audits",
                "native_sources",
                "original_kv_base",
                "kv_contract",
                "pair_inputs",
                "publisher_argv",
            },
            "native source arguments fields differ",
        )
        require(
            args["input_audits"]
            and args["native_sources"]
            and type(args["publisher_argv"]) is list
            and args["publisher_argv"],
            "native independent input/source/argv missing",
        )
        require(
            trusted_source_observations
            and trusted_input_digests
            and trusted_base_plan_ids
            and trusted_contract_digests,
            "independent native source/input/base/contract trust absent",
        )
        self.policy = copy.deepcopy(policy)
        self.sources = frozenset(trusted_source_observations)
        self.inputs = frozenset(trusted_input_digests)
        self.bases = frozenset(trusted_base_plan_ids)
        self.contracts = frozenset(trusted_contract_digests)
        # This in-process root-owned collection may be populated only after the
        # independent actual handoff observation; no future PID is invented.
        require(
            type(trusted_manager_handoffs) in (set, frozenset),
            "actual handoff trust must be an independently owned root set",
        )
        self.handoffs = trusted_manager_handoffs
        self.bundles = tuple(discover_bundles(tuple(policy["bundle_ids"])))
        require(
            len(self.bundles) == len(policy["bundle_ids"])
            and {b.bundle_id for b in self.bundles} == set(policy["bundle_ids"]),
            "actual installed source guard bundles differ",
        )
        self.paired = len(self.bundles) == 2
        require(
            (args["pair_inputs"] is not None) == self.paired,
            "pair input audit cannot be omitted or added to singleton",
        )

    def verify_plan_current(self):
        args = self.policy["source_arguments"]
        source_provenance.validate_observation(
            args["observation"], args["policy"], args["fixed"]
        )
        require(
            source_provenance.digest(canonical(args["observation"])) in self.sources,
            "native complete source observation not independently trusted",
        )
        launch_ref = self.policy["native_launch_spec"]
        _ref(launch_ref)
        launch = runtime.validate_semantic_launch_spec(launch_ref["path"], self.bundles)
        base_raw, contract_raw = (
            _ref(args["original_kv_base"]),
            _ref(args["kv_contract"]),
        )
        base = parse_plan_artifact(base_raw)
        require(
            base.plan_id in self.bases and _trusted(sha(contract_raw), self.contracts),
            "native original KV base/contract trust differs",
        )
        _require_original_kv_invocations(base)
        plan = parse_plan_artifact(_ref(launch["plan"]))
        actual_base = parse_plan_artifact(_ref(launch["base_plan"]))
        require(
            set(base.obligations).issubset(plan.obligations),
            "original KV base obligations removed",
        )
        binding = json.loads(_ref(launch["binding"]))
        kv_contracts = [
            raw
            for ref in launch["contracts"]
            if (raw := _ref(ref)) and json.loads(raw)["id"] == KV
        ]
        require(
            len(kv_contracts) == 1 and kv_contracts[0] == contract_raw,
            "compiled native Plan changed original trusted KV contract bytes",
        )
        selected = [b for b in binding["bindings"] if b["scope"] == SCOPE]
        require(
            len(selected) == 1
            and selected[0]["compiled_obligation"]["event"] == EVENT
            and selected[0]["compiled_obligation"]["role"] == "worker"
            and selected[0]["compiled_obligation"]["authority"] == "runtime"
            and selected[0]["compiled_obligation"]["completion"] == "all"
            and selected[0]["required_worker_ordinals"] == [0, 1],
            "original all-TP2 native semantic obligation missing",
        )
        required = {
            str(Path(__file__).resolve()): sha(Path(__file__).read_bytes()),
            **args["native_sources"],
        }
        for ref in [
            launch_ref,
            launch["base_plan"],
            launch["plan"],
            launch["binding"],
            launch["plugin_map"],
            *launch["contracts"],
            args["original_kv_base"],
            args["kv_contract"],
        ]:
            raw = _ref(ref)
            required[ref["path"]] = sha(raw)
        fixed = args["fixed"]
        audits = args["input_audits"]
        for audit in audits.values():
            require(
                _trusted(sha(canonical(audit)), self.inputs)
                and audit["schema"] == routes.SCHEMA
                and audit["formal_result"] is False,
                "native input audit not independently trusted",
            )
            revisions = audit["wheel_revisions"]
            require(
                revisions["manager"] == fixed["manager_commit"]
                and revisions["host"] == fixed["host_commit"]
                and revisions["ascend"] == fixed["accelerator_commit"],
                "native source/wheel revisions differ",
            )
            require(
                set(audit["wheel_sha256"]) == set(routes.DISTRIBUTIONS),
                "native original seven wheel audit changed",
            )
            routes._check_file_states(audit["file_state"])
            original.require_audited_sources(audit, required)
            cfg = json.loads(_ref(audit["config"]))
            require(
                audit["wheel_sha256"]
                == {k: v["sha256"] for k, v in cfg["wheel_artifacts"].items()},
                "native current config/wheel identity differs",
            )
            # The independently trusted original audit already hashed every
            # wheel and actual installed payload. Retain its original fresh
            # leaf/ancestor stat predicate on every current check, exactly as
            # RequestSemanticAuthority does; do not add multi-GB wheel rehashes
            # inside the original ten-second response deadline. This reuses
            # immutable expected declarations, never a prior filesystem result.
            require(
                all(
                    wheel["path"] in audit["file_state"]
                    for wheel in cfg["wheel_artifacts"].values()
                ),
                "native wheel lacks original independently audited file state",
            )
            if not self.paired:
                require(
                    len(fixed["plugin_commits"]) == 1
                    and set(fixed["plugin_commits"].values()) == {revisions["mod"]},
                    "singleton native plugin source differs",
                )
        registry._files(args["native_sources"])
        if self.paired:
            pair_inputs = args["pair_inputs"]
            require(
                _trusted(sha(canonical(pair_inputs)), self.inputs)
                and pair_inputs["native_inputs"] in audits.values(),
                "actual pair input root is not independently trusted",
            )
            from experiments.pair_semantic_candidate.binding import compile_pair_plan

            expected_base, expected, expected_native, _ = compile_pair_plan(
                base,
                self.bundles,
                json.loads(contract_raw),
                profiler_slots=dict(PROFILER_SLOTS),
            )
            require(
                plan == expected
                and actual_base == expected_base
                and binding == expected_native,
                "native pair compiler/current full Plan differs",
            )
            current = pair.audit_pair_inputs(
                pair_inputs["native_inputs"],
                pair_inputs["wheels"],
                plugin_commits=pair_inputs["plugin_commits"],
                bundles=self.bundles,
            )
            require(
                current == pair_inputs
                and fixed["plugin_commits"] == pair_inputs["plugin_commits"],
                "actual current pair source/wheel root differs",
            )
        else:
            require(
                actual_base == base and len(plan.plugins) == 1,
                "singleton native base or actual plugin set changed",
            )
        kv_plugin = next(p for p in plan.plugins if p.namespace + "." + p.name == KV)
        require(
            selected[0]["plugin_id"] == kv_plugin.id,
            "native capability bound to another plugin",
        )
        invocations = tuple(
            {
                "obligation_id": o.obligation_id,
                "plugin_id": kv_plugin.id,
                "entry_point": dict(
                    zip(("group", "name", "value"), pair.ENTRIES[KV], strict=True)
                ),
                "role": o.role,
                "required_ordinals": list(o.required_ordinals),
            }
            for o in base.obligations
            if o.event == "invoked"
        )
        require(invocations, "original KV base loader obligations missing")
        self.launch = launch
        return plan, invocations

    def bind_actual(self, enrollment, handoff, roster, kernels, host_journal):
        self.verify_plan_current()
        require(
            _trusted(sha(canonical(handoff)), self.handoffs),
            "actual authenticated publisher handoff not independently trusted",
        )
        bound = BoundNativePlanGuard(
            self, enrollment, handoff, roster, kernels, host_journal
        )
        bound.validate_current(enrollment, host_journal)
        return bound


class BoundNativePlanGuard:
    def __init__(self, guard, enrollment, handoff, roster, kernels, host_journal):
        self.guard = guard
        self.enrollment, self.handoff = (
            copy.deepcopy(enrollment),
            copy.deepcopy(handoff),
        )
        self.roster, self.kernels = copy.deepcopy(roster), copy.deepcopy(kernels)
        self.host_journal = Path(host_journal)

    def validate_current(self, enrollment, host_journal):
        guard = self.guard
        plan, invocations = guard.verify_plan_current()
        launch = guard.launch
        require(
            enrollment == self.enrollment and Path(host_journal) == self.host_journal,
            "native current enrollment/journal changed",
        )
        require(
            _trusted(sha(canonical(self.handoff)), guard.handoffs),
            "native publisher handoff trust revoked",
        )
        record = self.handoff["record"]
        publisher = record["publisher"]
        registry._kernel(publisher)
        require(
            _argv(publisher["pid"])
            == guard.policy["source_arguments"]["publisher_argv"],
            "native actual publisher argv differs",
        )
        if guard.policy["origin"] == "installed-manager":
            require(
                record["manager_source_sha256"] == manager_source_digests(),
                "actual installed Manager source differs",
            )
            raw = _ref(self.handoff["raw"])
            require(
                json.loads(raw)
                == {k: v for k, v in record.items() if k != "binding_sha256"}
                and sha(raw) == record["binding_sha256"],
                "original authenticated Manager handoff wire differs",
            )
        else:
            require(
                self.handoff.get("origin") == "host-baseline"
                and "manager_source_sha256" not in record,
                "baseline cannot impersonate Manager handoff",
            )
            argv = _argv(publisher["pid"])
            require(
                "--disable-ecpa-manager" in argv
                and ("--manual-hooks" in argv) != ("--enable-entrypoints" in argv),
                "actual baseline activation flags differ",
            )
        environment = record["environment"]
        require(
            environment["VLLM_ECPA_PLAN_ID"]
            == launch["native_plan_id"]
            == enrollment["native_plan_id"]
            and environment["VLLM_ECPA_LAUNCH_ID"] == enrollment["native_launch_id"],
            "native enrollment Plan/launch differs",
        )
        _semantic_context(enrollment["semantic_context"], launch)
        require(
            set(self.roster) == set(self.kernels) and "api-server/0" in self.kernels,
            "actual source guard kernel roster differs",
        )
        api = self.kernels["api-server/0"]["pid"]
        require(
            (
                pair._parent(api) == publisher["pid"]
                if guard.policy["origin"] == "installed-manager"
                else pair._descendant(api, publisher["pid"])
            ),
            "actual native API is not owned by declared publisher",
        )
        peers = enrollment["source_peers"]
        require(
            len(peers) == 3
            and {f"{p['process']['role']}/{p['process']['ordinal']}" for p in peers}
            == {"api-server/0", "worker/0", "worker/1"},
            "native actual API/TP2 sender membership differs",
        )
        for row in peers:
            process = row["process"]
            slot = f"{process['role']}/{process['ordinal']}"
            require(
                slot in self.roster
                and all(process.get(k) == v for k, v in self.roster[slot].items())
                and {k: process[k] for k in registry.KERNEL} == self.kernels[slot],
                "native sender kernel/Host role differs",
            )
        for slot, process in self.roster.items():
            kernel = self.kernels[slot]
            registry._kernel(kernel)
            require(
                pair._descendant(kernel["pid"], api)
                and process.get("assignment_source") == "host"
                and process["pid"] == kernel["pid"]
                and process["start_identity"]
                == f"pid:{kernel['pid']}:start_ticks:{kernel['start_ticks']}",
                "native actual role/kernel/ancestry differs",
            )
            actual_env = _environment(kernel["pid"])
            require(
                all(
                    actual_env.get(env.encode()) == str(launch[k]).encode()
                    for env, k in zip(ENV_CONTEXT, CONTEXT, strict=True)
                ),
                "actual native process semantic environment differs",
            )
        descriptor = self.handoff["host_evidence"]
        require(
            str(self.host_journal) == descriptor["path"],
            "native original Host evidence endpoint differs",
        )
        info = self.host_journal.lstat()
        require(
            [info.st_dev, info.st_ino, info.st_uid] == descriptor["identity"]
            and info.st_mode & 0o777 == 0o600,
            "native original Host evidence inode/mode differs",
        )
        raw = pair._regular(self.host_journal)
        required = {
            (KV, f"{b['role']}/{ordinal}")
            for b in invocations
            for ordinal in b["required_ordinals"]
        }
        if guard.paired:
            required.update(
                (PROFILER, f"{r}/{n}") for r, ns in PROFILER_SLOTS.items() for n in ns
            )
        seen = set()
        require(raw and raw.endswith(b"\n"), "native original Host journal incomplete")
        for line in raw.splitlines():
            event = host_evidence.parse_host_event(line)
            require(
                event["plan_id"] == enrollment["native_plan_id"]
                and event["launch_id"] == enrollment["native_launch_id"],
                "native Host original event from another Plan/launch",
            )
            process = event["process"]
            slot = f"{process['role']}/{process['ordinal']}"
            ep = event["entry_point"]
            extension = next(
                (
                    e
                    for e, target in pair.ENTRIES.items()
                    if (ep["group"], ep["name"], ep["value"]) == target
                ),
                None,
            )
            if (
                (extension, slot) in required
                and event["event"] == "invoked"
                and event["observation_kind"] == "loader_lifecycle"
            ):
                require(
                    process == self.roster[slot],
                    "native original loader Host epoch changed",
                )
                seen.add((extension, slot))
        require(
            seen == required, "native actual per-plugin/role loader coverage incomplete"
        )
        for kernel in self.kernels.values():
            registry._kernel(kernel)
            require(
                pair._descendant(kernel["pid"], api),
                "native actual process ancestry changed",
            )
        registry._kernel(publisher)
        after = self.host_journal.lstat()
        require(
            [after.st_dev, after.st_ino, after.st_uid] == descriptor["identity"]
            and after.st_mode & 0o777 == 0o600,
            "native original Host journal replaced",
        )
        return _SourceSnapshot(self, raw, plan.plan_id, enrollment["native_launch_id"])

    def verify_request_current(
        self,
        enrollment,
        host_journal,
        *,
        runtime_request_id,
        transaction_id,
        native_report,
    ):
        from experiments.formal_campaign.h3_native_verifier import (
            require_verified_native_request,
        )

        verified = require_verified_native_request(native_report)
        snapshot = self.validate_current(enrollment, host_journal)
        require(
            verified.runtime_request_id == runtime_request_id
            and verified.transaction_id == transaction_id
            and verified.native_plan_id == snapshot.plan_id.rsplit(":", 1)[-1]
            and verified.native_launch_id == snapshot.native_launch_id,
            (
                "consumed original full-native proof belongs to another "
                "request/Plan/launch"
            ),
        )
        if self.guard.paired:
            occurrence = sha(("request_finished\0" + runtime_request_id).encode())
            callbacks = [
                host_evidence.parse_host_event(line)
                for line in snapshot._raw.splitlines()
            ]
            require(
                any(
                    e["event"] == "effective"
                    and e["observation_kind"] == "runtime_effective"
                    and e["detail"] == "request-lifecycle-eventbus:request_finished"
                    and e["occurrence_id"] == occurrence
                    and tuple(e["entry_point"][k] for k in ("group", "name", "value"))
                    == pair.ENTRIES[PROFILER]
                    and e["process"]
                    == self.roster.get(
                        f"{e['process']['role']}/{e['process']['ordinal']}"
                    )
                    for e in callbacks
                ),
                "native actual pair lacks original profiler finished callback",
            )
        return snapshot


def build_native_plan_guard(**arguments):
    """No launch, signals, fabricated receipts or public route authority."""
    return NativePlanGuard(**arguments)
