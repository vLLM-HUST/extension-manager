"""Fresh two-MOD source/Plan/Host joins for the native carrier.

No permit from the legacy singleton issuer is normalized or re-signed here.
A successful join is an input to the external carrier, never a public-route
capability by itself. Original full-prefix native verification stays mandatory.
"""

from __future__ import annotations

import copy
import hashlib
import json
import stat
import zipfile
from pathlib import Path

from experiments.formal_campaign import source_provenance
from experiments.native_attention_candidate import live_route_reader as routes
from experiments.native_attention_candidate import request_drain_consumer as native
from experiments.native_attention_candidate import (
    semantic_producer_registry as registry,
)
from vllm_hust_ext import host_evidence, semantic_runtime_binding

from .binding import IDS, KV, PROFILER, compile_pair_plan, require

SCHEMA = "ecpa-real-kv-profiler-source-inputs/v1"
ENTRIES = {
    KV: (
        "vllm.general_plugins",
        "ascend_kvcompress",
        "vllm_ascend_kvcompress.plugin:register",
    ),
    PROFILER: (
        "vllm.general_plugins",
        "request_lifecycle_profiler",
        "vllm_request_lifecycle_profiler.plugin:register_plugin",
    ),
}
DISTRIBUTIONS = {
    KV: "vllm-ascend-kvcompress-hust",
    PROFILER: "vllm-request-lifecycle-profiler-plugin",
}


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _regular(path):
    path = Path(path)
    require(
        path.is_absolute() and path.resolve() == path,
        "pair source path is not canonical",
    )
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "pair source is not regular")
    raw = path.read_bytes()
    after = path.lstat()
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        "pair source changed while read",
    )
    return raw


def audit_pair_inputs(native_inputs, wheels, *, plugin_commits, bundles):
    """Extend, never rewrite, the independently audited seven-wheel KV input.

    This function hashes each wheel and verifies actual installed payloads in
    the executing interpreter. Its caller must independently trust its output.
    """
    require(
        set(wheels) == IDS and set(plugin_commits) == IDS,
        "both exact pair source identities required",
    )
    require(
        native_inputs["schema"] == routes.SCHEMA
        and native_inputs["formal_result"] is False,
        "original native input audit required",
    )
    require(
        set(native_inputs["wheel_sha256"]) == set(routes.DISTRIBUTIONS),
        "original seven-wheel audit required",
    )
    require(
        native_inputs["wheel_revisions"]["mod"] == plugin_commits[KV],
        "KV source differs from original audit",
    )
    require(
        native_inputs["wheel_sha256"]["mod"] == wheels[KV]["sha256"],
        "KV wheel differs from original audit",
    )
    require(
        len(bundles) == 2 and {b.bundle_id for b in bundles} == IDS,
        "actual pair bundles missing",
    )
    _, snapshots = semantic_runtime_binding.installed_plugin_identities(bundles)
    snapshots = {s["bundle_id"]: s for s in snapshots}
    routes._check_file_states(native_inputs["file_state"])
    states, payloads = {}, {}
    protocol_paths = sorted(Path(__file__).parent.glob("*.py"))
    protocol = routes._inventory(
        [
            {"path": str(p.resolve()), "sha256": sha(_regular(p.resolve()))}
            for p in protocol_paths
        ],
        states,
    )
    for extension in sorted(IDS):
        wheel = wheels[extension]
        require(
            wheel["revision"] == plugin_commits[extension],
            "pair source commit/wheel revision differs",
        )
        require(
            sha(_regular(wheel["path"])) == wheel["sha256"], "pair wheel bytes differ"
        )
        payloads[extension] = routes._installed_payload(
            wheel, DISTRIBUTIONS[extension], states
        )
        # Include manifest, entry points and other non-code static payload too;
        # the original generic runtime checker intentionally covers code/ELFs.
        with zipfile.ZipFile(wheel["path"]) as archive:
            for row in snapshots[extension]["files"]:
                require(
                    row["path"] in archive.namelist(),
                    "installed pair static payload absent from wheel",
                )
                original = archive.read(row["path"])
                require(
                    len(original) == row["size"] and sha(original) == row["sha256"],
                    "installed pair manifest/static metadata differs from wheel",
                )
    routes._check_file_states(native_inputs["file_state"])
    routes._check_file_states(states)
    return {
        "schema": SCHEMA,
        "native_inputs": copy.deepcopy(native_inputs),
        "native_inputs_sha256": sha(canonical(native_inputs)),
        "plugin_commits": copy.deepcopy(plugin_commits),
        "wheels": copy.deepcopy(wheels),
        "protocol_sources": protocol,
        "installed_payloads": payloads,
        "installed_bundle_snapshots": snapshots,
        "file_state": states,
        "formal_result": False,
    }


def _parent(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    require(fields[0] != "Z", "pair process is a zombie")
    return int(fields[1])


def _descendant(pid, ancestor):
    seen = set()
    while pid > 1 and pid not in seen:
        if pid == ancestor:
            return True
        seen.add(pid)
        pid = _parent(pid)
    return False


def verify_pair_host_events(raw, *, plan_id, launch_id, roster, required_slots):
    """Pure exact per-extension × role coverage; live kernels checked by owner.

    `roster` maps original Host slot names to its original process object. A
    loader invocation from one MOD never fills the other's slot. Effective
    observations are not admitted as loader invocations.
    """
    require(raw and raw.endswith(b"\n"), "original pair Host journal incomplete")
    require(set(required_slots) == IDS, "each pair member requires its own roster")
    expected = {
        (extension, slot)
        for extension, slots in required_slots.items()
        for slot in slots
    }
    require(
        expected and all(slot in roster for _, slot in expected),
        "pair roster lacks required original slot",
    )
    coverage, parsed = {}, []
    for line in raw.splitlines():
        event = host_evidence.parse_host_event(line)
        require(
            event["plan_id"] == plan_id and event["launch_id"] == launch_id,
            "pair Host event belongs to another Plan/launch",
        )
        parsed.append(event)
        process = event["process"]
        slot = f"{process['role']}/{process['ordinal']}"
        entry = event["entry_point"]
        identity = (entry["group"], entry["name"], entry["value"])
        extension = next(
            (key for key, value in ENTRIES.items() if identity == value), None
        )
        if (extension, slot) not in expected:
            continue
        require(
            process == roster[slot] and process.get("assignment_source") == "host",
            "pair Host process differs from original kernel roster",
        )
        if (
            event["event"] == "invoked"
            and event["observation_kind"] == "loader_lifecycle"
        ):
            coverage[(extension, slot)] = event["event_id"]
    require(
        set(coverage) == expected,
        "both MODs lack exact original loader invocation coverage",
    )
    return coverage, parsed


class _HostSnapshot:
    __slots__ = ("_owner", "_raw", "_report")

    def __init__(self, owner, raw, report):
        self._owner, self._raw, self._report = owner, raw, report


def required_pair_slots(profiler_slots):
    return {
        KV: ["worker/0", "worker/1"],
        PROFILER: sorted(f"{r}/{n}" for r, ns in profiler_slots.items() for n in ns),
    }


class PairSourceAuthority:
    """Independent source/input trust plus fresh installed/Host/native joins.

    The carrier supplies original independently authenticated Manager handoff
    and Host sink descriptor, and must keep its original traffic gate, leases,
    completion clock, one-use consume and response release. This object cannot
    mint, extend or replace any of those capabilities.
    """

    def __init__(
        self,
        *,
        bundles,
        trusted_source_observations,
        trusted_pair_inputs,
        trusted_manager_handoffs,
        trusted_kv_base_plan_ids,
        trusted_kv_contract_sha256,
    ):
        require(
            len(bundles) == 2 and {b.bundle_id for b in bundles} == IDS,
            "actual pair bundles missing",
        )
        require(
            trusted_source_observations
            and trusted_pair_inputs
            and trusted_manager_handoffs
            and trusted_kv_base_plan_ids
            and trusted_kv_contract_sha256,
            "independent pair/source/Manager trust missing",
        )
        self.bundles = tuple(bundles)
        self.sources = frozenset(trusted_source_observations)
        self.inputs = frozenset(trusted_pair_inputs)
        self.managers = frozenset(trusted_manager_handoffs)
        self.kv_base_plans = frozenset(trusted_kv_base_plan_ids)
        self.kv_contracts = frozenset(trusted_kv_contract_sha256)

    def source_current(
        self,
        pair_inputs,
        *,
        launch_spec_path,
        fixed,
        policy,
        observation,
        original_kv_base,
        kv_contract,
        profiler_slots,
    ):
        require(
            sha(canonical(pair_inputs)) in self.inputs,
            "pair input audit is not independently trusted",
        )
        require(
            pair_inputs["schema"] == SCHEMA and pair_inputs["formal_result"] is False,
            "pair input schema differs",
        )
        require(
            source_provenance.digest(canonical(observation)) in self.sources,
            "pair source observation is not independently trusted",
        )
        source_provenance.validate_observation(observation, policy, fixed)
        require(
            fixed["plugin_commits"] == pair_inputs["plugin_commits"]
            and set(fixed["plugin_commits"]) == IDS,
            "all actual pair sources must be admitted",
        )
        revisions = pair_inputs["native_inputs"]["wheel_revisions"]
        require(
            revisions["manager"] == fixed["manager_commit"]
            and revisions["host"] == fixed["host_commit"]
            and revisions["ascend"] == fixed["accelerator_commit"],
            "pair source and original native runtime revisions differ",
        )
        # Full installed snapshots are recomputed by the original launch parser.
        launch = semantic_runtime_binding.validate_semantic_launch_spec(
            launch_spec_path, self.bundles
        )
        before = sha(canonical(pair_inputs))
        observed = audit_pair_inputs(
            pair_inputs["native_inputs"],
            pair_inputs["wheels"],
            plugin_commits=pair_inputs["plugin_commits"],
            bundles=self.bundles,
        )
        require(
            observed == pair_inputs and before == sha(canonical(pair_inputs)),
            "current pair payload or native inputs differ",
        )
        require(
            original_kv_base.plan_id in self.kv_base_plans,
            "original KV base Plan is not independently trusted",
        )
        require(
            sha(canonical(kv_contract)) in self.kv_contracts,
            "original KV semantic contract is not independently trusted",
        )
        expected_base, expected_plan, expected_native, _ = compile_pair_plan(
            original_kv_base, self.bundles, kv_contract, profiler_slots=profiler_slots
        )
        from vllm_hust_ext.plan_artifact import parse_plan_artifact

        require(
            parse_plan_artifact(_regular(launch["base_plan"]["path"])) == expected_base,
            "pair base Plan dropped original KV or profiler obligations",
        )
        require(
            parse_plan_artifact(_regular(launch["plan"]["path"])) == expected_plan,
            "pair Plan differs from both actual plugin obligations",
        )
        require(
            json.loads(_regular(launch["binding"]["path"])) == expected_native,
            "pair native semantic binding differs",
        )
        return launch

    def host_current(self, handoff, *, launch, roster, kernels, required_slots):
        require(
            sha(canonical(handoff)) in self.managers,
            "Manager handoff is not independently trusted",
        )
        require(set(roster) == set(kernels), "pair Host kernel roster differs")
        manager = handoff["record"]["publisher"]
        registry._kernel(manager)
        require("api-server/0" in kernels, "original pair API process is missing")
        api_pid = kernels["api-server/0"]["pid"]
        require(
            _parent(api_pid) == manager["pid"],
            "actual pair API is not Manager's supervised child",
        )
        for kernel in kernels.values():
            registry._kernel(kernel)
            require(
                _descendant(kernel["pid"], api_pid),
                "pair process belongs to another Host tree",
            )
        descriptor = handoff["host_evidence"]
        path = Path(descriptor["path"])
        info = path.lstat()
        require(
            [info.st_dev, info.st_ino, info.st_uid] == descriptor["identity"]
            and stat.S_IMODE(info.st_mode) == 0o600,
            "original Manager Host sink identity differs",
        )
        require(
            handoff["record"]["environment"]["VLLM_ECPA_PLAN_ID"]
            == launch["native_plan_id"],
            "Manager handoff uses another pair Plan",
        )
        for slot, process in roster.items():
            kernel = kernels[slot]
            require(
                process["pid"] == kernel["pid"]
                and process["start_identity"]
                == f"pid:{kernel['pid']}:start_ticks:{kernel['start_ticks']}",
                "pair Host process/kernel epoch differs",
            )
        raw = _regular(path)
        coverage, _ = verify_pair_host_events(
            raw,
            plan_id=launch["native_plan_id"],
            launch_id=handoff["record"]["environment"]["VLLM_ECPA_LAUNCH_ID"],
            roster=roster,
            required_slots=required_slots,
        )
        for kernel in kernels.values():
            registry._kernel(kernel)
            require(
                _descendant(kernel["pid"], api_pid),
                "pair process ancestry changed during read",
            )
        registry._kernel(manager)
        after = path.lstat()
        require(
            [after.st_dev, after.st_ino, after.st_uid] == descriptor["identity"]
            and stat.S_IMODE(after.st_mode) == 0o600,
            "pair Host sink replaced",
        )
        return _HostSnapshot(
            self,
            raw,
            {
                "host_prefix_sha256": sha(raw),
                "host_prefix_bytes": len(raw),
                "loader_coverage": [
                    {"extension_id": e, "slot": s, "event_id": v}
                    for (e, s), v in sorted(coverage.items())
                ],
                "formal_result": False,
            },
        )

    def verify_native_request(
        self,
        recipe,
        phase_id,
        output,
        *,
        descriptor,
        spec_path,
        journal_path,
        policy_path,
        drain_policy_path,
    ):
        """No caller-provided verdict: run the original full global consumer."""
        return native.verify_observation(
            recipe,
            phase_id,
            output,
            descriptor=descriptor,
            spec_path=spec_path,
            journal_path=journal_path,
            policy_path=policy_path,
            drain_policy_path=drain_policy_path,
        )

    def verify_profiler_finished(
        self, snapshot, *, runtime_request_id, plan_id, launch_id, roster
    ):
        require(
            type(snapshot) is _HostSnapshot and snapshot._owner is self,
            "original authority-owned Host snapshot required",
        )
        raw = snapshot._raw
        require(
            type(runtime_request_id) is str and runtime_request_id,
            "actual native runtime request missing",
        )
        require(raw and raw.endswith(b"\n"), "original callback prefix incomplete")
        occurrence = sha(("request_finished\0" + runtime_request_id).encode())
        matched = []
        for line in raw.splitlines():
            event = host_evidence.parse_host_event(line)
            require(
                event["plan_id"] == plan_id and event["launch_id"] == launch_id,
                "callback belongs to another Plan/launch",
            )
            process, entry = event["process"], event["entry_point"]
            slot = f"{process['role']}/{process['ordinal']}"
            if (entry["group"], entry["name"], entry["value"]) != ENTRIES[PROFILER]:
                continue
            if (
                event["event"] != "effective"
                or event["observation_kind"] != "runtime_effective"
            ):
                continue
            if event["occurrence_id"] != occurrence:
                continue
            require(
                slot in roster
                and process == roster[slot]
                and process.get("assignment_source") == "host",
                "callback original process not enrolled",
            )
            require(
                event["detail"] == "request-lifecycle-eventbus:request_finished",
                "profiler callback kind differs",
            )
            matched.append(event["event_id"])
        require(
            matched, "no original finished callback for actual native runtime request"
        )
        return {
            "runtime_request_id": runtime_request_id,
            "callback_event_ids": matched,
            "event": "effective",
            "observation_kind": "runtime_effective",
            "formal_result": False,
            "public_route_authorized": False,
        }

    def verify_request_pair(
        self,
        pair_inputs,
        *,
        source_arguments,
        handoff,
        roster,
        kernels,
        required_slots,
        recipe,
        phase_id,
        output,
        descriptor,
        spec_path,
        journal_path,
        policy_path,
        drain_policy_path,
    ):
        """Full KV consumer AND independently captured original profiler callback.

        No caller runtime request id or successful-consumer verdict is accepted.
        This observation must still pass the carrier's original clock, lease,
        generation, membership and one-use public response release checks.
        """
        require(
            required_slots == required_pair_slots(source_arguments["profiler_slots"]),
            "pair coverage differs from compiled individual obligations",
        )
        launch = self.source_current(pair_inputs, **source_arguments)
        self.host_current(
            handoff,
            launch=launch,
            roster=roster,
            kernels=kernels,
            required_slots=required_slots,
        )
        observed = self.verify_native_request(
            recipe,
            phase_id,
            output,
            descriptor=descriptor,
            spec_path=spec_path,
            journal_path=journal_path,
            policy_path=policy_path,
            drain_policy_path=drain_policy_path,
        )
        snapshot = self.host_current(
            handoff,
            launch=launch,
            roster=roster,
            kernels=kernels,
            required_slots=required_slots,
        )
        callback = self.verify_profiler_finished(
            snapshot,
            runtime_request_id=observed["runtime_request_id"],
            plan_id=launch["native_plan_id"],
            launch_id=handoff["record"]["environment"]["VLLM_ECPA_LAUNCH_ID"],
            roster=roster,
        )
        require(
            self.source_current(pair_inputs, **source_arguments) == launch,
            "pair deployment changed during request verification",
        )
        return {
            "schema": "ecpa-real-kv-profiler-request-observation/v1",
            "native": observed,
            "profiler_finished": callback,
            "host": snapshot._report,
            "formal_result": False,
            "public_route_authorized": False,
        }


class PairEpochGuard:
    """Native carrier adapter: always fresh source + each-entry Host roster join.

    Captured handoff must already be independently trusted by PairSourceAuthority.
    Enrollment's original role/epoch objects are compared without normalizing.
    The caller retains its own generation, membership, lease and clock checks.
    """

    def __init__(
        self,
        authority,
        *,
        pair_inputs,
        source_arguments,
        handoff,
        roster,
        kernels,
        required_slots,
    ):
        require(
            type(authority) is PairSourceAuthority,
            "source-owned pair authority required",
        )
        self.authority = authority
        self.pair_inputs = copy.deepcopy(pair_inputs)
        self.source_arguments = source_arguments
        self.handoff = copy.deepcopy(handoff)
        self.roster = copy.deepcopy(roster)
        self.kernels = copy.deepcopy(kernels)
        require(
            required_slots == required_pair_slots(source_arguments["profiler_slots"]),
            "pair coverage differs from compiled individual obligations",
        )
        self.required_slots = copy.deepcopy(required_slots)

    def validate_current(self, enrollment, host_journal):
        require(
            str(host_journal) == self.handoff["host_evidence"]["path"],
            "native carrier supplied another Host journal",
        )
        peers = enrollment["source_peers"]
        for row in peers:
            process = row["process"]
            slot = f"{process['role']}/{process['ordinal']}"
            require(
                slot in self.roster
                and all(process.get(k) == v for k, v in self.roster[slot].items()),
                "native enrollment differs from original pair Host roster",
            )
            require(
                {key: process[key] for key in registry.KERNEL} == self.kernels[slot],
                "native pair kernel membership differs",
            )
        require(
            len(peers) == 3
            and {
                f"{row['process']['role']}/{row['process']['ordinal']}" for row in peers
            }
            == {"api-server/0", "worker/0", "worker/1"},
            "actual native TP2/API sender roster incomplete",
        )
        launch = self.authority.source_current(
            self.pair_inputs, **self.source_arguments
        )
        return self.authority.host_current(
            self.handoff,
            launch=launch,
            roster=self.roster,
            kernels=self.kernels,
            required_slots=self.required_slots,
        )
