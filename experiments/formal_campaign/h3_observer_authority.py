"""Native private-routing authority, distinct from invoked-only admission.

The static guard is reconstructed from independently issued source inputs.
Enrollment retains all original kernel/listener/lease/CAS predicates; native
completion is checked per request and never inferred from source readiness.
"""

from __future__ import annotations

import json
from pathlib import Path

from experiments.formal_campaign.h3_dynamic_authority import (
    DynamicAuthority,
    DynamicJournal,
    canonical,
    check_ref,
    digest,
    require,
)
from experiments.formal_campaign.h3_native_verifier import NativeEpochVerifier

PROFILE = "ecpa-h3-source-owned-observer-private-route/v1"
JOURNAL = "ecpa-h3-observer-authority-journal/v1"


def observed_host_kernel(process):
    """Bind untouched Host role fields to a separately observed current kernel."""
    from experiments.formal_campaign.h3_worker_relaunch import identity

    kernel = identity(process["pid"])
    require(
        process.get("assignment_source") == "host"
        and process["start_identity"]
        == f"pid:{kernel['pid']}:start_ticks:{kernel['start_ticks']}",
        "original Host role start identity differs from actual kernel",
    )
    return kernel


def native_host_roster(records, plan_id, launch_id):
    """Join provisional discovery to later immutable Host role assignments.

    Environment unknown/0 is not a Host slot. Retain every original process
    object, and require every such provisional row to have a later exact-epoch
    Host binding; never select the last of conflicting assigned identities.
    """
    roster = {}
    bound_epochs = {}
    provisional = []
    for event in records:
        if event["plan_id"] != plan_id or event["launch_id"] != launch_id:
            continue
        process = event["process"]
        # Role/ordinal/assignment change when Host binds the process. Every
        # remaining field (including host/PID/start_identity/process_epoch) must
        # match exactly, with canonical JSON preserving scalar types.
        epoch = canonical(
            {
                key: value
                for key, value in process.items()
                if key not in {"role", "ordinal", "assignment_source"}
            }
        )
        if process.get("assignment_source") == "environment":
            require(
                process["role"] == "unknown"
                and event["event"] in {"discovered", "resolved"}
                and event["observation_kind"] == "loader_lifecycle",
                "native provisional Host row is not pre-assignment discovery",
            )
            provisional.append((epoch, event["observed_at_ns"]))
            continue
        require(
            process.get("assignment_source") == "host" and process["role"] != "unknown",
            "native role requires a concrete Host assignment",
        )
        slot = f"{process['role']}/{process['ordinal']}"
        require(
            slot not in roster or canonical(roster[slot]) == canonical(process),
            "native Host role kernel changed",
        )
        previous = bound_epochs.get(epoch)
        require(
            previous is None or previous[0] == slot,
            "native Host process epoch assigned multiple roles",
        )
        # Preserve the original process object. This is not a rewritten event.
        roster.setdefault(slot, process)
        latest = event["observed_at_ns"]
        if previous is not None:
            latest = max(latest, previous[1])
        bound_epochs[epoch] = (slot, latest)
    for epoch, observed_at_ns in provisional:
        require(
            epoch in bound_epochs and bound_epochs[epoch][1] > observed_at_ns,
            "native provisional Host process lacks a later exact-epoch assignment",
        )
    return roster


def verify_native_membership(source_peers, members, plan_id, launch_id):
    """Join untouched Host events and fresh kernel identities to exact senders.

    Host process objects have seven fields; the collector sender ABI adds the
    independently observed kernel fields. Neither object is projected to a
    subset, and no original Host event is rewritten.
    """
    from vllm_hust_ext.host_evidence import parse_host_event

    expected_slots = {"api-server/0", "worker/0", "worker/1"}
    require(
        len(source_peers) == len(members) == 3,
        "native peer roster requires exactly three members and senders",
    )
    events = [parse_host_event(canonical(member["event"])) for member in members]
    require(
        all(e["plan_id"] == plan_id and e["launch_id"] == launch_id for e in events),
        "native membership Plan/launch differs",
    )
    roster = native_host_roster(events, plan_id, launch_id)
    require(set(roster) == expected_slots, "native membership slots differ")
    expected = {}
    kernels = set()
    for member, event in zip(members, events, strict=True):
        process = event["process"]
        slot = f"{process['role']}/{process['ordinal']}"
        require(
            canonical([member["role"], member["ordinal"]])
            == canonical([process["role"], process["ordinal"]])
            and slot not in expected,
            "native membership slot is duplicated or differs from Host role",
        )
        kernel = observed_host_kernel(process)
        require(
            canonical(member["identity"])
            == canonical({**kernel, "launch_id": launch_id}),
            "native membership identity differs from current kernel/launch",
        )
        kernel_key = canonical(kernel)
        require(kernel_key not in kernels, "native membership kernels alias")
        kernels.add(kernel_key)
        expected[slot] = {**process, **kernel}
    seen = set()
    for peer in source_peers:
        process = peer["process"]
        slot = f"{process['role']}/{process['ordinal']}"
        require(
            slot in expected
            and slot not in seen
            and canonical(process) == canonical(expected[slot]),
            "native sender differs from exact Host role plus current kernel",
        )
        seen.add(slot)
    require(seen == expected_slots, "native sender slots are incomplete")


class NativeJournal(DynamicJournal):
    schema = JOURNAL


class NativeAuthority(DynamicAuthority):
    """Construct with actual source guard objects, never a JSON success carrier."""

    def __init__(self, policy, journal, *, plan_guards):
        require(len(plan_guards) == 2, "both original and replacement Plans required")
        from experiments.formal_campaign.h3_native_plan_guard import NativePlanGuard

        require(
            all(type(g) is NativePlanGuard for g in plan_guards),
            "source-owned native Plan guards required",
        )
        self.native_plan_guards = tuple(plan_guards)
        self.native_epochs = {}
        self.bound_client = None
        super().__init__(policy, journal)

    @staticmethod
    def policy_validator(policy):
        from jsonschema import Draft7Validator

        schema_path = Path(__file__).parent / "h3-observer-policy.schema.json"
        Draft7Validator(json.loads(schema_path.read_bytes())).validate(policy)
        required = {
            "schema",
            "start_id",
            "registration_sha256",
            "static_deployment_sha256",
            "grant",
            "backend_endpoint",
            "model",
            "worker_ordinals",
            "source_refs",
            "plan_artifacts",
            "host_evidence_paths",
            "host_evidence_roots",
            "api_argv",
            "native_plan_bindings",
        }
        require(
            set(policy) == required
            and policy["schema"] == "ecpa-h3-observer-static-policy/v1"
            and policy["worker_ordinals"] == [0, 1],
            "native policy domain/fields differ",
        )
        require(
            policy["host_evidence_paths"] or policy["host_evidence_roots"],
            "source-owned native Host journal scope missing",
        )
        for ref in policy["source_refs"] + policy["plan_artifacts"]:
            check_ref(ref)

    def make_binding_guards(self, policy):
        return []

    def _source_current(self):
        for ref in self.policy["source_refs"] + self.policy["plan_artifacts"]:
            check_ref(ref)
        plans = [guard.verify_plan_current()[0] for guard in self.native_plan_guards]
        for plan in plans:
            require(
                any(
                    binding
                    == {
                        "execution_plan_id": plan.plan_id,
                        "runtime_plan_id": plan.plan_id.rsplit(":", 1)[-1],
                    }
                    for binding in self.policy["native_plan_bindings"]
                ),
                "full native Plan is not exactly bound to static intent",
            )

    def _plan_and_obligations(self, enrollment):
        bound = self._epoch(enrollment)
        bound["guard"].validate_current(
            bound["native_enrollment"], bound["host_journal"]
        )
        # This means source/loader prepared for private forwarding. It does not
        # discharge native runtime obligations or release a public response.
        return digest(
            canonical(
                {
                    "state": "native-source-prepared-private-only",
                    "enrollment_sha256": enrollment["sha256"],
                }
            )
        )

    def _epoch(self, enrollment):
        value = self.native_epochs.get(enrollment["sha256"])
        require(value is not None, "actual native bootstrap/guard not bound")
        return value

    def attach_actual_epoch(
        self,
        enrollment_sha256,
        *,
        native_enrollment,
        handoff,
        roster,
        kernels,
        host_journal,
        descriptor,
        spec_path,
        policy_path,
        drain_path,
        socket_path,
        journal_path,
        snapshots,
    ):
        """Called by the independent post-Popen enrollment owner under its fence.

        All kernel identities and bootstrap descriptor already exist. This never
        guesses a future process or edits the static deployment policy.
        """
        with self.lock:
            self._lease()
            require(
                self.route.generation is None
                and self.enrollment is not None
                and self.enrollment["sha256"] == enrollment_sha256,
                "close-before-native-attach or enrollment fence differs",
            )
            self._observe_members(self.enrollment["members"])
            self.observe_backend(self.candidate[1])
            require(
                native_enrollment["native_plan_id"] == self.enrollment["plan_id"]
                and native_enrollment["native_launch_id"]
                == self.enrollment["launch_id"],
                "native context differs from actual enrolled epoch",
            )
            source_peers = native_enrollment["source_peers"]
            verify_native_membership(
                source_peers,
                self.enrollment["members"],
                self.enrollment["plan_id"],
                self.enrollment["launch_id"],
            )
            index = self.enrollment["generation"] - 1
            require(index in (0, 1), "original H3 has exactly two actual epochs")
            guard = self.native_plan_guards[index].bind_actual(
                native_enrollment, handoff, roster, kernels, host_journal
            )
            guard.validate_current(native_enrollment, host_journal)
            spec = json.loads(Path(spec_path).read_bytes())
            require(
                spec["senders"] == source_peers
                and spec["native_plan_id"] == native_enrollment["native_plan_id"]
                and spec["native_launch_id"] == native_enrollment["native_launch_id"],
                "collector actual peers/context differ from bound native epoch",
            )
            verifier = NativeEpochVerifier(
                native_spec=spec_path,
                tensor_policy=policy_path,
                drain_policy=drain_path,
                descriptor=descriptor,
                socket_path=socket_path,
                journal_path=journal_path,
                snapshots=snapshots,
            )
            require(
                enrollment_sha256 not in self.native_epochs,
                "native verifier cannot be rebound within one membership",
            )
            self.native_epochs[enrollment_sha256] = {
                "guard": guard,
                "verifier": verifier,
                "native_enrollment": native_enrollment,
                "host_journal": host_journal,
            }
            self._record(
                "native.epoch.attached",
                self.route,
                enrollment_sha256=enrollment_sha256,
                native_plan_id=spec["native_plan_id"],
                native_launch_id=spec["native_launch_id"],
            )

    def native_verifier_for(self, enrollment):
        self._recheck()
        return self._epoch(enrollment)["verifier"]

    def verify_native_request_current(self, enrollment, **fields):
        self._recheck()
        epoch = self._epoch(enrollment)
        epoch["guard"].verify_request_current(
            epoch["native_enrollment"], epoch["host_journal"], **fields
        )
        self._recheck()

    def configure_start(self, *, start, recipe, output):
        self.start = start
        self.recipe = recipe
        self.output = Path(output)
        require(start["start_id"].startswith("observer-loss-r"), "wrong original cell")
        self.collectors = []
        self.observer_bindings = {}
        self.current_observer = None
        self.observer_lost = False
        self.live_scope = None
        self.live_grants = None
        self.live_rebind_attempted = False
        self.live_transport_enrollment = None
        phases = recipe["arms"][start["arm"]]["phases"]
        require(
            all(
                Path(p["native_bootstrap"]["output"]).parent == self.output
                for p in phases
            ),
            "native start output differs from frozen paths",
        )

    def _prepare_actual_epoch(self, index, handoff_ref):
        import os

        from experiments.formal_campaign.h3_native_bootstrap import start_native_epoch
        from experiments.formal_campaign.h3_native_source_scope import (
            scope_native_senders,
        )
        from experiments.formal_campaign.h3_worker_relaunch import identity

        require(
            index in (0, 1)
            and self.enrollment is not None
            and self.enrollment["generation"] == index + 1
            and self.route.generation is None,
            "native prepare actual epoch differs",
        )
        phase = self.recipe["arms"][self.start["arm"]]["phases"][index]
        expected = self.output / f"phase{index}.native-source-handoff.json"
        require(handoff_ref["path"] == str(expected), "native handoff path differs")
        handoff = json.loads(check_ref(handoff_ref).read_bytes())
        publisher = handoff["record"]["publisher"]
        current = identity(publisher["pid"])
        require(
            all(publisher[k] == current[k] for k in current),
            "native publisher kernel differs",
        )
        argv = [
            s.decode()
            for s in Path(f"/proc/{publisher['pid']}/cmdline").read_bytes().split(b"\0")
            if s
        ]
        require(
            argv == phase["argv"],
            "native publisher command differs from registered source",
        )
        records = self._host_records(self.enrollment["launch_id"])
        roster = native_host_roster(
            records, self.enrollment["plan_id"], self.enrollment["launch_id"]
        )
        kernels = {slot: observed_host_kernel(p) for slot, p in roster.items()}
        # Kernel fields follow the original registry. Host process_epoch remains
        # in the original role object, with no role or identity rewriting.
        bootstrap = phase["native_bootstrap"]
        sources = bootstrap["source_files"]
        peers = []
        for member in self.enrollment["members"]:
            original_process = member["event"]["process"]
            slot = f"{original_process['role']}/{original_process['ordinal']}"
            kernel = observed_host_kernel(original_process)
            require(
                original_process == roster[slot] and kernel == kernels[slot],
                "native sender original Host role/kernel differs from roster",
            )
            # The collector's existing sender ABI is the original Host process
            # plus independently observed kernel fields, never a rewritten event.
            process = {**original_process, **kernel}
            status = Path(f"/proc/{process['pid']}/status").read_text().splitlines()
            uid = int(next(s for s in status if s.startswith("Uid:")).split()[2])
            gid = int(next(s for s in status if s.startswith("Gid:")).split()[2])
            require(
                uid == os.getuid() and gid == os.getgid(),
                "native peer credentials differ",
            )
            peers.append(
                {
                    "process": process,
                    "peer_uid": uid,
                    "peer_gid": gid,
                    "cmdline_sha256": __import__("hashlib")
                    .sha256(Path(f"/proc/{process['pid']}/cmdline").read_bytes())
                    .hexdigest(),
                    "source_files": sources,
                }
            )
        peers, sources = scope_native_senders(peers, sources)
        guard = self.native_plan_guards[index]
        guard.handoffs.add(__import__("hashlib").sha256(canonical(handoff)).hexdigest())
        launch = json.loads(check_ref(phase["semantic_launch_spec"]).read_bytes())
        native_enrollment = {
            "native_plan_id": self.enrollment["plan_id"],
            "native_launch_id": self.enrollment["launch_id"],
            "source_peers": peers,
            "semantic_context": {
                k: launch[k]
                for k in (
                    "execution_plan_id",
                    "controller_instance",
                    "candidate_generation",
                    "membership_epoch",
                )
            },
        }
        bound = guard.bind_actual(
            native_enrollment,
            handoff,
            roster,
            kernels,
            handoff["host_evidence"]["path"],
        )
        bound.validate_current(native_enrollment, handoff["host_evidence"]["path"])
        initializer = None
        if self.live_scope is not None:
            require(index == 0, "live observer continuation cannot relaunch Host phase1")
            from experiments.formal_campaign.h3_observer_live_launcher import LiveGrants
            self.live_grants = LiveGrants(self, self.live_scope)
            initializer = self.live_grants.before_publication
        process, descriptor = start_native_epoch(
            output=bootstrap["output"],
            senders=peers,
            phases=bootstrap["phases"],
            native_plan_id=native_enrollment["native_plan_id"],
            native_launch_id=native_enrollment["native_launch_id"],
            kv_requirements=bootstrap["kv_requirements"],
            tensor_requirements=bootstrap["tensor_requirements"],
            native_context_path=bootstrap["native_context_path"],
            tensor_context_path=bootstrap["tensor_context_path"],
            source_files=sources,
            _before_context_publication=initializer,
        )
        self.collectors.append(process)
        if self.live_grants is not None:
            marker = json.loads((self.output / "phase0.launch-observation.json").read_bytes())
            self.live_grants.wait_actual_endpoints(marker["launched_monotonic_ns"] +
                int(self.live_scope.value()["original"]["probe"]["ready_timeout_s"] * 1e9))
        from experiments.formal_campaign import h3_native_collector
        from experiments.formal_campaign.h3_observer_loss import binding

        bound = binding(
            process,
            descriptor,
            authority=identity(os.getpid()),
            start_id=self.start["start_id"],
            enrollment=self.enrollment["sha256"],
            phase_index=index,
            collector_source=Path(h3_native_collector.__file__).resolve(),
            collector_argv=process.args,
        )
        with self.lock:
            if index == 1:
                require(
                    self.observer_lost and self.route.generation is None,
                    "replacement observer requires prior actual loss and closed route",
                )
            self.observer_bindings[index] = bound
            self.current_observer = (process, bound)
            self.observer_lost = False
            self._record("observer.actual-bound", self.route, binding=bound)

        root = Path(bootstrap["output"])
        self.attach_actual_epoch(
            self.enrollment["sha256"],
            native_enrollment=native_enrollment,
            handoff=handoff,
            roster=roster,
            kernels=kernels,
            host_journal=handoff["host_evidence"]["path"],
            descriptor=descriptor,
            spec_path=root / "native-spec.json",
            policy_path=root / "tensor-policy.json",
            drain_path=root / "drain-policy.json",
            socket_path=root / "native.sock",
            journal_path=root / "native.jsonl",
            snapshots=root / "consumed",
        )
        return {"native_state": "source-prepared-private-only"}

    def apply(self, value):
        operation = value.get("operation")
        require(not (getattr(self, 'live_transport_enrollment', None) is not None
            and operation in {'enroll_generation', 'admit_generation', 'prepare_native_epoch'}),
            'live transport fence forbids generic semantic reenrollment/reopen')
        if operation not in {"prepare_native_epoch", "bind_original_client", "restart_live_observer"}:
            result = super().apply(value)
            if operation == "capabilities":
                result["profiles"] = [PROFILE]
                if getattr(self,"live_scope",None) is not None:
                    result["profiles"].append("ecpa-h3-observer-live-transport-control/v2")
                    result["live_receipt"] = self.live_scope.receipt_ref()
                    result["live_transport_permission"] = "source-bound-unprepared"
            return result
        fields = {
            "prepare_native_epoch": {"phase_index", "handoff"},
            "bind_original_client": {"process_identity"},
            "restart_live_observer": {"live_receipt"},
        }
        require(
            set(value)
            == {"operation", "registration_sha256", "holder", "token"}
            | fields[operation],
            "native control fields differ",
        )
        # attach_actual_epoch acquires the same non-reentrant lock itself.
        # This single control thread performs all writer operations; requests
        # cannot open or replace an enrollment while the route remains closed.
        with self.lock:
            self._lease(value)
            require(
                self.route.generation is None or operation == "bind_original_client",
                "native setup requires a closed public route",
            )
        if operation == "restart_live_observer":
            require(self.live_scope is not None and value["live_receipt"] == self.live_scope.receipt_ref()
                and not self.live_rebind_attempted, "new v2 receipt required; one actual observer repair only")
            self.live_rebind_attempted = True
            from experiments.formal_campaign.h3_observer_live_rebind import Coordinator
            from experiments.formal_campaign.h3_observer_live_launcher import write_private
            coordinator = Coordinator(self)
            coordinator.prepare_successor()
            result = coordinator.rebind()
            write_private(self.output / "live-observer-rebind-attempt.json", result)
            if result["transport_commit_complete"]:
                attached = coordinator.attach_committed_successor()
                write_private(self.output / "live-observer-verifier-attached.json", attached)
                from experiments.formal_campaign.h3_observer_live_route import open_actual_successor
                open_actual_successor(self, coordinator)
            return {"transport_commit_complete": result["transport_commit_complete"],
                "formal_result": False, "recovery_ns": None,
                "attempt": {"path": str(self.output / "live-observer-rebind-attempt.json"),
                    "sha256": digest((self.output / "live-observer-rebind-attempt.json").read_bytes())}}
        if operation == "prepare_native_epoch":
            return self._prepare_actual_epoch(value["phase_index"], value["handoff"])
        from experiments.formal_campaign.h3_native_http import BoundOriginalClient

        with self.lock:
            require(self.bound_client is None, "original client cannot be rebound")
            self.bound_client = BoundOriginalClient(
                value["process_identity"],
                self.output / "runtime-client-spec.json",
                self.output / "client.jsonl",
                self.output / "client-ready.json",
            )
            self._record(
                "client.actual-bound",
                self.route,
                client_kernel=value["process_identity"],
            )
            return {"client": "actual-original60-bound"}

    def check_observer(self):
        if self.observer_lost:
            require(False, "source observer lost")
        if self.current_observer is None:
            return
        process, bound = self.current_observer
        if process.poll() is not None:
            self.observer_lost = True
            self._close("original observer lost")
            self._record(
                "observer.loss.observed",
                self.route,
                observer=bound["observer"],
                enrollment_sha256=bound["enrollment_sha256"],
            )
            require(False, "source observer lost")

    def _close(self, reason):
        current=getattr(self, 'live_transport_enrollment', None)
        if current is not None:
            self.revoked_enrollments.add(current['sha256'])
        return super()._close(reason)

    def routing_enrollment(self):
        return self.live_transport_enrollment or self.enrollment

    def _recheck(self):
        self.check_observer()
        if self.live_transport_enrollment is not None:
            from experiments.formal_campaign.h3_observer_live_route import recheck_actual_route
            return recheck_actual_route(self)
        return super()._recheck()

    def watch_observer(self, stop):
        while not stop.wait(0.01):
            with self.lock:
                try:
                    self.check_observer()
                except Exception:
                    if not self.observer_lost:
                        self._close("observer monitor failure")
                        self.observer_lost = True

    def close_collectors(self):
        for process in self.collectors:
            if process.stdin:
                with __import__("contextlib").suppress(BrokenPipeError):
                    process.stdin.close()
            process.wait(timeout=10)


def main():
    import argparse
    import sys
    import threading
    from contextlib import suppress
    from http.server import ThreadingHTTPServer

    from experiments.formal_campaign import h3_observer_registration as registration
    from experiments.formal_campaign.h3_dynamic_authority import serve_control
    from experiments.formal_campaign.h3_native_http import NativeProxyHandler

    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("policy", "journal", "socket", "campaign", "receipt"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--start-id", required=True)
    parser.add_argument("--public-port", type=int, required=True)
    parser.add_argument("--owned-stdin-lifetime", action="store_true")
    args = parser.parse_args()
    validated = registration.validate_receipt_for_start(
        args.campaign, args.receipt, args.start_id
    )
    spec, original, start = validated.selected(args.start_id)
    receipt = validated.guard_receipt(args.start_id)
    require(
        start["policy"]["path"] == str(args.policy)
        and start["policy"]["sha256"] == args.policy_sha256
        and start["authority"]["journal"] == str(args.journal),
        "native registered authority argv differs",
    )
    policy = json.loads(check_ref(start["policy"]).read_bytes())
    recipe = json.loads(check_ref(start["recipe_template"]).read_bytes())
    guards = registration.build_plan_guards(
        spec, original, receipt, start, trusted_manager_handoffs=set()
    )
    journal = NativeJournal(args.journal, digest(canonical(policy)))
    authority = NativeAuthority(policy, journal, plan_guards=guards)
    output = Path(
        recipe["arms"][start["arm"]]["phases"][0]["native_bootstrap"]["output"]
    ).parent
    authority.configure_start(start=start, recipe=recipe, output=output)
    import os
    live_intent = os.environ.get("ECPA_H3_OBSERVER_LIVE_INTENT")
    live_receipt = os.environ.get("ECPA_H3_OBSERVER_LIVE_RECEIPT")
    require(bool(live_intent) == bool(live_receipt), "partial live receipt environment forbidden")
    if live_intent:
        from experiments.formal_campaign.h3_observer_live_registration import validate_for_start
        scope = validate_for_start(live_intent, live_receipt, args.start_id, check_remote=True)
        require(scope.value()["base_campaign"]["path"] == str(args.campaign.resolve())
            and scope.value()["base_receipt"]["path"] == str(args.receipt.resolve()),
            "live extension bound to another original admission")
        authority.live_scope = scope

    stop = threading.Event()
    watcher = threading.Thread(
        target=authority.watch_observer, args=(stop,), daemon=True
    )
    watcher.start()
    require(recipe["authority"]["socket"] == str(args.socket), "native socket differs")
    if authority.live_scope is not None:
        from experiments.formal_campaign.h3_observer_live_http import LiveProxyHandler
        handler = LiveProxyHandler
    else:
        handler = NativeProxyHandler
    server = ThreadingHTTPServer(("127.0.0.1", args.public_port), handler)
    server.authority = authority
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if args.owned_stdin_lifetime:
        threading.Thread(
            target=serve_control, args=(args.socket, authority), daemon=True
        ).start()
        try:
            sys.stdin.buffer.read()
        finally:
            with authority.lock:
                authority._close("independent native owner lifetime ended")
            server.shutdown()
            server.server_close()
            stop.set()
            watcher.join(timeout=1)
            authority.close_collectors()
            journal.close()
            with suppress(FileNotFoundError):
                args.socket.unlink()
    else:
        serve_control(args.socket, authority)


if __name__ == "__main__":
    main()
