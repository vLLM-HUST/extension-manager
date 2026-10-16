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

PROFILE = "ecpa-h3-source-owned-native-private-route/v1"
JOURNAL = "ecpa-h3-native-authority-journal/v1"


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

        schema_path = Path(__file__).parent / "h3-native-policy.schema.json"
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
            and policy["schema"] == "ecpa-h3-native-static-policy/v1"
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
            require(
                len(source_peers) == 3
                and all(
                    any(
                        peer["process"] == member["event"]["process"]
                        for member in self.enrollment["members"]
                    )
                    for peer in source_peers
                ),
                "native peer roster differs from actual membership",
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
        self.collectors = []
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
        roster = {}
        for event in records:
            if (
                event["plan_id"] != self.enrollment["plan_id"]
                or event["launch_id"] != self.enrollment["launch_id"]
            ):
                continue
            process = event["process"]
            slot = f"{process['role']}/{process['ordinal']}"
            require(
                slot not in roster or roster[slot] == process,
                "native Host role kernel changed",
            )
            roster[slot] = process
        kernels = {
            slot: {k: p[k] for k in ("pid", "start_ticks", "session", "boot_id")}
            for slot, p in roster.items()
        }
        # Kernel fields follow the original registry. Host process_epoch remains
        # in the original role object, with no role or identity rewriting.
        bootstrap = phase["native_bootstrap"]
        sources = bootstrap["source_files"]
        peers = []
        for member in self.enrollment["members"]:
            process = member["event"]["process"]
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
        )
        self.collectors.append(process)
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
        if operation not in {"prepare_native_epoch", "bind_original_client"}:
            result = super().apply(value)
            if operation == "capabilities":
                result["profiles"] = [PROFILE]
            return result
        fields = {
            "prepare_native_epoch": {"phase_index", "handoff"},
            "bind_original_client": {"process_identity"},
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

    def close_collectors(self):
        for process in self.collectors:
            if process.stdin:
                process.stdin.close()
            process.wait(timeout=10)


def main():
    import argparse
    import sys
    import threading
    from contextlib import suppress
    from http.server import ThreadingHTTPServer

    from experiments.formal_campaign import h3_native_registration as registration
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
    spec, original, receipt = registration.validate_receipt(args.campaign, args.receipt)
    start = next(s for s in spec["starts"] if s["start_id"] == args.start_id)
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
    require(recipe["authority"]["socket"] == str(args.socket), "native socket differs")
    server = ThreadingHTTPServer(("127.0.0.1", args.public_port), NativeProxyHandler)
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
            authority.close_collectors()
            journal.close()
            with suppress(FileNotFoundError):
                args.socket.unlink()
    else:
        serve_control(args.socket, authority)


if __name__ == "__main__":
    main()
