"""Full original native archive consumer for one H3 request in a shared prefix.

No filtered journal is accepted. Selection of a request occurs only after all
original global records, artifacts, source ACKs and cached OP facts pass the
unchanged archive consumer. This produces no public route permission by itself.
"""

from __future__ import annotations

import base64
import json
import threading
import time
import weakref
from dataclasses import dataclass, field
from pathlib import Path

from experiments.formal_campaign import h3_native_client, h3_native_collector
from experiments.formal_campaign.h3_native_bootstrap import (
    verify_senders,
    write_private,
)
from experiments.native_attention_candidate import (
    attention_consumer,
    drain_time_policy,
    request_drain_consumer,
)
from experiments.native_kv_tensor_candidate.projection_tensor_join import (
    verify_projection_tensor_join,
)

native = h3_native_collector.native
require = h3_native_collector.require

_CONSUMED = weakref.WeakValueDictionary()


def require_verified_native_request(report):
    """Accept only this module's actually consumed owned ticket, never JSON."""
    require(
        type(report) is VerifiedNativeRequest and _CONSUMED.get(id(report)) is report,
        "native report is detached, forged or not consumed",
    )
    return report


@dataclass(frozen=True)
class VerifiedNativeRequest:
    """Report only; authority must separately check current epoch/lease/membership."""

    request_id: str
    runtime_request_id: str
    transaction_id: str
    native_plan_id: str
    native_launch_id: str
    original_prefix_sha256: str
    verified_monotonic_ns: int
    response_sha256: str
    original_sent_ns: int
    original_deadline_ns: int
    snapshot_report_path: str
    snapshot_report_sha256: str
    _report_raw: bytes = field(repr=False)
    _owner: object = field(repr=False, compare=False)


class NativeEpochVerifier:
    def __init__(
        self,
        *,
        native_spec,
        tensor_policy,
        drain_policy,
        descriptor,
        socket_path,
        journal_path,
        snapshots,
    ):
        self._owner = object()
        self._issued = {}
        self._request_begins = {}
        self._consume_lock = threading.Lock()
        self.spec_path = Path(native_spec)
        self.policy_path = Path(tensor_policy)
        self.drain_path = Path(drain_policy)
        self.descriptor = descriptor
        self.socket_path = Path(socket_path)
        self.journal = Path(journal_path)
        self.snapshots = Path(snapshots)
        self.snapshots.mkdir(mode=0o700)
        self.inputs = {
            path: path.read_bytes()
            for path in (self.spec_path, self.policy_path, self.drain_path)
        }
        self.spec = json.loads(self.inputs[self.spec_path])
        verify_senders(self.spec["senders"])

    def _current(self):
        require(
            all(p.read_bytes() == raw for p, raw in self.inputs.items()),
            "native immutable epoch inputs changed",
        )
        verify_senders(self.spec["senders"])
        return h3_native_client.authenticate(
            self.socket_path,
            self.descriptor,
            self.spec_path,
            Path(h3_native_collector.__file__),
            drain_policy_path=self.drain_path,
        )

    def begin_request(self, request_id):
        before = self._current()
        require(
            not any(
                s["phase"]["client_request_id"] == request_id
                for s in before["status"]["source_drain"]["runtimes"].values()
            ),
            "native request already mapped before actual send",
        )
        with self._consume_lock:
            require(
                request_id not in self._request_begins, "native request begin replayed"
            )
            self._request_begins[request_id] = before

    def verify_request(
        self,
        *,
        request_id,
        request_body,
        response_status,
        response_body,
        sent_ns,
        received_ns,
        backend_sent_ns,
        deadline_ns,
        response_expectation,
    ):
        require(response_status == 200, "native upstream did not return200")
        require(
            0 < sent_ns <= received_ns <= deadline_ns
            and deadline_ns - sent_ns == 10_000_000_000,
            "original H3 timeout/deadline differs",
        )
        # Correlation is a transport header; the original frozen body is never
        # rewritten to carry challenge prompts or replacement request identities.
        phases = [
            p for p in self.spec["phases"] if p["client_request_id"] == request_id
        ]
        require(len(phases) == 1, "native request not in frozen60 cohort")
        phase = phases[0]
        require(
            phase["external_request_id"] == f"cmpl-{request_id}-0",
            "actual completion external request-ID translation differs",
        )
        with self._consume_lock:
            require(
                request_id in self._request_begins, "native actual before ACK missing"
            )
            before = self._request_begins.pop(request_id)
        while True:
            after = self._current()
            states = after["status"]["source_drain"]["runtimes"]
            matches = [(rid, s) for rid, s in states.items() if s["phase"] == phase]
            require(len(matches) <= 1, "native request mapping is ambiguous")
            if matches and matches[0][1]["complete"]:
                break
            require(
                time.monotonic_ns() < deadline_ns,
                "request lacks full original source-drained prefix before deadline",
            )
            time.sleep(0.01)
        runtime, state = matches[0]
        raw = self.journal.read_bytes()[: state["sealed_prefix_bytes"]]
        require(
            native.sha(raw) == state["sealed_prefix_sha256"],
            "source-sealed original prefix changed",
        )
        root = self.snapshots / native.sha(request_id.encode())
        require(
            root.name == native.sha(request_id.encode())
            and root.parent == self.snapshots,
            "request snapshot path escapes owner directory",
        )
        root.mkdir(mode=0o700)
        events = [json.loads(line) for line in raw.splitlines()]
        # Copy every artifact referenced by the full original prefix. No request
        # filtering, event projection, reconstructed ACK or rehashed chain.
        for event in events:
            if event.get("kind") != "tensor.artifact.accepted":
                continue
            artifact = event["artifact"]
            basename = artifact["basename"]
            require(
                Path(basename).name == basename, "artifact basename escapes archive"
            )
            payload = (self.journal.parent / basename).read_bytes()
            require(
                native.sha(payload) == artifact["sha256"], "original artifact changed"
            )
            (root / basename).write_bytes(payload)
        snapshot = root / "native.jsonl"
        snapshot.write_bytes(raw)
        owner, materializations = object(), {}
        report = attention_consumer._verify_attention_archive(
            self.spec_path,
            self.policy_path,
            snapshot,
            acknowledged_prefix=state["sealed_prefix"],
            drain_policy_path=self.drain_path,
            drain_protocol=h3_native_collector,
            _owner=owner,
            _owned_materializations=materializations,
        )
        temporal_phase = dict(
            phase,
            ack_time_policy=drain_time_policy.FINAL_PREFIX_POLICY,
            rpc_budget_s=10,
            ack_client_source_sha256=native.sha(
                Path(h3_native_client.__file__).read_bytes()
            ),
        )
        temporal = request_drain_consumer.verify_time_contract(
            temporal_phase,
            events,
            {
                "sent_monotonic_ns": backend_sent_ns,
                "received_monotonic_ns": received_ns,
                "client": before["authentication_clock"]["client"],
            },
            before,
            after,
            self.descriptor,
            self.spec["senders"][0]["peer_uid"],
        )
        complete = [
            t
            for t in report["attention_complete_transactions"]
            if t["phase_id"] == phase["phase_id"]
        ]
        require(
            len(complete) == 1 and complete[0]["runtime_request_id"] == runtime,
            "request lacks full56 native OP/tensor completion",
        )
        tx = complete[0]["transaction_id"]
        payloads = {}
        projections = {}
        for event in events:
            if event.get("phase") == phase and event.get("kind") == "native.accepted":
                fact = json.loads(base64.b64decode(event["raw_base64"], validate=True))
                if fact["schema"] == native.PROJECTION_V2:
                    projections[fact["process"]["ordinal"]] = fact
        for event in events:
            if event.get("phase") != phase or "raw_base64" not in event:
                continue
            fact = json.loads(base64.b64decode(event["raw_base64"], validate=True))
            require(
                event["accepted_monotonic_ns"] <= deadline_ns,
                "native source accepted after original deadline",
            )
            if event["kind"] == "tensor.artifact.accepted":
                payload = (root / event["artifact"]["basename"]).read_bytes()
                require(
                    native.sha(payload) == event["artifact"]["sha256"],
                    "typed payload changed after full archive consumption",
                )
                typed = materializations[event["sequence"]]._report_after_fresh_read(
                    payload, owner
                )
                clocks = [
                    typed[k]
                    for k in (
                        "source_before_gather_ns",
                        "reference_after_gather_ns",
                        "write_completed_barrier_ns",
                        "destination_readback_completed_ns",
                    )
                ]
                require(
                    clocks == sorted(clocks)
                    and all(sent_ns <= x <= received_ns for x in clocks),
                    "actual native tensor clocks outside request",
                )
                payloads[event["sequence"]] = typed
            if event["kind"] == "attention.operator.accepted":
                projection = projections[fact["process"]["ordinal"]]
                row = projection["host_cpu_block_ids"]
                require(
                    fact["process"] == projection["process"]
                    and fact["actual_cpu_block_ids"][: len(row)] == row
                    and projection["monotonic_ns"]
                    <= fact["metadata_bound_monotonic_ns"],
                    "native OP did not read the same-worker materialized full row",
                )
                require(
                    all(
                        sent_ns <= fact[k] <= received_ns
                        for k in (
                            "materialization_ack_registered_monotonic_ns",
                            "metadata_bound_monotonic_ns",
                            "native_entry_readback_started_ns",
                            "native_entry_readback_completed_ns",
                            "native_call_started_ns",
                            "native_call_returned_ns",
                            "native_stream_completed_ns",
                        )
                    ),
                    "actual cached OP clocks outside request",
                )
        require(len(payloads) == 56, "missing original two-rank/all28 tensor receipts")
        verify_projection_tensor_join(
            events,
            payloads,
            runtime_request_id=runtime,
            transaction_id=tx,
            phase_id=phase["phase_id"],
            effect_upload_sequences=set(temporal["effect_upload_sequences"]),
        )
        data, request = json.loads(response_body), json.loads(request_body)
        choices = data.get("choices")
        require(
            data.get("id") == f"cmpl-{request_id}"
            and data.get("model") == request["model"]
            and isinstance(choices, list)
            and len(choices) == 1
            and choices[0].get("index") == 0
            and choices[0].get("finish_reason") == "stop"
            and choices[0].get("text") == response_expectation["text_equals"],
            "original H3 functional response oracle failed",
        )
        self._current()
        now = time.monotonic_ns()
        require(
            now <= deadline_ns, "full native consumption exceeded original10s deadline"
        )
        report_path = root / "native-consume-report.json"
        write_private(
            report_path,
            {
                "request_id": request_id,
                "full_archive": report,
                "verified_monotonic_ns": now,
                "formal_result": False,
                "native_spec": str(self.spec_path),
                "tensor_policy": str(self.policy_path),
                "drain_policy": str(self.drain_path),
                "journal": str(snapshot),
                "spec_sha256": native.sha(self.inputs[self.spec_path]),
                "policy_sha256": native.sha(self.inputs[self.policy_path]),
                "drain_sha256": native.sha(self.inputs[self.drain_path]),
                "sealed_prefix": state["sealed_prefix"],
                "phase": phase,
                "before": before,
                "after": after,
                "temporal": temporal,
                "backend_sent_ns": backend_sent_ns,
                "backend_received_ns": received_ns,
                "original_sent_ns": sent_ns,
                "original_deadline_ns": deadline_ns,
                "response_sha256": native.sha(response_body),
                "response_body_base64": base64.b64encode(response_body).decode(),
                "descriptor": self.descriptor,
            },
        )
        proof = VerifiedNativeRequest(
            request_id,
            runtime,
            tx,
            self.spec["native_plan_id"],
            self.spec["native_launch_id"],
            native.sha(raw),
            now,
            native.sha(response_body),
            sent_ns,
            deadline_ns,
            str(report_path),
            native.sha(report_path.read_bytes()),
            native.canonical(report),
            self._owner,
        )
        with self._consume_lock:
            self._issued[id(proof)] = proof
        return proof

    def consume(self, proof, *, request_id, response_body, deadline_ns):
        """One-use object identity, not a JSON/dataclass success assertion."""
        with self._consume_lock:
            require(
                type(proof) is VerifiedNativeRequest
                and self._issued.get(id(proof)) is proof
                and proof._owner is self._owner
                and proof.request_id == request_id
                and proof.response_sha256 == native.sha(response_body)
                and deadline_ns == proof.original_deadline_ns
                and native.sha(Path(proof.snapshot_report_path).read_bytes())
                == proof.snapshot_report_sha256,
                "native proof is forged, replayed or for another request",
            )
            self._current()
            require(
                time.monotonic_ns() <= deadline_ns,
                "native proof expired before consumption",
            )
            del self._issued[id(proof)]
            _CONSUMED[id(proof)] = proof
            return proof
