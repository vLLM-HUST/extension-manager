"""Full original native archive consumer for one H4 request in a shared prefix.

No filtered journal is accepted. Selection of a request occurs only after all
original global records, artifacts, source ACKs and cached OP facts pass the
unchanged archive consumer. This produces no public route permission by itself.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import threading
import time
import weakref
from dataclasses import dataclass, field
from pathlib import Path

from experiments.formal_campaign import h4_sampled_native_client, h4_sampled_native_collector
from experiments.formal_campaign.h4_sampled_native_bootstrap import (
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

native = h4_sampled_native_collector.native
require = h4_sampled_native_collector.require

_CONSUMED = weakref.WeakValueDictionary()


def require_verified_h4_native_request(report):
    """Accept only this module's actually consumed owned ticket, never JSON."""
    require(
        type(report) is VerifiedH4NativeRequest and _CONSUMED.get(id(report)) is report,
        "native report is detached, forged or not consumed",
    )
    return report


@dataclass(frozen=True)
class VerifiedH4NativeRequest:
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
    schedule_sha256: str
    profiler_occurrence_id: str
    profiler_prefix_sha256: str
    profiler_snapshot_path: str
    profiler_snapshot_sha256: str
    _report_raw: bytes = field(repr=False)
    _owner: object = field(repr=False, compare=False)


def _profiler_snapshot(path, roster, kernels, plan_id, launch_id):
    """Read the entire original private Host journal and bind actual role epochs."""
    from vllm_hust_ext.host_evidence import parse_host_event

    require(set(roster) == set(kernels), "profiler Host/kernel roster differs")
    for slot, process in roster.items():
        kernel = kernels[slot]
        require(set(kernel) == {"pid", "start_ticks", "session", "boot_id"}
                and {key: native.identity(kernel["pid"])[key] for key in kernel} == kernel
                and process["assignment_source"] == "host"
                and process["start_identity"] == f"pid:{kernel['pid']}:start_ticks:{kernel['start_ticks']}",
                "profiler actual Host role/kernel changed")
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, "original profiler journal path differs")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        require(stat.S_ISREG(first.st_mode) and first.st_uid == os.getuid()
                and stat.S_IMODE(first.st_mode) == 0o600
                and 0 < first.st_size <= 64 * 1024 * 1024, "profiler journal is not private/bounded")
        raw = b""
        while part := os.read(fd, 1024 * 1024):
            raw += part
            require(len(raw) <= 64 * 1024 * 1024, "profiler journal exceeds full-prefix bound")
        last = os.fstat(fd)
        require((first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns, first.st_ctime_ns)
                == (last.st_dev, last.st_ino, last.st_size, last.st_mtime_ns, last.st_ctime_ns)
                and len(raw) == last.st_size and raw.endswith(b"\n"),
                "original profiler journal changed while reading")
    finally:
        os.close(fd)
    events = [parse_host_event(line) for line in raw.splitlines()]
    originals = {native.canonical({k: v for k, v in p.items()
                                 if k not in {"role", "ordinal", "assignment_source"}})
                 for p in roster.values()}
    for event in events:
        require(event["plan_id"] == plan_id and event["launch_id"] == launch_id,
                "original profiler journal mixes Plan/launch")
        process = event["process"]
        slot = f"{process['role']}/{process['ordinal']}"
        if process["assignment_source"] == "environment":
            require(process["role"] == "unknown" and event["event"] in {"discovered", "resolved"}
                    and event["observation_kind"] == "loader_lifecycle"
                    and native.canonical({k: v for k, v in process.items()
                                          if k not in {"role", "ordinal", "assignment_source"}}) in originals,
                    "unbound profiler journal process has no exact assigned epoch")
        else:
            require(slot in roster and native.canonical(process) == native.canonical(roster[slot]),
                    "original profiler Host role changed")
    return raw, events, [last.st_dev, last.st_ino], time.time_ns()


class H4NativeEpochVerifier:
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
        schedule_path,
        profiler_host_journal,
        profiler_roster,
        profiler_kernels,
    ):
        from experiments.formal_campaign.h4_sampled_native_schedule import read_schedule, bind_selected_phases
        self.schedule_path = Path(schedule_path)
        self.schedule, schedule_raw = read_schedule(self.schedule_path)
        self.profiler_host_journal = Path(profiler_host_journal)
        self.profiler_roster = json.loads(native.canonical(profiler_roster))
        self.profiler_kernels = json.loads(native.canonical(profiler_kernels))
        self._profiler_begins = {}
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
        from experiments.formal_campaign.h4_sampled_native_bootstrap import make_private_directory
        make_private_directory(self.snapshots)
        self.inputs = {
            path: path.read_bytes()
            for path in (self.spec_path, self.policy_path, self.drain_path)
        }
        self.spec = json.loads(self.inputs[self.spec_path])
        bind_selected_phases(self.spec, self.schedule)
        self.inputs[self.schedule_path] = schedule_raw
        verify_senders(self.spec["senders"])

    def _current(self):
        require(
            all(p.read_bytes() == raw for p, raw in self.inputs.items()),
            "native immutable epoch inputs changed",
        )
        verify_senders(self.spec["senders"])
        return h4_sampled_native_client.authenticate(
            self.socket_path,
            self.descriptor,
            self.spec_path,
            Path(h4_sampled_native_collector.__file__),
            drain_policy_path=self.drain_path,
            schedule_path=self.schedule_path,
        )

    def begin_request(self, request_id):
        before = self._current()
        declaration = [row for row in self.schedule["requests"]
                       if row["request_id"] == request_id and row["selected"]]
        require(len(declaration) == 1, "native begin is not one frozen H4 sample")
        profile = _profiler_snapshot(self.profiler_host_journal, self.profiler_roster,
                                    self.profiler_kernels, self.spec["native_plan_id"],
                                    self.spec["native_launch_id"])
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
            self._profiler_begins[request_id] = profile

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
            and deadline_ns - sent_ns == 120_000_000_000,
            "original H4 timeout/deadline differs",
        )
        # Correlation is a transport header; the original frozen body is never
        # rewritten to carry challenge prompts or replacement request identities.
        phases = [
            p for p in self.spec["phases"] if p["client_request_id"] == request_id
        ]
        require(len(phases) == 1, "native request not in frozen32 sample cohort")
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
            profile_before = self._profiler_begins.pop(request_id)
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
            drain_protocol=h4_sampled_native_collector,
            _owner=owner,
            _owned_materializations=materializations,
        )
        temporal_phase = dict(
            phase,
            ack_time_policy=drain_time_policy.FINAL_PREFIX_POLICY,
            rpc_budget_s=120,
            ack_client_source_sha256=native.sha(
                Path(h4_sampled_native_client.__file__).read_bytes()
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
        choices, usage = data.get("choices"), data.get("usage")
        declaration = [row for row in self.schedule["requests"]
                       if row["request_id"] == request_id and row["selected"]]
        require(len(declaration) == 1
                and native.sha(request_body) == declaration[0]["body_sha256"],
                "sample body differs from original frozen H4 traffic")
        require(set(response_expectation) == {"min_completion_tokens", "max_completion_tokens"}
                and response_expectation == {"min_completion_tokens": 16, "max_completion_tokens": 64}
                and request["max_tokens"] == 64,
                "registered H4 native functional scope differs")
        require(data.get("id") == f"cmpl-{request_id}"
                and data.get("model") == request["model"]
                and isinstance(choices, list) and len(choices) == 1
                and choices[0].get("index") == 0
                and choices[0].get("finish_reason") in {"stop", "length"}
                and type(choices[0].get("text")) is str and bool(choices[0]["text"].strip())
                and type(usage) is dict
                and all(type(usage.get(k)) is int for k in ("prompt_tokens", "completion_tokens", "total_tokens"))
                and 16 <= usage["completion_tokens"] <= 64
                and usage["prompt_tokens"] > 0
                and usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"],
                "registered H4 functional response/usage failed")
        profile_raw, profile_events, profile_inode, profile_wall_ns = _profiler_snapshot(
            self.profiler_host_journal, self.profiler_roster, self.profiler_kernels,
            self.spec["native_plan_id"], self.spec["native_launch_id"])
        before_raw, _, before_inode, before_wall_ns = profile_before
        require(profile_inode == before_inode and profile_raw.startswith(before_raw),
                "original profiler global history changed after request began")
        occurrence = native.sha(("request_finished\0" + runtime).encode())
        matched = [event for event in profile_events[len(before_raw.splitlines()):]
                   if event["event"] == "effective"
                   and event["observation_kind"] == "runtime_effective"
                   and event["detail"] == "request-lifecycle-eventbus:request_finished"
                   and event["occurrence_id"] == occurrence
                   and tuple(event["entry_point"][k] for k in ("group", "name", "value"))
                   == ("vllm.general_plugins", "request_lifecycle_profiler",
                       "vllm_request_lifecycle_profiler.plugin:register_plugin")
                   and event["process"]["role"] in {"api-server", "engine-core-scheduler"}
                   and event["process"]["ordinal"] == 0]
        require(matched and all(before_wall_ns <= event["observed_at_ns"] <= profile_wall_ns
                                for event in matched),
                "same actual opaque runtime lacks new source-owned profiler finished callback")
        profiler_snapshot = root / "profiler-original.jsonl"
        fd = os.open(profiler_snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(profile_raw); stream.flush(); os.fsync(stream.fileno())
        finally:
            os.close(fd)
        self._current()
        now = time.monotonic_ns()
        require(
            now <= deadline_ns, "full native consumption exceeded original120s deadline"
        )
        report_path = root / "native-consume-report.json"
        write_private(
            report_path,
            {
                "schema": "ecpa-h4-sampled-native-consume-report/v1",
                "request_id": request_id,
                "schedule_sha256": native.sha(self.inputs[self.schedule_path]),
                "profiler_snapshot": str(profiler_snapshot),
                "profiler_snapshot_sha256": native.sha(profile_raw),
                "profiler_occurrence_id": occurrence,
                "profiler_matched_events": matched,
                "profiler_before_prefix_sha256": native.sha(before_raw),
                "profiler_before_wall_ns": before_wall_ns,
                "profiler_after_wall_ns": profile_wall_ns,
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
        proof = VerifiedH4NativeRequest(
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
            native.sha(self.inputs[self.schedule_path]),
            occurrence,
            native.sha(profile_raw),
            str(profiler_snapshot),
            native.sha(profile_raw),
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
                type(proof) is VerifiedH4NativeRequest
                and self._issued.get(id(proof)) is proof
                and proof._owner is self._owner
                and proof.request_id == request_id
                and proof.response_sha256 == native.sha(response_body)
                and deadline_ns == proof.original_deadline_ns
                and native.sha(Path(proof.snapshot_report_path).read_bytes())
                == proof.snapshot_report_sha256
                and native.sha(Path(proof.profiler_snapshot_path).read_bytes())
                == proof.profiler_snapshot_sha256
                and proof.profiler_occurrence_id
                == native.sha(("request_finished\0" + proof.runtime_request_id).encode())
                and proof.schedule_sha256 == native.sha(self.inputs[self.schedule_path]),
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


# Domain-local compatibility name; this accepts only the independent H4 token.
require_verified_native_request = require_verified_h4_native_request
