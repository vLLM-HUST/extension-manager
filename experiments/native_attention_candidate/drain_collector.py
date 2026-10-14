"""Prospective full-phase worker drain collector; old contracts are untouched."""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import struct
import threading
import time
from pathlib import Path

from . import collector as attention
from . import phase_drain as drain

native = attention.native
require = attention.transport.require
POLICY = "ecpa-native-attention-source-drain-policy/v1"
START = "ecpa-native-attention-source-drain-start/v1"


def acknowledgement_item(event):
    return {k: event[k] for k in ("sequence", "event_sha256", "raw_sha256")}


def verify_drain(
    fact,
    *,
    sender,
    spec,
    phase,
    records,
    accepted_monotonic_ns,
    previous_ack_accepted_monotonic_ns,
):
    """Pure source/clock/full-intake-prefix check shared by live and portable."""
    require(
        set(fact)
        == {
            "schema",
            "process",
            "launch_id",
            "plan_id",
            "monotonic_ns",
            "runtime_request_id",
            "source_ack_count",
            "source_ack_chain_sha256",
            "source_last_ack",
            "native_requests_contains",
            "native_input_batch_contains",
            "scheduled_finished",
            "source_drain_completed_monotonic_ns",
            "formal_producer_registration",
        },
        "source drain fields differ",
    )
    require(
        fact["schema"] == drain.SCHEMA
        and fact["process"] == sender["process"]
        and sender["process"]["role"] == "worker"
        and sender["process"]["ordinal"] in phase["expected_ranks"]
        and fact["launch_id"] == spec["native_launch_id"]
        and fact["plan_id"] == spec["native_plan_id"]
        and fact["native_requests_contains"] is False
        and fact["native_input_batch_contains"] is False
        and fact["scheduled_finished"] is True
        and fact["formal_producer_registration"] is False,
        "source drain identity/removal predicate differs",
    )
    require(
        records
        and type(fact["source_ack_count"]) is int
        and fact["source_ack_count"] == len(records)
        and fact["source_ack_chain_sha256"] == drain.digest(records)
        and fact["source_last_ack"] == records[-1],
        "source drain does not bind complete sender intake ACKs",
    )
    stamp, completed = fact["monotonic_ns"], fact["source_drain_completed_monotonic_ns"]
    require(
        type(stamp) is int
        and type(completed) is int
        and type(previous_ack_accepted_monotonic_ns) is int
        and spec["frozen_monotonic_ns"]
        <= previous_ack_accepted_monotonic_ns
        <= stamp
        <= completed
        <= accepted_monotonic_ns
        and accepted_monotonic_ns - stamp <= spec["max_event_age_ns"],
        "source drain chronology differs",
    )


class DrainCollector(attention.AttentionCollector):
    def __init__(self, spec_path, journal_path, policy_path, drain_policy_path):
        self.intake_clocks = {}
        super().__init__(spec_path, journal_path, policy_path)
        raw, _ = native.read_private(Path(drain_policy_path), 0o600)
        value = json.loads(raw)
        require(
            set(value)
            == {
                "schema",
                "native_spec_sha256",
                "tensor_policy_sha256",
                "phase_ids",
                "required_ranks",
                "formal_registration",
            }
            and value["schema"] == POLICY
            and value["native_spec_sha256"] == self.spec_sha256
            and value["tensor_policy_sha256"] == self.policy_sha256
            and value["phase_ids"] == [p["phase_id"] for p in self.spec["phases"]]
            and value["required_ranks"] == [0, 1]
            and value["formal_registration"] is False
            and len(value["phase_ids"]) == 1,
            "source drain policy is missing, changed or promoted",
        )
        self.lock = threading.RLock()
        self.source_sha256 = native.sha(Path(__file__).read_bytes())
        self.drain_policy_sha256 = native.sha(raw)
        self.sender_records = {}
        self.closed = set()
        self._append(
            {
                "kind": "attention.drain.start",
                "schema": START,
                "source_sha256": self.source_sha256,
                "producer_source_sha256": native.sha(Path(drain.__file__).read_bytes()),
                "drain_policy_sha256": self.drain_policy_sha256,
                "formal_registration": False,
            }
        )
        os.fsync(self.archive_dirfd)

    def _append(self, value):
        event = super()._append(value)
        if "accepted_monotonic_ns" in event:
            self.intake_clocks[(event["peer"]["pid"], event["runtime_request_id"])] = (
                event["accepted_monotonic_ns"]
            )
        return event

    def accept(self, peer, raw):
        fact = json.loads(raw)
        runtime = fact.get("runtime_request_id")
        if runtime is None and fact.get("schema") in {
            attention.transport.ENVELOPE,
            attention.transport.RUNTIME_ENVELOPE,
        }:
            runtime = fact["runtime_request_id"]
        with self.lock:
            key = (peer[0], runtime)
            if key in self.closed:
                self.failed = True
                raise ValueError("native fact after authenticated source drain")
            if fact.get("schema") != drain.SCHEMA:
                ack = super().accept(peer, raw)
                if self.senders[peer[0]]["process"]["role"] == "worker":
                    self.sender_records.setdefault(key, []).append(
                        {k: ack[k] for k in ("sequence", "event_sha256", "raw_sha256")}
                    )
                return ack
            require(not self.failed, "collector persistence failed")
            sender = self.senders.get(peer[0])
            require(
                sender is not None
                and peer[1] == sender["peer_uid"] == os.getuid()
                and peer[2] == sender["peer_gid"],
                "source drain kernel peer differs",
            )
            actual = native.identity(peer[0])
            require(
                all(sender["process"].get(k) == v for k, v in actual.items())
                and native.sha(Path(f"/proc/{peer[0]}/cmdline").read_bytes())
                == sender["cmdline_sha256"],
                "source drain kernel epoch/argv differs",
            )
            sources = native.source_digests(sender["source_files"])
            require(
                native.sha(Path(drain.__file__).read_bytes()) in sources.values(),
                "source drain producer bytes are not registered",
            )
            phase = self.maps.get(runtime)
            require(phase is not None, "source drain lacks actual API mapping")
            accepted = time.monotonic_ns()
            verify_drain(
                fact,
                sender=sender,
                spec=self.spec,
                phase=phase,
                records=self.sender_records.get(key, []),
                accepted_monotonic_ns=accepted,
                previous_ack_accepted_monotonic_ns=self.intake_clocks[key],
            )
            event = self._append(
                {
                    "kind": "attention.worker.drained",
                    "accepted_monotonic_ns": accepted,
                    "raw_base64": base64.b64encode(raw).decode(),
                    "raw_sha256": native.sha(raw),
                    "peer": dict(pid=peer[0], uid=peer[1], gid=peer[2]),
                    "source_sha256": sources,
                    "process": actual,
                    "phase": phase,
                    "runtime_request_id": runtime,
                    "archive_identity": self.archive_identity,
                }
            )
            self.closed.add(key)
            ack = dict(
                schema=native.ACK,
                raw_sha256=native.sha(raw),
                event_sha256=event["event_sha256"],
                sequence=event["sequence"],
                phase=phase,
                collector=self.collector_identity,
                collector_source_sha256=self.source_sha256,
                archive_identity=self.archive_identity,
                formal_producer_registration=False,
                classification="REAL_RUNTIME_UNQUALIFIED",
            )
            ack["ack_sha256"] = native.sha(native.canonical(ack))
            return ack


class DrainHandler(native.Handler):
    def handle(self):
        peer = struct.unpack(
            "3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        try:
            frame = self.rfile.readline(native.MAX_FRAME + 1)
            require(
                frame.endswith(b"\n") and len(frame) <= native.MAX_FRAME,
                "native frame is incomplete or oversized",
            )
            request = json.loads(frame)
            collector = self.server.collector
            if request == {"op": "describe"}:
                meta = Path(self.server.server_address).stat()
                with collector.lock:
                    os.fsync(collector.fd)
                    issued = time.monotonic_ns()
                    prefix = dict(
                        next_sequence=collector.sequence,
                        last_event_sha256=collector.previous,
                    )
                    closed = {}
                    for runtime, phase in collector.maps.items():
                        ranks = sorted(
                            collector.senders[pid]["process"]["ordinal"]
                            for pid, rid in collector.closed
                            if rid == runtime
                        )
                        complete = ranks == phase["expected_ranks"]
                        closed[runtime] = dict(
                            phase=phase,
                            ranks=ranks,
                            complete=complete,
                            sealed_prefix=prefix
                            if complete and not collector.failed
                            else None,
                        )
                    response = dict(
                        schema="ecpa-native-semantic-collector-status/v1",
                        issued_monotonic_ns=issued,
                        spec_sha256=collector.spec_sha256,
                        collector_source_sha256=collector.source_sha256,
                        collector=collector.collector_identity,
                        socket_identity=[meta.st_dev, meta.st_ino],
                        socket_path=str(self.server.server_address),
                        archive_identity=collector.archive_identity,
                        classification="CPU_REVIEW_CANDIDATE_ONLY",
                        formal_producer_registration=False,
                        failed=collector.failed,
                        acknowledged_prefix=prefix,
                        source_drain=dict(
                            schema=POLICY,
                            policy_sha256=collector.drain_policy_sha256,
                            runtimes=closed,
                        ),
                    )
                self.wfile.write(native.canonical(response) + b"\n")
                return
            require(
                set(request) == {"raw_base64"},
                "native frame carries unsupported fields",
            )
            raw = base64.b64decode(request["raw_base64"], validate=True)
            response = collector.accept(peer, raw)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            response = dict(
                schema="ecpa-native-semantic-collector-reject/v1",
                reason=str(exc),
                formal_producer_registration=False,
            )
        self.wfile.write(native.canonical(response) + b"\n")


class DrainServer(native.Server):
    def __init__(self, path, collector):
        super().__init__(path, collector)
        self.RequestHandlerClass = DrainHandler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("spec", "policy", "journal", "socket", "drain-policy"):
        parser.add_argument("--" + field, required=True, type=Path)
    args = parser.parse_args()
    collector = DrainCollector(args.spec, args.journal, args.policy, args.drain_policy)
    with DrainServer(args.socket, collector) as server:
        meta = args.socket.stat()
        print(
            json.dumps(
                dict(
                    collector=collector.collector_identity,
                    socket_identity=[meta.st_dev, meta.st_ino],
                    socket_path=str(args.socket),
                    collector_source_sha256=collector.source_sha256,
                    spec_sha256=collector.spec_sha256,
                    policy_sha256=collector.policy_sha256,
                    archive_identity=collector.archive_identity,
                )
            ),
            flush=True,
        )
        server.serve_forever()


if __name__ == "__main__":
    main()
