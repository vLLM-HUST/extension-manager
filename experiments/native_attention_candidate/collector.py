"""Opt-in authenticated cached OP collector; old tensor protocol is unchanged."""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import time
from pathlib import Path

from experiments.exposure_gate import native_semantic_collector as native
from experiments.native_kv_tensor_candidate import artifact_transport as transport

from . import operator_observer as observer

START = "ecpa-native-attention-transport-source-candidate/v1"


def verify_reference(
    fact, event, payload, *, collector_source_sha256, collector_identity
):
    """Pure original typed event/ACK/blob join; no fabricated filtered journal."""
    return _verify_reference(
        fact,
        event,
        payload,
        collector_source_sha256=collector_source_sha256,
        collector_identity=collector_identity,
    )


def _verify_owned_reference(
    fact,
    event,
    payload,
    materialization,
    owner,
    *,
    collector_source_sha256,
    collector_identity,
):
    transport.require(
        type(materialization) is observer._OwnedMaterialization,
        "internal owned materialization required",
    )
    return _verify_reference(
        fact,
        event,
        payload,
        collector_source_sha256=collector_source_sha256,
        collector_identity=collector_identity,
        _materialization=materialization,
        _owner=owner,
    )


def _verify_reference(
    fact,
    event,
    payload,
    *,
    collector_source_sha256,
    collector_identity,
    _materialization=None,
    _owner=None,
):
    transport.require(
        event["kind"] == "tensor.artifact.accepted",
        "source attention ACK does not reference a typed materialization",
    )
    ack = fact["materialization_ack"]
    raw = base64.b64decode(event["raw_base64"], validate=True)
    envelope = json.loads(raw)
    transport.require(
        ack["schema"] == native.ACK
        and ack["sequence"] == event["sequence"]
        and ack["event_sha256"] == event["event_sha256"]
        and ack["raw_sha256"] == event["raw_sha256"] == native.sha(raw)
        and ack["phase"] == event["phase"]
        and ack["archive_identity"] == event["archive_identity"]
        and ack["collector"] == collector_identity
        and ack["collector_source_sha256"] == collector_source_sha256
        and ack["formal_producer_registration"] is False
        and ack["ack_sha256"]
        == native.sha(
            native.canonical({k: v for k, v in ack.items() if k != "ack_sha256"})
        ),
        "native OP source ACK differs from actual prior raw typed event",
    )
    transport.require(
        fact["source_materialization_sha256"]
        == event["artifact"]["sha256"]
        == native.sha(payload)
        and fact["runtime_request_id"] == envelope["runtime_request_id"]
        and fact["materialization_transaction_id"] == envelope["transaction_id"]
        and fact["process"] == envelope["process"]
        and fact["launch_id"] == envelope["launch_id"]
        and fact["plan_id"] == envelope["plan_id"],
        "native OP request/plan/worker/payload differs from source receipt",
    )
    if _materialization is None:
        result = observer.verify_observation(fact, json.loads(payload))
    else:
        result = observer._verify_owned_observation(
            fact, _materialization, payload, _owner
        )
    transport.require(
        event["accepted_monotonic_ns"]
        <= fact["materialization_ack_registered_monotonic_ns"],
        "native OP source ACK precedes actual archive acceptance",
    )
    return result


class AttentionCollector(transport.TensorArtifactCollector):
    def __init__(self, spec_path, journal_path, policy_path):
        self.journal_path = Path(journal_path)
        super().__init__(spec_path, journal_path, policy_path)
        transport.require(
            self.policy["schema"] == transport.RUNTIME_POLICY,
            "cached attention requires explicit native runtime contract",
        )
        self.source_sha256 = native.sha(Path(__file__).read_bytes())
        self.operator_seen = set()
        self._accepted_tensor_acks = {}
        self.operator_source_sha256 = native.sha(Path(observer.__file__).read_bytes())
        self._append(
            {
                "kind": "attention.transport.start",
                "schema": START,
                "source_sha256": self.source_sha256,
                "operator_source_sha256": self.operator_source_sha256,
                "tensor_transport_source_sha256": native.sha(
                    Path(transport.__file__).read_bytes()
                ),
                "formal_registration": False,
            }
        )
        os.fsync(self.archive_dirfd)

    def accept(self, peer, raw):
        fact = json.loads(raw)
        if fact.get("schema") != observer.SCHEMA:
            ack = super().accept(peer, raw)
            if fact.get("schema") == transport.RUNTIME_ENVELOPE:
                with self.lock:
                    self._accepted_tensor_acks[ack["sequence"]] = copy.deepcopy(ack)
            return ack
        with self.lock:
            transport.require(not self.failed, "collector persistence failed")
            pid, uid, gid = peer
            sender = self.senders.get(pid)
            transport.require(
                sender is not None
                and sender["process"]["role"] == "worker"
                and sender["peer_uid"] == uid == os.getuid()
                and sender["peer_gid"] == gid,
                "native OP source kernel peer is not registered worker",
            )
            transport.require(
                all(
                    sender["process"].get(k) == v
                    for k, v in native.identity(pid).items()
                )
                and native.sha(Path(f"/proc/{pid}/cmdline").read_bytes())
                == sender["cmdline_sha256"],
                "native OP source kernel epoch/argv changed",
            )
            sources = native.source_digests(sender["source_files"])
            transport.require(
                self.operator_source_sha256 in sources.values()
                and self.source_sha256 in sources.values(),
                "native OP source/receiver bytes are not frozen for peer",
            )
            now = time.monotonic_ns()
            stamp = fact["monotonic_ns"]
            transport.require(
                native.canonical(fact) == raw
                and len(raw) <= 49152
                and fact["process"] == sender["process"]
                and fact["launch_id"] == self.spec["native_launch_id"]
                and fact["plan_id"] == self.spec["native_plan_id"]
                and type(stamp) is int
                and self.spec["frozen_monotonic_ns"] <= stamp <= now
                and now - stamp <= self.spec["max_event_age_ns"],
                "native OP source bytes/identity/clock unsupported",
            )
            events = [
                json.loads(line)
                for line in Path(self.journal_path).read_bytes().splitlines()
            ]
            sequence = fact["materialization_ack"]["sequence"]
            transport.require(
                type(sequence) is int and 0 <= sequence < len(events),
                "native OP source ACK points outside actual archive",
            )
            transport.require(
                self._accepted_tensor_acks.get(sequence) == fact["materialization_ack"],
                "native OP source ACK was not issued by this live collector",
            )
            reference = events[sequence]
            payload = (
                Path(self.journal_path)
                .parent.joinpath(reference["artifact"]["basename"])
                .read_bytes()
            )
            verify_reference(
                fact,
                reference,
                payload,
                collector_source_sha256=self.source_sha256,
                collector_identity=self.collector_identity,
            )
            typed_key = (
                fact["runtime_request_id"],
                fact["materialization_transaction_id"],
                fact["process"]["ordinal"],
                fact["layer_index"],
            )
            transport.require(
                typed_key in self.tensor_seen,
                "native OP reference was not accepted by this live collector",
            )
            phase = reference["phase"]
            transport.require(
                fact["runtime_request_id"] in self.mapping_stamps
                and self.mapping_stamps[fact["runtime_request_id"]]
                <= fact["native_call_started_ns"],
                "native OP precedes actual source request mapping",
            )
            key = (
                phase["phase_id"],
                fact["runtime_request_id"],
                fact["process"]["ordinal"],
                fact["layer_index"],
            )
            transport.require(
                key not in self.operator_seen, "duplicate first native OP witness"
            )
            try:
                event = self._append(
                    {
                        "kind": "attention.operator.accepted",
                        "accepted_monotonic_ns": now,
                        "raw_base64": base64.b64encode(raw).decode(),
                        "raw_sha256": native.sha(raw),
                        "source_sha256": sources,
                        "peer": dict(pid=pid, uid=uid, gid=gid),
                        "process": native.identity(pid),
                        "phase": phase,
                        "runtime_request_id": fact["runtime_request_id"],
                        "archive_identity": self.archive_identity,
                    }
                )
            except OSError:
                self.failed = True
                raise
            self.operator_seen.add(key)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("spec", "policy", "journal", "socket"):
        parser.add_argument("--" + flag, type=Path, required=True)
    args = parser.parse_args()
    collector = AttentionCollector(args.spec, args.journal, args.policy)
    with native.Server(args.socket, collector) as server:
        stat = args.socket.stat()
        print(
            json.dumps(
                dict(
                    collector=collector.collector_identity,
                    socket_identity=[stat.st_dev, stat.st_ino],
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
