"""Actual H4 native intake: 32 selected requests from272.

At most eight unfinished runtimes.

This is a separate protocol, not a relabeled serial request phasebook. All
native/tensor/OP/source-drain acceptance predicates are the unchanged originals.
A release prefix is sealed only when every runtime in that original global
prefix is source-closed on both ranks, so the unchanged full archive verifier
can examine the complete history without filtering or rehashing it.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import socket
import stat
import struct
import sys
import threading
import time
from pathlib import Path

from experiments.formal_campaign.h4_sampled_native_schedule import (
    bind_selected_phases,
    read_schedule,
)
from experiments.native_attention_candidate import drain_collector as original
from experiments.native_attention_candidate.request_drain_collector import (
    verify_raw_prefix,
)

native = original.native
require = original.require
POLICY = "ecpa-h4-sampled-concurrent-native-drain-policy/v1"
START = "ecpa-h4-sampled-concurrent-native-drain-start/v1"
START_KIND = "h4.sampled.native.drain.start"
STATUS = "ecpa-h4-sampled-concurrent-native-collector-status/v1"
verify_drain = original.verify_drain
REQUESTS = 32
CONCURRENCY = 8


class H4NativeCollector(original.DrainCollector):
    def __init__(
        self, spec_path, journal_path, policy_path, drain_policy_path, schedule_path
    ):
        spec_raw, _ = native.read_private(Path(spec_path), 0o600)
        tensor_raw, _ = native.read_private(Path(policy_path), 0o600)
        drain_raw, _ = native.read_private(Path(drain_policy_path), 0o600)
        spec = json.loads(spec_raw)
        policy = json.loads(drain_raw)
        schedule, schedule_raw = read_schedule(schedule_path)
        bind_selected_phases(spec, schedule)
        self.schedule_sha256 = native.sha(schedule_raw)
        phase_ids = [p["phase_id"] for p in spec["phases"]]
        require(
            len(phase_ids) == REQUESTS and len(set(phase_ids)) == REQUESTS,
            "original H4 native source must enroll exactly32 unique requests",
        )
        require(
            policy
            == {
                "schema": POLICY,
                "native_spec_sha256": native.sha(spec_raw),
                "tensor_policy_sha256": native.sha(tensor_raw),
                "phase_ids": phase_ids,
                "required_ranks": [0, 1],
                "formal_registration": False,
            },
            "H4 native policy differs",
        )
        self.intake_clocks = {}
        # Only the single-phase constructor is replaced. Every accept call below
        # goes through original.DrainCollector.accept and its original chain.
        original.attention.AttentionCollector.__init__(
            self, spec_path, journal_path, policy_path
        )
        self.lock = threading.RLock()
        self.source_sha256 = native.sha(Path(__file__).read_bytes())
        self.drain_policy_sha256 = native.sha(drain_raw)
        self.sender_records = {}
        self.closed = set()
        self.sealed = {}
        self._append(
            {
                "kind": START_KIND,
                "schedule_sha256": self.schedule_sha256,
                "schema": START,
                "source_sha256": self.source_sha256,
                "producer_source_sha256": native.sha(
                    Path(original.drain.__file__).read_bytes()
                ),
                "inherited_collector_source_sha256": native.sha(
                    Path(original.__file__).read_bytes()
                ),
                "drain_policy_sha256": self.drain_policy_sha256,
                "phase_ids": phase_ids,
                "formal_registration": False,
            }
        )
        os.fsync(self.archive_dirfd)

    def _ranks(self, runtime):
        return sorted(
            self.senders[pid]["process"]["ordinal"]
            for pid, rid in self.closed
            if rid == runtime
        )

    def _prefix(self):
        return {"next_sequence": self.sequence, "last_event_sha256": self.previous}

    def _journal_raw(self):
        descriptor = os.open(self.journal_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600
                and [info.st_dev, info.st_ino]
                == [
                    self.archive_identity["journal_device"],
                    self.archive_identity["journal_inode"],
                ],
                "H4 native journal inode/ownership differs",
            )
            chunks = []
            while part := os.read(descriptor, 1024 * 1024):
                chunks.append(part)
            raw = b"".join(chunks)
            require(len(raw) == info.st_size, "H4 native journal size changed")
            verify_raw_prefix(raw, self._prefix())
            return raw
        finally:
            os.close(descriptor)

    def _seal_quiescent_prefix(self):
        if not self.maps or any(
            self._ranks(runtime) != phase["expected_ranks"]
            for runtime, phase in self.maps.items()
        ):
            return
        os.fsync(self.fd)
        raw = self._journal_raw()
        prefix = self._prefix()
        sealed_ns = time.monotonic_ns()
        for runtime, phase in self.maps.items():
            if runtime not in self.sealed:
                self.sealed[runtime] = {
                    "phase": copy.deepcopy(phase),
                    "ranks": [0, 1],
                    "complete": True,
                    "sealed_prefix": copy.deepcopy(prefix),
                    "sealed_prefix_bytes": len(raw),
                    "sealed_prefix_sha256": native.sha(raw),
                    "sealed_monotonic_ns": sealed_ns,
                }

    def accept(self, peer, raw):
        fact = json.loads(raw)
        require(isinstance(fact, dict), "native fact must be an object")
        with self.lock:
            if fact.get("schema") == native.MAPPING:
                unfinished = sum(
                    self._ranks(runtime) != phase["expected_ranks"]
                    for runtime, phase in self.maps.items()
                )
                require(
                    unfinished < CONCURRENCY,
                    "original H4 native concurrency bound exceeded",
                )
            # Includes actual SO_PEERCRED, live kernel/source, raw replay,
            # original typed tensors, cached OPs and exact sender ACK closure.
            ack = super().accept(peer, raw)
            if fact.get("schema") == original.drain.SCHEMA:
                self._seal_quiescent_prefix()
            return ack

    def describe(self, path):
        with self.lock:
            os.fsync(self.fd)
            raw = self._journal_raw()
            states = {}
            for runtime, phase in self.maps.items():
                if runtime in self.sealed:
                    value = self.sealed[runtime]
                    require(
                        native.sha(raw[: value["sealed_prefix_bytes"]])
                        == value["sealed_prefix_sha256"],
                        "original sealed H4 global prefix bytes changed",
                    )
                    states[runtime] = copy.deepcopy(value)
                else:
                    states[runtime] = {
                        "phase": copy.deepcopy(phase),
                        "ranks": self._ranks(runtime),
                        "complete": False,
                        "sealed_prefix": None,
                        "sealed_prefix_bytes": None,
                        "sealed_prefix_sha256": None,
                        "sealed_monotonic_ns": None,
                    }
            info = Path(path).lstat()
            return {
                "schema": STATUS,
                "schedule_sha256": self.schedule_sha256,
                "issued_monotonic_ns": time.monotonic_ns(),
                "collector": self.collector_identity,
                "spec_sha256": self.spec_sha256,
                "collector_source_sha256": self.source_sha256,
                "socket_identity": [info.st_dev, info.st_ino],
                "socket_path": str(path),
                "archive_identity": self.archive_identity,
                "classification": "REAL_RUNTIME_UNQUALIFIED",
                "formal_producer_registration": False,
                "failed": self.failed,
                "acknowledged_prefix": self._prefix(),
                "source_drain": {
                    "schema": POLICY,
                    "policy_sha256": self.drain_policy_sha256,
                    "runtimes": states,
                },
            }


class Handler(native.Handler):
    def handle(self):
        peer = struct.unpack(
            "3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        try:
            frame = self.rfile.readline(native.MAX_FRAME + 1)
            require(
                frame.endswith(b"\n") and len(frame) <= native.MAX_FRAME,
                "H4 native frame bound differs",
            )
            request = json.loads(frame)
            if request == {"op": "describe"}:
                response = self.server.collector.describe(self.server.server_address)
            else:
                require(set(request) == {"raw_base64"}, "unsupported native command")
                response = self.server.collector.accept(
                    peer, base64.b64decode(request["raw_base64"], validate=True)
                )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            response = {
                "schema": "ecpa-h4-sampled-concurrent-native-reject/v1",
                "reason": str(exc),
                "formal_producer_registration": False,
            }
        self.wfile.write(native.canonical(response) + b"\n")


class Server(native.Server):
    def __init__(self, path, collector):
        super().__init__(path, collector)
        self.RequestHandlerClass = Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("spec", "policy", "drain-policy", "journal", "socket", "schedule"):
        parser.add_argument("--" + field, type=Path, required=True)
    parser.add_argument("--owned-stdin-lifetime", action="store_true")
    args = parser.parse_args()
    collector = H4NativeCollector(
        args.spec, args.journal, args.policy, args.drain_policy, args.schedule
    )
    with Server(args.socket, collector) as server:
        info = args.socket.lstat()
        print(
            json.dumps(
                {
                    "schema": "ecpa-h4-sampled-native-collector-ready/v1",
                    "schedule_sha256": collector.schedule_sha256,
                    "collector": collector.collector_identity,
                    "collector_source_sha256": collector.source_sha256,
                    "spec_sha256": collector.spec_sha256,
                    "policy_sha256": collector.policy_sha256,
                    "socket_identity": [info.st_dev, info.st_ino],
                    "archive_identity": collector.archive_identity,
                    "socket_path": str(args.socket),
                    "formal_producer_registration": False,
                }
            ),
            flush=True,
        )
        if args.owned_stdin_lifetime:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                sys.stdin.buffer.read()
            finally:
                server.shutdown()
        else:
            server.serve_forever()


if __name__ == "__main__":
    main()
