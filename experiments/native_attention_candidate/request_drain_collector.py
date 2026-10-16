"""Explicit serial multi-request drain intake; original protocols are unchanged."""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import socket
import stat
import struct
import threading
import time
from pathlib import Path

from . import drain_collector as original

native = original.native
require = original.require
POLICY = "ecpa-request-native-drain-policy/v1"
START = "ecpa-request-native-drain-start/v1"
START_KIND = "request.drain.start"
STATUS = "ecpa-request-native-collector-status/v1"
MAX_PHASES = 64
verify_drain = original.verify_drain


def verify_raw_prefix(raw, prefix):
    """Verify every original record from sequence zero; never filter a phase."""
    require(raw and raw.endswith(b"\n"), "request journal prefix is incomplete")
    previous = "0" * 64
    count = 0
    for count, line in enumerate(raw.splitlines(), 1):
        event = json.loads(line)
        require(
            native.canonical(event) == line
            and event["sequence"] == count - 1
            and event["previous_sha256"] == previous
            and event["event_sha256"]
            == native.sha(
                native.canonical(
                    {k: v for k, v in event.items() if k != "event_sha256"}
                )
            ),
            "request journal full original hashchain differs",
        )
        previous = event["event_sha256"]
    require(
        prefix == {"next_sequence": count, "last_event_sha256": previous},
        "request journal acknowledged prefix differs",
    )
    return count


class RequestDrainCollector(original.DrainCollector):
    def __init__(self, spec_path, journal_path, policy_path, drain_policy_path):
        spec_raw, _ = native.read_private(Path(spec_path), 0o600)
        policy_raw, _ = native.read_private(Path(policy_path), 0o600)
        raw, _ = native.read_private(Path(drain_policy_path), 0o600)
        spec, value = json.loads(spec_raw), json.loads(raw)
        phase_ids = [p["phase_id"] for p in spec["phases"]]
        require(
            1 <= len(phase_ids) <= MAX_PHASES
            and len(set(phase_ids)) == len(phase_ids)
            and value
            == {
                "schema": POLICY,
                "native_spec_sha256": native.sha(spec_raw),
                "tensor_policy_sha256": native.sha(policy_raw),
                "phase_ids": phase_ids,
                "required_ranks": [0, 1],
                "formal_registration": False,
            },
            "request drain policy is missing, changed, unbounded or promoted",
        )
        self.intake_clocks = {}
        # Deliberately bypass only the old single-phase policy constructor.
        # All original typed native/tensor/OP/drain accept algorithms are reused.
        original.attention.AttentionCollector.__init__(
            self, spec_path, journal_path, policy_path
        )
        self.lock = threading.RLock()
        self.source_sha256 = native.sha(Path(__file__).read_bytes())
        self.drain_policy_sha256 = native.sha(raw)
        self.sender_records = {}
        self.closed = set()
        self.sealed = {}
        self._append(
            {
                "kind": START_KIND,
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

    def _prefix(self):
        return {"next_sequence": self.sequence, "last_event_sha256": self.previous}

    def _journal_raw(self):
        descriptor = os.open(self.journal_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            meta = os.fstat(descriptor)
            require(
                stat.S_ISREG(meta.st_mode)
                and meta.st_uid == os.getuid()
                and stat.S_IMODE(meta.st_mode) == 0o600
                and [meta.st_dev, meta.st_ino]
                == [
                    self.archive_identity["journal_device"],
                    self.archive_identity["journal_inode"],
                ],
                "request journal identity differs",
            )
            chunks = []
            while chunk := os.read(descriptor, 1024 * 1024):
                chunks.append(chunk)
            raw = b"".join(chunks)
            require(len(raw) == meta.st_size, "request journal size changed")
            verify_raw_prefix(raw, self._prefix())
            return raw
        finally:
            os.close(descriptor)

    def accept(self, peer, raw):
        fact = json.loads(raw)
        require(isinstance(fact, dict), "request native fact is not an object")
        with self.lock:
            if fact.get("schema") == native.MAPPING:
                require(
                    all(runtime in self.sealed for runtime in self.maps),
                    "request collector permits one unfinished phase at a time",
                )
            ack = super().accept(peer, raw)
            if fact.get("schema") == original.drain.SCHEMA:
                runtime = fact["runtime_request_id"]
                phase = self.maps[runtime]
                ranks = sorted(
                    self.senders[pid]["process"]["ordinal"]
                    for pid, rid in self.closed
                    if rid == runtime
                )
                if ranks == phase["expected_ranks"]:
                    try:
                        require(
                            runtime not in self.sealed, "request phase sealed twice"
                        )
                        os.fsync(self.fd)
                        journal = self._journal_raw()
                        self.sealed[runtime] = {
                            "phase": copy.deepcopy(phase),
                            "ranks": ranks,
                            "complete": True,
                            "sealed_prefix": self._prefix(),
                            "sealed_prefix_bytes": len(journal),
                            "sealed_prefix_sha256": native.sha(journal),
                            "sealed_monotonic_ns": time.monotonic_ns(),
                        }
                    except BaseException:
                        self.failed = True
                        raise
            return ack

    def describe(self, socket_path):
        with self.lock:
            os.fsync(self.fd)
            journal = self._journal_raw()
            states = {}
            for runtime, phase in self.maps.items():
                if runtime in self.sealed:
                    snapshot = self.sealed[runtime]
                    require(
                        native.sha(journal[: snapshot["sealed_prefix_bytes"]])
                        == snapshot["sealed_prefix_sha256"],
                        "sealed request prefix bytes changed",
                    )
                    states[runtime] = copy.deepcopy(snapshot)
                else:
                    states[runtime] = {
                        "phase": copy.deepcopy(phase),
                        "ranks": sorted(
                            self.senders[pid]["process"]["ordinal"]
                            for pid, rid in self.closed
                            if rid == runtime
                        ),
                        "complete": False,
                        "sealed_prefix": None,
                        "sealed_prefix_bytes": None,
                        "sealed_prefix_sha256": None,
                        "sealed_monotonic_ns": None,
                    }
            meta = Path(socket_path).lstat()
            return {
                "schema": STATUS,
                "issued_monotonic_ns": time.monotonic_ns(),
                "spec_sha256": self.spec_sha256,
                "collector_source_sha256": self.source_sha256,
                "collector": self.collector_identity,
                "socket_identity": [meta.st_dev, meta.st_ino],
                "socket_path": str(socket_path),
                "archive_identity": self.archive_identity,
                "classification": "CPU_REVIEW_CANDIDATE_ONLY",
                "formal_producer_registration": False,
                "failed": self.failed,
                "acknowledged_prefix": self._prefix(),
                "source_drain": {
                    "schema": POLICY,
                    "policy_sha256": self.drain_policy_sha256,
                    "runtimes": states,
                },
            }


class RequestDrainHandler(native.Handler):
    def handle(self):
        peer = struct.unpack(
            "3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        try:
            frame = self.rfile.readline(native.MAX_FRAME + 1)
            require(
                frame.endswith(b"\n") and len(frame) <= native.MAX_FRAME,
                "request native frame is incomplete or oversized",
            )
            request = json.loads(frame)
            collector = self.server.collector
            if request == {"op": "describe"}:
                response = collector.describe(self.server.server_address)
            else:
                require(
                    set(request) == {"raw_base64"}, "unsupported request native frame"
                )
                response = collector.accept(
                    peer, base64.b64decode(request["raw_base64"], validate=True)
                )
        except (OSError, ValueError, KeyError, TypeError) as error:
            response = {
                "schema": "ecpa-request-native-collector-reject/v1",
                "reason": str(error),
                "formal_producer_registration": False,
            }
        self.wfile.write(native.canonical(response) + b"\n")


class RequestDrainServer(native.Server):
    def __init__(self, path, collector):
        super().__init__(path, collector)
        self.RequestHandlerClass = RequestDrainHandler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("spec", "policy", "journal", "socket", "drain-policy"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    collector = RequestDrainCollector(
        args.spec, args.journal, args.policy, args.drain_policy
    )
    with RequestDrainServer(args.socket, collector) as server:
        meta = args.socket.lstat()
        print(
            json.dumps(
                {
                    "collector": collector.collector_identity,
                    "socket_identity": [meta.st_dev, meta.st_ino],
                    "socket_path": str(args.socket),
                    "collector_source_sha256": collector.source_sha256,
                    "spec_sha256": collector.spec_sha256,
                    "policy_sha256": collector.policy_sha256,
                    "archive_identity": collector.archive_identity,
                }
            ),
            flush=True,
        )
        server.serve_forever()


if __name__ == "__main__":
    main()
