"""Live, request-scoped semantic witness producer for an independently gated reply.

The producer performs its own fresh private HTTP request and validates the full
worker tensor/operator/drain chain before quoting it. Every quote rechecks live
kernel epochs, source bytes, collector authentication and a nonrenewable lease.
This profile is nonformal and never authorizes a different request.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import socket
import stat
import struct
import threading
import time
import traceback
from pathlib import Path

from experiments.native_attention_candidate import drain_consumer
from experiments.native_challenge_candidate import collector_client
from vllm_hust_ext.config import load_config
from vllm_hust_ext.discovery import discover_bundles
from vllm_hust_ext.runtime_phase_handoff import process_identity
from vllm_hust_ext.semantic_runtime_binding import validate_semantic_launch_spec

REGISTRATION = "ecpa-live-native-semantic-registration/v1"
QUERY = "ecpa-live-native-semantic-query/v1"
QUOTE = "ecpa-live-native-semantic-quote/v1"
READY = "ecpa-live-native-semantic-producer-ready/v1"
SCOPE_FIELDS = (
    "execution_plan_id",
    "native_plan_id",
    "native_launch_id",
    "controller_instance",
    "candidate_generation",
    "membership_epoch",
)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def read_private(path, limit=2 * 1024 * 1024):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, "noncanonical private input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(meta.st_mode)
            and meta.st_uid == os.geteuid()
            and stat.S_IMODE(meta.st_mode) in (0o400, 0o600)
            and meta.st_size <= limit,
            "private input owner/mode/size differs",
        )
        return stream.read(limit + 1)


def read_environment(pid):
    return dict(
        part.split(b"=", 1)
        for part in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
        if b"=" in part
    )


class LiveProducer:
    def __init__(self, path):
        self.path = Path(path)
        self.raw = read_private(path)
        self.registration = r = json.loads(self.raw)
        require(
            r["schema"] == REGISTRATION and r["formal_result"] is False,
            "live producer registration classification differs",
        )
        require(
            type(r["max_validity_ns"]) is int
            and 0 < r["max_validity_ns"] <= 30_000_000_000,
            "live producer lease bound differs",
        )
        require(
            r["producer_source_path"] == str(Path(__file__).resolve())
            and r["producer_source_sha256"] == digest(Path(__file__).read_bytes()),
            "registered live producer source differs",
        )
        self.registration_sha256 = digest(canonical(r))
        self.scope = {key: r[key] for key in SCOPE_FIELDS}
        require(
            r["execution_plan_id"] == "plan:sha256:" + r["native_plan_id"],
            "native/compiled execution Plan differs",
        )
        enabled = load_config().enabled
        bundles = discover_bundles(enabled) if enabled else ()
        launch = validate_semantic_launch_spec(
            Path(r["semantic_launch_spec_path"]), bundles
        )
        require(
            all(
                launch[key] == r[key]
                for key in SCOPE_FIELDS
                if key != "native_launch_id"
            ),
            "semantic launch scope differs",
        )
        self.recipe = json.loads(read_private(r["recipe_path"]))
        self.phase = next(
            p for p in self.recipe["phases"] if p["phase_id"] == r["phase_id"]
        )
        self.spec = json.loads(read_private(r["spec_path"]))
        require(
            self.spec["native_plan_id"] == r["native_plan_id"]
            and self.spec["native_launch_id"] == r["native_launch_id"]
            and self.spec["senders"] == r["source_peers"],
            "native source registration differs",
        )
        require(not Path(r["probe_output"]).exists(), "probe output must be fresh")
        self.identity = process_identity(os.getpid())
        self.lock = threading.Lock()
        self.proof = None
        self.completed = False
        self.failure = None
        self.stop = threading.Event()
        self.baseline_files = {
            str(p): digest(read_private(p))
            for p in (
                self.path,
                Path(r["semantic_launch_spec_path"]),
                Path(r["plan_path"]),
                Path(r["binding_path"]),
                Path(r["recipe_path"]),
                Path(r["spec_path"]),
                Path(r["policy_path"]),
                Path(r["drain_policy_path"]),
            )
        }
        self.check_live()

    def check_live(self):
        r = self.registration
        require(
            process_identity(r["owner_identity"]["pid"]) == r["owner_identity"],
            "owner epoch changed",
        )
        require(
            process_identity(r["manager_identity"]["pid"]) == r["manager_identity"],
            "Manager epoch changed",
        )
        for peer in r["source_peers"]:
            process = peer["process"]
            current = process_identity(process["pid"])
            require(
                all(current[k] == process[k] for k in current),
                "worker/API epoch changed",
            )
            require(
                digest(Path(f"/proc/{process['pid']}/cmdline").read_bytes())
                == peer["cmdline_sha256"],
                "source command changed",
            )
            actual = read_environment(process["pid"])
            required = {
                "VLLM_ECPA_PLAN_ID": r["native_plan_id"],
                "VLLM_ECPA_LAUNCH_ID": r["native_launch_id"],
                "ECPA_SEMANTIC_EXECUTION_PLAN_ID": r["execution_plan_id"],
                "ECPA_SEMANTIC_CONTROLLER_INSTANCE": r["controller_instance"],
                "ECPA_SEMANTIC_CANDIDATE_GENERATION": str(r["candidate_generation"]),
                "ECPA_SEMANTIC_MEMBERSHIP_EPOCH": str(r["membership_epoch"]),
            }
            require(
                all(actual.get(k.encode()) == v.encode() for k, v in required.items()),
                "source process semantic scope differs",
            )
            for source in peer["source_files"]:
                require(
                    digest(Path(source["path"]).read_bytes()) == source["sha256"],
                    "worker source changed",
                )
        for path, expected in getattr(self, "baseline_files", {}).items():
            require(
                digest(read_private(path)) == expected,
                "frozen live registration input changed",
            )
        require(
            digest(Path(__file__).read_bytes()) == r["producer_source_sha256"],
            "producer source changed",
        )
        require(
            digest(Path(r["collector_source"]).read_bytes())
            == r["collector_descriptor"]["collector_source_sha256"],
            "collector source changed",
        )

    def authenticate(self):
        r = self.registration
        return collector_client.authenticate(
            Path(r["collector_socket_path"]),
            r["collector_descriptor"],
            Path(r["spec_path"]),
            Path(r["collector_source"]),
            drain_policy_path=Path(r["drain_policy_path"]),
        )

    def execute_probe(self):
        r = self.registration
        try:
            result = drain_consumer.execute_with_drain(
                self.recipe,
                r["phase_id"],
                Path(r["probe_output"]),
                socket_path=Path(r["collector_socket_path"]),
                descriptor=r["collector_descriptor"],
                spec_path=Path(r["spec_path"]),
                collector_source_path=Path(r["collector_source"]),
                journal_path=Path(r["journal_path"]),
                policy_path=Path(r["policy_path"]),
                drain_policy_path=Path(r["drain_policy_path"]),
            )
            require(
                result.get("mixed_attention_HTTP_ACK_join") is True
                and result.get("rpc_task_passed") is True,
                "fresh private probe semantic/task predicate failed",
            )
            observed = drain_consumer.verify_observation(
                self.recipe,
                r["phase_id"],
                Path(r["probe_output"]),
                descriptor=r["collector_descriptor"],
                spec_path=Path(r["spec_path"]),
                journal_path=Path(r["journal_path"]),
                policy_path=Path(r["policy_path"]),
                drain_policy_path=Path(r["drain_policy_path"]),
            )
            self.check_live()
            after = self.authenticate()
            require(
                drain_consumer.verify_sealed_status(
                    after, self.phase, r["drain_policy_path"]
                ),
                "source closure unavailable live",
            )
            original = json.loads(
                (Path(r["probe_output"]) / "collector-after.json").read_bytes()
            )
            require(
                after["status"]["acknowledged_prefix"]
                == original["status"]["acknowledged_prefix"],
                "live source prefix changed",
            )
            require(
                observed["tensor_receipt_count"]
                == observed["operator_receipt_count"]
                == 56,
                "live semantic receipt coverage differs",
            )
            completed = time.monotonic_ns()
            observation_raw = canonical(observed)
            response = (Path(r["probe_output"]) / "response.bin").read_bytes()
            request = (Path(r["probe_output"]) / "request.bin").read_bytes()
            with self.lock:
                self.proof = {
                    "observation_sha256": digest(observation_raw),
                    "request_sha256": digest(request),
                    "response_sha256": digest(response),
                    "issued_monotonic_ns": completed,
                    "expires_monotonic_ns": completed + r["max_validity_ns"],
                    "tensor_receipts": 56,
                    "operator_receipts": 56,
                    "worker_closures": 2,
                    "full_prefix_records": after["status"]["acknowledged_prefix"][
                        "next_sequence"
                    ],
                }
                self.journal_sha256 = digest(Path(r["journal_path"]).read_bytes())
                self.final_prefix = after["status"]["acknowledged_prefix"]
                self.completed = True
            (self.path.parent / "producer-completion.json").write_bytes(
                canonical(
                    {
                        "schema": "ecpa-live-native-semantic-completion/v1",
                        "producer": self.identity,
                        "registration_sha256": self.registration_sha256,
                        "scope": self.scope,
                        "proof": self.proof,
                        "formal_result": False,
                    }
                )
            )
        except Exception as exc:
            with self.lock:
                self.failure = str(exc)
                self.completed = True
            (self.path.parent / "producer-failure.txt").write_text(
                traceback.format_exc()
            )

    def quote(self, query):
        require(
            set(query) == {"schema", "nonce", "registration_sha256"}
            and query["schema"] == QUERY
            and re.fullmatch(r"[0-9a-f]{64}", query["nonce"])
            and query["registration_sha256"] == self.registration_sha256,
            "live query identity differs",
        )
        response = {
            "schema": QUOTE,
            "nonce": query["nonce"],
            "registration_sha256": self.registration_sha256,
            "producer": self.identity,
            "scope": self.scope,
            "ready": False,
            "reason": "private probe pending",
            "proof": None,
            "formal_result": False,
        }
        with self.lock:
            proof = dict(self.proof) if self.proof else None
            failure = self.failure
        if failure:
            response["reason"] = "private probe failed: " + failure
            return response
        if proof is None:
            return response
        try:
            self.check_live()
            require(
                time.monotonic_ns() < proof["expires_monotonic_ns"],
                "semantic lease expired",
            )
            after = self.authenticate()
            require(
                after["status"]["acknowledged_prefix"] == self.final_prefix
                and drain_consumer.verify_sealed_status(
                    after, self.phase, self.registration["drain_policy_path"]
                ),
                "source full prefix or closure changed",
            )
            require(
                digest(Path(self.registration["journal_path"]).read_bytes())
                == self.journal_sha256,
                "source journal changed after closure",
            )
            proof["issued_monotonic_ns"] = time.monotonic_ns()
            require(
                proof["issued_monotonic_ns"] < proof["expires_monotonic_ns"],
                "semantic lease expired",
            )
            response.update(
                ready=True,
                reason="finite request verified; current epochs and fixed lease valid",
                proof=proof,
            )
        except Exception as exc:
            response["reason"] = str(exc)
        return response

    def serve(self):
        r = self.registration
        path = Path(r["producer_socket"])
        require(
            path.is_absolute() and not os.path.lexists(path),
            "producer socket must be fresh",
        )
        parent = path.parent.stat()
        require(
            parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) == 0o700,
            "producer socket parent is not private",
        )
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            path.chmod(0o600)
            listener.listen(4)
            listener.settimeout(0.5)
            meta = path.stat()
            ready = {
                "schema": READY,
                "producer": self.identity,
                "source_sha256": digest(Path(__file__).read_bytes()),
                "socket_path": str(path),
                "socket_identity": {"device": meta.st_dev, "inode": meta.st_ino},
                "registration_sha256": self.registration_sha256,
            }
            print(json.dumps(ready), flush=True)
            threading.Thread(target=self.execute_probe, daemon=True).start()
            while not self.stop.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    connection.settimeout(30)
                    try:
                        _, uid, _ = struct.unpack(
                            "3i",
                            connection.getsockopt(
                                socket.SOL_SOCKET, socket.SO_PEERCRED, 12
                            ),
                        )
                        require(uid == os.geteuid(), "foreign authority uid")
                        frame = b""
                        while not frame.endswith(b"\n"):
                            data = connection.recv(65536)
                            require(
                                data and len(frame) + len(data) <= 65536,
                                "query incomplete/oversized",
                            )
                            frame += data
                        connection.sendall(
                            canonical(self.quote(json.loads(frame))) + b"\n"
                        )
                    except Exception:
                        continue
        path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", required=True, type=Path)
    args = parser.parse_args()
    producer = LiveProducer(args.registration)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: producer.stop.set())
    producer.serve()


if __name__ == "__main__":
    main()
