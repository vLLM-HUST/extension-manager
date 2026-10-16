"""Fresh baseline native-effect probe; never a Manager execution attestation.

Host activation is a prerequisite only. The unchanged native HTTP/tensor/OP/drain
consumer independently establishes the finite request effect before any proof.
The independent cell issuer/controller is deliberately outside this module.
"""

from __future__ import annotations

import argparse
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

from experiments.native_attention_candidate import baseline_native_scope as scopes
from experiments.native_attention_candidate import drain_consumer
from experiments.native_attention_candidate import semantic_producer_registry as util
from experiments.native_attention_candidate.baseline_host_binding import (
    SCHEMA as HOST_SCHEMA,
)
from experiments.native_attention_candidate.live_semantic_producer import (
    read_environment,
    read_private,
)
from experiments.native_challenge_candidate import collector_client
from vllm_hust_ext.activation_profile import (
    CONFIG_ENV,
    ENABLE_ENV,
    PATH_ENV,
    SHA_ENV,
    load_activation_profile,
)
from vllm_hust_ext.runtime_phase_handoff import process_identity

REGISTRATION = "ecpa-baseline-live-semantic-registration/v1"
QUERY = "ecpa-baseline-live-semantic-query/v1"
QUOTE = "ecpa-baseline-live-semantic-quote/v1"
READY = "ecpa-baseline-live-semantic-producer-ready/v1"
COMPLETION = "ecpa-baseline-live-semantic-completion/v1"
ORIGIN = "baseline-host-observer"
FIELDS = {
    "schema",
    "origin",
    "baseline_scope_reference",
    "host_observer_receipt_reference",
    "activation_profile_reference",
    "common_query_reference",
    "owner_kernel",
    "host_kernel",
    "observer_kernel",
    "observer_socket_path",
    "source_peers",
    "recipe_path",
    "phase_id",
    "probe_output",
    "spec_path",
    "journal_path",
    "policy_path",
    "drain_policy_path",
    "collector_source",
    "collector_descriptor",
    "collector_socket_path",
    "producer_socket",
    "producer_source_path",
    "producer_source_sha256",
    "max_validity_ns",
    "formal_result",
}
canonical, digest, require = util.canonical, util.sha, util.require
RESERVED_OUTPUTS = (
    "baseline-producer-completion.json",
    "baseline-producer-failure.txt",
)


def _write_new(path, raw):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


class BaselineLiveProducer:
    """Independent baseline schema, real epochs and nonrenewable native proof.

    Write a mode0600 registration with exactly FIELDS. Artifact references are
    {path, sha256} of raw private bytes; common_query_reference must be canonical
    phase.payload. owner_kernel and observer_kernel identify the actual owner
    holding HostObserver, not a declared Manager. source_peers are the original
    collector senders, including cmdline/source hashes and captured Host roles.

    Construct from that fresh file, then serve() in the independent process (CLI
    --registration does this). READY announces an endpoint, never effect success.
    Each QUERY uses a new64hex nonce and SHA256(canonical(registration)); QUOTE
    repeats its baseline origin/scope. Only ready=true carries full native proof.
    The owner may also call execute_probe() once and quote(query) directly for a
    local lifecycle; neither creates a permit, deployment or response authority.
    """

    def __init__(self, registration_path):
        self.path = Path(registration_path)
        self.raw = read_private(self.path)
        require(
            all(
                not os.path.lexists(self.path.with_name(name))
                for name in RESERVED_OUTPUTS
            ),
            "baseline reserved producer evidence output is not fresh",
        )
        r = self.registration = json.loads(self.raw, object_pairs_hook=scopes._unique)
        require(
            set(r) == FIELDS
            and r["schema"] == REGISTRATION
            and r["origin"] == ORIGIN
            and r["formal_result"] is False,
            "baseline producer fields/origin differ",
        )
        require(
            type(r["max_validity_ns"]) is int
            and r["max_validity_ns"] == 30_000_000_000,
            "baseline fixed30s lease required",
        )
        require(
            r["producer_source_path"] == str(Path(__file__).resolve())
            and r["producer_source_sha256"] == digest(Path(__file__).read_bytes()),
            "baseline producer source differs",
        )
        self.registration_sha256 = digest(canonical(r))
        self.native_scope = scopes.BaselineNativeScope(
            scopes._reference(r["baseline_scope_reference"])
        )
        self.scope = self.native_scope.value()
        profile_ref = r["activation_profile_reference"]
        require(
            set(profile_ref) == {"path", "sha256"}, "baseline profile reference differs"
        )
        self.profile = load_activation_profile(
            Path(profile_ref["path"]), profile_ref["sha256"]
        )
        require(
            self.profile.sha256 == self.scope["activation_profile_sha256"],
            "baseline activation profile differs",
        )
        self.receipt = scopes._object(r["host_observer_receipt_reference"])
        receipt = self.receipt
        require(
            receipt["schema"] == HOST_SCHEMA
            and receipt["origin"] == ORIGIN
            and receipt["activation_only"] is True
            and receipt["effect_qualification"] is None
            and receipt["formal_result"] is False
            and all(
                receipt[key] == self.scope[key]
                for key in ("observer_trial_id", "arm", "activation_profile_sha256")
            ),
            "baseline observer prerequisite differs",
        )
        require(
            receipt["owner"] == r["owner_kernel"] == r["observer_kernel"]
            and receipt["host"] == r["host_kernel"],
            "baseline owner/Host observer epochs differ",
        )
        scopes._receipt_sources_and_prefix(receipt)
        self.recipe = json.loads(read_private(r["recipe_path"]))
        require(
            len(self.recipe["phases"]) == 1, "baseline finite single request required"
        )
        self.phase = self.recipe["phases"][0]
        require(self.phase["phase_id"] == r["phase_id"], "baseline phase differs")
        query_raw = scopes._reference(r["common_query_reference"])
        require(
            digest(query_raw) == self.scope["common_query_sha256"]
            and query_raw == canonical(self.phase["payload"]),
            "baseline common query must be the exact canonical request",
        )
        self.spec = json.loads(read_private(r["spec_path"]))
        aliases = self.scope["native_correlation"]
        require(
            self.spec["native_plan_id"] == aliases["plan_id"]
            and self.spec["native_launch_id"] == aliases["launch_id"]
            and canonical(self.spec["senders"]) == canonical(r["source_peers"]),
            "baseline native correlation/senders differ",
        )
        expected = {row["process"]["pid"]: row for row in receipt["peers"]}
        peers = r["source_peers"]
        require(
            len(peers) == len(expected) == 3
            and len({p["process"]["pid"] for p in peers}) == 3
            and {(p["process"]["role"], p["process"]["ordinal"]) for p in peers}
            == {("api-server", 0), ("worker", 0), ("worker", 1)},
            "baseline TP2 membership differs",
        )
        for peer in peers:
            require(
                peer["process"] == expected[peer["process"]["pid"]]["process"],
                "baseline sender differs from captured Host-assigned peer",
            )
        require(
            not os.path.lexists(r["probe_output"]),
            "baseline private probe output must be fresh",
        )
        self.identity = process_identity(os.getpid())
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.proof = None
        self.failure = None
        self.completed = False
        self.started = False
        self.seen_nonces = set()
        paths = [
            self.path,
            Path(r["recipe_path"]),
            Path(r["spec_path"]),
            Path(r["policy_path"]),
            Path(r["drain_policy_path"]),
        ]
        paths += [
            Path(r[key]["path"])
            for key in (
                "baseline_scope_reference",
                "host_observer_receipt_reference",
                "activation_profile_reference",
                "common_query_reference",
            )
        ]
        self.baseline_files = {str(path): digest(read_private(path)) for path in paths}
        self.check_live()

    def check_live(self):
        r = self.registration
        for key in ("owner_kernel", "host_kernel", "observer_kernel"):
            util._kernel(r[key])
        require(
            scopes._reference(r["baseline_scope_reference"]) == self.native_scope.raw
            and scopes._object(r["host_observer_receipt_reference"]) == self.receipt,
            "baseline scope/activation receipt changed",
        )
        self.profile.validate_installed()
        self._check_activation_prefix()
        from experiments.native_attention_candidate.baseline_host_binding import (
            _ancestors,
            _socket,
        )

        require(
            _socket(r["observer_socket_path"]) == self.receipt["socket"],
            "baseline observer socket changed",
        )
        aliases = self.scope["native_correlation"]
        expected_env = {
            PATH_ENV: str(self.profile.path),
            SHA_ENV: self.profile.sha256,
            ENABLE_ENV: "1",
            CONFIG_ENV: canonical(self.profile.configuration).decode(),
            "ECPA_ACTIVATION_CONTRACT": self.scope["arm"],
            "ECPA_BASELINE_HOST_OBSERVER_TRIAL": self.scope["observer_trial_id"],
            "ECPA_BASELINE_HOST_OBSERVER_SOCKET": r["observer_socket_path"],
            "ECPA_BASELINE_HOST_OBSERVER_OWNER": canonical(
                r["observer_kernel"]
            ).decode(),
            "VLLM_ECPA_EVIDENCE_SINK": (
                "experiments.native_attention_candidate.baseline_host_binding:record_event"
            ),
            "VLLM_ECPA_EVIDENCE_STRICT": "1",
            "VLLM_ECPA_PLAN_ID": aliases["plan_id"],
            "VLLM_ECPA_LAUNCH_ID": aliases["launch_id"],
            scopes.PATH_ENV: r["baseline_scope_reference"]["path"],
            scopes.SHA_ENV: r["baseline_scope_reference"]["sha256"],
        }
        for peer in r["source_peers"]:
            p = peer["process"]
            kernel = {key: p[key] for key in util.KERNEL}
            util._kernel(kernel)
            chain = _ancestors(p["pid"])
            require(
                r["host_kernel"] in chain and r["owner_kernel"] in chain,
                "baseline peer left owned Host subtree",
            )
            require(
                digest(Path(f"/proc/{p['pid']}/cmdline").read_bytes())
                == peer["cmdline_sha256"],
                "baseline source command changed",
            )
            actual = read_environment(p["pid"])
            require(
                all(
                    actual.get(k.encode()) == v.encode()
                    for k, v in expected_env.items()
                )
                and actual.get(b"VLLMHUST_EXT_ENABLED_BUNDLES") in (None, b"")
                and not any(k.startswith(b"ECPA_SEMANTIC_") for k in actual)
                and b"VLLM_HUST_EXT_EVIDENCE_PATH" not in actual,
                "baseline actual process scope/config differs",
            )
            util._files({s["path"]: s["sha256"] for s in peer["source_files"]})
        for path, expected in self.baseline_files.items():
            require(
                digest(read_private(path)) == expected, "baseline frozen input changed"
            )
        require(
            digest(Path(__file__).read_bytes()) == r["producer_source_sha256"]
            and digest(Path(r["collector_source"]).read_bytes())
            == r["collector_descriptor"]["collector_source_sha256"],
            "baseline producer/collector source changed",
        )

    def _check_activation_prefix(self):
        """Reconstruct source-bearing ingress, not caller-asserted peer roles."""
        from importlib import metadata

        from experiments.native_attention_candidate import (
            baseline_host_binding as observer,
        )

        receipt = self.receipt
        scopes._receipt_sources_and_prefix(receipt)
        dist = metadata.distribution("vllm")
        paths = {
            str(Path(str(dist.locate_file(p))).resolve())
            for p in (
                "vllm/plugins/__init__.py",
                "vllm/plugins/evidence.py",
                "vllm/entrypoints/cli/main.py",
                "vllm/v1/executor/multiproc_executor.py",
                "vllm/v1/engine/core.py",
            )
        }
        require(
            set(receipt["host_sources"]) == paths
            and receipt["observer_source"]
            == {
                "path": str(Path(observer.__file__).resolve()),
                "sha256": digest(Path(observer.__file__).read_bytes()),
            },
            "baseline actual Host/observer source origin differs",
        )
        rows = [
            json.loads(line)
            for line in Path(receipt["journal"]["path"]).read_bytes().splitlines()
        ]
        for row in rows:
            envelope = row["envelope"]
            require(
                envelope["schema"] == HOST_SCHEMA
                and envelope["sender"] == row["kernel"]
                and envelope["trial"] == self.scope["observer_trial_id"]
                and envelope["profile_sha256"] == self.profile.sha256
                and envelope["observer_source"] == receipt["observer_source"]
                and receipt["owner"] in row["ancestors"]
                and receipt["host"] in row["ancestors"],
                "baseline raw Host ingress identity differs",
            )
        peers = receipt["peers"]
        require(
            len(peers) == len({p["kernel"]["pid"] for p in peers}) == 3,
            "baseline captured peer kernels repeated",
        )
        for peer in peers:
            p = peer["process"]
            require(
                {k: p[k] for k in util.KERNEL} == peer["kernel"]
                and p["assignment_source"] == "host",
                "baseline captured Host-assigned kernel differs",
            )
            events = [row for row in rows if row["kernel"] == peer["kernel"]]
            require(
                any(
                    row["envelope"]["payload"]["process"].get("assignment_source")
                    == "host"
                    and all(
                        p.get(k) == v
                        for k, v in row["envelope"]["payload"]["process"].items()
                    )
                    for row in events
                ),
                "baseline captured role has no authenticated Host callback",
            )
            first, last = (
                peer["activation_resolved_sequence"],
                peer["activation_invoked_sequence"],
            )
            require(
                type(first) is int
                and type(last) is int
                and 0 <= first < last < len(rows),
                "baseline activation ordering differs",
            )
            for index, event in ((first, "resolved"), (last, "invoked")):
                payload = rows[index]["envelope"]["payload"]
                require(
                    rows[index]["kernel"] == peer["kernel"]
                    and payload["event"] == event
                    and payload["entry_point"]
                    == {
                        "group": "vllm.general_plugins",
                        "name": "ascend_kvcompress",
                        "value": "vllm_ascend_kvcompress.plugin:register",
                    },
                    "baseline selected callable raw join differs",
                )
            require(
                rows[first]["envelope"]["payload"].get("detail")
                == (
                    None
                    if self.scope["arm"] == "entry-points-unmanaged"
                    else "baseline-explicit-callable"
                )
                and not any(
                    row["envelope"]["payload"]["event"] == "failed"
                    and row["envelope"]["payload"].get("entry_point", {}).get("name")
                    == "ascend_kvcompress"
                    for row in events
                ),
                "baseline activation arm/failed callback differs",
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

    def _consumer_arguments(self):
        r = self.registration
        return {
            "descriptor": r["collector_descriptor"],
            "spec_path": Path(r["spec_path"]),
            "journal_path": Path(r["journal_path"]),
            "policy_path": Path(r["policy_path"]),
            "drain_policy_path": Path(r["drain_policy_path"]),
        }

    def execute_probe(self):
        with self.lock:
            require(not self.started, "baseline private probe already started")
            self.started = True
        r = self.registration
        try:
            self.check_live()
            result = drain_consumer.execute_with_drain(
                self.recipe,
                r["phase_id"],
                Path(r["probe_output"]),
                socket_path=Path(r["collector_socket_path"]),
                collector_source_path=Path(r["collector_source"]),
                **self._consumer_arguments(),
            )
            require(
                result.get("mixed_attention_HTTP_ACK_join") is True
                and result.get("rpc_task_passed") is True,
                "baseline fresh private task/native predicate failed",
            )
            observed = drain_consumer.verify_observation(
                self.recipe,
                r["phase_id"],
                Path(r["probe_output"]),
                **self._consumer_arguments(),
            )
            self.check_live()
            after = self.authenticate()
            require(
                drain_consumer.verify_sealed_status(
                    after, self.phase, r["drain_policy_path"]
                ),
                "baseline source closures unavailable live",
            )
            original = json.loads(
                (Path(r["probe_output"]) / "collector-after.json").read_bytes()
            )
            require(
                canonical(after["status"]["acknowledged_prefix"])
                == canonical(original["status"]["acknowledged_prefix"]),
                "baseline final source prefix changed",
            )
            require(
                observed["tensor_receipt_count"]
                == observed["operator_receipt_count"]
                == 56
                and observed["finite_native_argument_completion_join"] is True
                and observed["observed_typed_HTTP_ACK_join"] is True,
                "baseline native effect coverage differs",
            )
            out = Path(r["probe_output"])
            request, response = (
                (out / "request.bin").read_bytes(),
                (out / "response.bin").read_bytes(),
            )
            require(
                request == canonical(self.phase["payload"]),
                "baseline executed different request",
            )
            require(
                observed["whole_journal_sha256"]
                == digest(Path(r["journal_path"]).read_bytes())
                and observed["actual_raw_response_sha256"] == digest(response),
                "baseline verified raw journal/response drifted before proof",
            )
            self.check_live()
            now = time.monotonic_ns()
            proof = {
                "observation_sha256": digest(canonical(observed)),
                "request_sha256": digest(request),
                "response_sha256": digest(response),
                "issued_monotonic_ns": now,
                "expires_monotonic_ns": now + r["max_validity_ns"],
                "tensor_receipts": 56,
                "operator_receipts": 56,
                "worker_closures": 2,
                "full_prefix_records": after["status"]["acknowledged_prefix"][
                    "next_sequence"
                ],
            }
            journal_sha256 = digest(Path(r["journal_path"]).read_bytes())
            _write_new(
                self.path.with_name(RESERVED_OUTPUTS[0]),
                canonical(
                    {
                        "schema": COMPLETION,
                        "origin": ORIGIN,
                        "producer": self.identity,
                        "registration_sha256": self.registration_sha256,
                        "scope": self.scope,
                        "proof": proof,
                        "formal_result": False,
                    }
                ),
            )
            # Do not expose a proof until its exclusive completion record exists.
            with self.lock:
                self.proof = proof
                self.journal_sha256 = journal_sha256
                self.response_sha256 = digest(response)
                self.final_prefix = after["status"]["acknowledged_prefix"]
                self.completed = True
        except Exception as exc:
            with self.lock:
                self.failure, self.completed = str(exc), True
            _write_new(
                self.path.with_name(RESERVED_OUTPUTS[1]),
                traceback.format_exc().encode(),
            )

    def quote(self, query):
        require(
            set(query) == {"schema", "nonce", "registration_sha256"}
            and query["schema"] == QUERY
            and isinstance(query["nonce"], str)
            and re.fullmatch(r"[0-9a-f]{64}", query["nonce"])
            and query["registration_sha256"] == self.registration_sha256,
            "baseline quote query differs",
        )
        with self.lock:
            require(
                query["nonce"] not in self.seen_nonces
                and len(self.seen_nonces) < 50000,
                "baseline query nonce replay/exhaustion",
            )
            self.seen_nonces.add(query["nonce"])
            proof = dict(self.proof) if self.proof else None
            failure = self.failure
        response = {
            "schema": QUOTE,
            "origin": ORIGIN,
            "nonce": query["nonce"],
            "registration_sha256": self.registration_sha256,
            "producer": self.identity,
            "scope": self.scope,
            "ready": False,
            "reason": failure or "private baseline native probe pending",
            "proof": None,
            "formal_result": False,
        }
        if failure or proof is None:
            return response
        try:
            self.check_live()
            require(
                time.monotonic_ns() < proof["expires_monotonic_ns"],
                "baseline fixed lease expired",
            )
            after = self.authenticate()
            require(
                canonical(after["status"]["acknowledged_prefix"])
                == canonical(self.final_prefix)
                and drain_consumer.verify_sealed_status(
                    after, self.phase, self.registration["drain_policy_path"]
                ),
                "baseline final prefix/closure changed",
            )
            require(
                digest(Path(self.registration["journal_path"]).read_bytes())
                == self.journal_sha256
                and digest(
                    (
                        Path(self.registration["probe_output"]) / "response.bin"
                    ).read_bytes()
                )
                == self.response_sha256,
                "baseline raw journal/response changed",
            )
            self.check_live()
            proof["issued_monotonic_ns"] = time.monotonic_ns()
            require(
                proof["issued_monotonic_ns"] < proof["expires_monotonic_ns"],
                "baseline fixed lease expired",
            )
            response.update(
                ready=True,
                reason=(
                    "fresh baseline native effect verified; "
                    "current epochs and original lease valid"
                ),
                proof=proof,
            )
        except Exception as exc:
            with self.lock:
                self.failure = str(exc)  # Never reopen after epoch/source/expiry loss.
            response["reason"] = str(exc)
        return response

    def serve(self):
        path = Path(self.registration["producer_socket"])
        require(
            path.is_absolute()
            and path.parent.resolve() == path.parent
            and not os.path.lexists(path),
            "baseline producer socket not fresh/canonical",
        )
        parent = path.parent.stat()
        require(
            parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) == 0o700,
            "baseline producer socket directory not private",
        )
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            path.chmod(0o600)
            listener.listen(4)
            listener.settimeout(0.1)
            meta = path.stat()
            print(
                json.dumps(
                    {
                        "schema": READY,
                        "origin": ORIGIN,
                        "producer": self.identity,
                        "source_sha256": digest(Path(__file__).read_bytes()),
                        "socket_path": str(path),
                        "socket_identity": {
                            "device": meta.st_dev,
                            "inode": meta.st_ino,
                        },
                        "registration_sha256": self.registration_sha256,
                        "formal_result": False,
                    }
                ),
                flush=True,
            )
            threading.Thread(target=self.execute_probe, daemon=True).start()
            while not self.stop.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    connection.settimeout(15)
                    try:
                        pid, uid, _ = struct.unpack(
                            "3i",
                            connection.getsockopt(
                                socket.SOL_SOCKET, socket.SO_PEERCRED, 12
                            ),
                        )
                        require(
                            uid == os.geteuid()
                            and process_identity(pid)
                            == self.registration["owner_kernel"],
                            "baseline querying owner epoch differs",
                        )
                        raw = b""
                        while not raw.endswith(b"\n"):
                            chunk = connection.recv(65536)
                            require(
                                chunk and len(raw) + len(chunk) <= 65536,
                                "baseline query incomplete/oversized",
                            )
                            raw += chunk
                        require(raw.count(b"\n") == 1, "baseline query trailing frame")
                        connection.sendall(
                            canonical(self.quote(json.loads(raw))) + b"\n"
                        )
                    except Exception:
                        continue
        path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", required=True, type=Path)
    producer = BaselineLiveProducer(parser.parse_args().registration)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: producer.stop.set())
    producer.serve()


if __name__ == "__main__":
    main()
