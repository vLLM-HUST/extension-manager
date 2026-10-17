"""Source-owned immutable producer grants and independently challenged endpoints."""

from __future__ import annotations

import json
import os
import secrets
import socket
import stat
import struct
import time
from pathlib import Path

from experiments.exposure_gate import native_semantic_collector as native
from experiments.formal_campaign.h3_dynamic_authority import check_ref, require
from experiments.formal_campaign.h3_observer_live_registration import (
    DOMAIN,
    ValidatedLiveStart,
)
from experiments.formal_campaign.h3_observer_paths import create_private_directory

POLICY = "ecpa-native-observer-rebind-policy/v2"
COMMAND = "ecpa-native-observer-rebind-command/v1"


def write_private(path, value):
    raw = native.canonical(value)
    require(
        len(raw) <= native.MAX_FRAME,
        "live private record exceeds original bounded reader",
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, "immutable grant short write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return {"path": str(path), "sha256": native.sha(raw)}


def recheck_scope(scope):
    require(
        type(scope) is ValidatedLiveStart,
        "independently issued live-start scope required",
    )
    receipt = json.loads(check_ref(scope.receipt_ref()).read_bytes())
    root = Path(__file__).resolve().parents[2]
    for relative, expected in receipt["protocol_sources"].items():
        path = root / relative
        require(
            native.sha(path.read_bytes()) == expected.removeprefix("sha256:"),
            "live protocol source changed after independent issuance",
        )
    native.source_digests(receipt["host_sources"])
    return receipt


class LiveGrants:
    def __init__(self, authority, scope):
        from experiments.formal_campaign.h3_observer_authority import NativeAuthority

        require(
            type(authority) is NativeAuthority and type(scope) is ValidatedLiveStart,
            "actual original authority and independently issued v2 scope required",
        )
        value = scope.value()
        require(
            value["start"] == authority.start,
            "v2 scope does not select this exact original start",
        )
        self.authority, self.scope = authority, scope
        self.value = value
        self.receipt = recheck_scope(scope)
        self.directory = Path(value["declaration"]["grant_directory"])
        require(
            self.directory == authority.output / "live-observer-control",
            "grant root differs from exact original owned start",
        )
        self.group = []
        self.policies = {}
        self.endpoints = []
        self.endpoint_proof = None
        self.initial_descriptor = None

    def recheck(self):
        self.authority._source_current()
        recheck_scope(self.scope)
        require(
            self.authority.start == self.value["start"],
            "original source-owned start changed",
        )
        for policy, reference in self.policies.values():
            raw, _ = native.read_private(Path(reference["path"]), 0o600)
            require(
                native.sha(raw) == reference["sha256"]
                and raw == native.canonical(policy),
                "original immutable producer grant changed",
            )
        if self.endpoint_proof is not None:
            reference, expected = self.endpoint_proof
            raw, _ = native.read_private(Path(reference["path"]), 0o600)
            require(
                native.sha(raw) == reference["sha256"] and raw == expected,
                "independent all-producer enrollment bytes changed",
            )

    def before_publication(self, *, process, descriptor, contexts):
        """Actual collector exists; grants become durable before context visibility."""
        self.recheck()
        authority = self.authority
        require(
            authority.route.generation is None and not self.group,
            "grant publication must precede first admission and occur once",
        )
        require(
            process.poll() is None
            and native.identity(process.pid) == descriptor["collector"],
            "initial collector is not actual owned ready process",
        )
        spec_raw, _ = native.read_private(
            Path(contexts["semantic"]["spec_path"]), 0o600
        )
        require(
            native.sha(spec_raw)
            == contexts["semantic"]["spec_sha256"]
            == contexts["tensor"]["spec_sha256"],
            "initial paired context/spec SHA differs",
        )
        self.initial_descriptor = json.loads(native.canonical(descriptor))
        spec = json.loads(spec_raw)
        require(
            spec["native_plan_id"] == authority.enrollment["plan_id"]
            and spec["native_launch_id"] == authority.enrollment["launch_id"]
            and len(spec["phases"]) == 60,
            "initial actual fullPlan/60 scope differs",
        )
        controller = native.identity(os.getpid())
        argv = Path(f"/proc/{os.getpid()}/cmdline").read_bytes()
        require(
            [p.decode() for p in argv.split(b"\0") if p]
            == authority.start["authority"]["command"],
            "controller is not original source-issued complete authority argv",
        )
        root = Path(__file__).resolve().parents[2]
        controller_sources = [
            {"path": str(root / relative), "sha256": sha.removeprefix("sha256:")}
            for relative, sha in self.receipt["protocol_sources"].items()
        ]
        native.source_digests(controller_sources)
        create_private_directory(self.directory)
        for sender in spec["senders"]:
            process_identity = sender["process"]
            actual = native.identity(process_identity["pid"])
            require(
                all(process_identity[k] == v for k, v in actual.items()),
                "grant producer not exact original native sender",
            )
            role = process_identity["role"]
            ordinal = process_identity["ordinal"]
            from experiments.formal_campaign.h3_observer_live_registration import (
                actual_control_path,
            )

            control_path = actual_control_path(self.directory, actual["pid"])
            own = control_path.parent
            create_private_directory(own)
            self.group.append(
                dict(
                    producer=actual,
                    role=role,
                    ordinal=ordinal,
                    socket_path=str(control_path),
                    ready_path=str(own / "control-ready.json"),
                    source_files=sender["source_files"],
                    cmdline_sha256=sender["cmdline_sha256"],
                    control_nonce=secrets.token_hex(32),
                )
            )
        require(
            [(m["role"], m["ordinal"]) for m in self.group]
            == [("api-server", 0), ("worker", 0), ("worker", 1)],
            "original API+TP2 producer order differs",
        )
        phase = json.loads(check_ref(authority.start["recipe_template"]).read_bytes())[
            "arms"
        ][authority.start["arm"]]["phases"][0]
        bootstrap = phase["native_bootstrap"]
        refs = {
            channel: {
                "path": bootstrap[
                    "native_context_path"
                    if channel == "semantic"
                    else "tensor_context_path"
                ],
                "sha256": native.sha(native.canonical(value)),
            }
            for channel, value in contexts.items()
        }
        for member in self.group:
            pid = member["producer"]["pid"]
            channels = {"semantic": refs["semantic"]}
            if member["role"] == "worker":
                channels["tensor"] = refs["tensor"]
            policy = dict(
                schema=POLICY,
                domain=DOMAIN,
                start_id=authority.start["start_id"],
                receipt_sha256=self.scope.receipt_ref()["sha256"],
                producer=member["producer"],
                controller=controller,
                controller_cmdline_sha256=native.sha(argv),
                controller_source_files=controller_sources,
                producer_source_files=member["source_files"],
                native_plan_id=spec["native_plan_id"],
                native_launch_id=spec["native_launch_id"],
                socket_path=member["socket_path"],
                journal_path=str(self.directory / str(pid) / "producer-control.jsonl"),
                ready_path=member["ready_path"],
                producer_group=self.group,
                control_nonce=member["control_nonce"],
                initial_contexts=channels,
                max_recovery_ns=30_000_000_000,
            )
            reference = write_private(self.directory / f"{pid}.json", policy)
            self.policies[str(pid)] = (policy, reference)
        write_private(
            self.directory / "immutable-grant-index.json",
            dict(
                schema="ecpa-h3-observer-immutable-grant-index/v2",
                start_id=authority.start["start_id"],
                receipt=self.scope.receipt_ref(),
                controller=controller,
                original_producers=self.group,
                policies={key: value[1] for key, value in self.policies.items()},
                source_complete=False,
                native_completion_proved=False,
            ),
        )

    def wait_actual_endpoints(self, deadline_ns):
        """Readiness requires real peer credentials, exact inode, nonce and source."""
        self.recheck()
        require(
            not self.endpoints and len(self.group) == 3,
            "initial actual grant publication absent/replayed",
        )
        observations = []
        for member in self.group:
            path = Path(member["ready_path"])
            while not path.exists():
                require(
                    time.monotonic_ns() < deadline_ns,
                    "original ready bound expired before producer endpoint",
                )
                require(
                    native.identity(member["producer"]["pid"]) == member["producer"],
                    "original producer lost during grant startup",
                )
                time.sleep(0.01)
            raw, _ = native.read_private(path, 0o600)
            ready = json.loads(raw)
            sock = Path(member["socket_path"])
            info, parent = sock.lstat(), sock.parent.lstat()
            require(
                stat.S_ISSOCK(info.st_mode)
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.getuid()
                and info.st_gid == os.getgid()
                and stat.S_IMODE(parent.st_mode) == 0o700
                and parent.st_uid == os.getuid(),
                "actual producer endpoint owner/mode differs",
            )
            policy, policy_ref = self.policies[str(member["producer"]["pid"])]
            require(
                ready
                == dict(
                    schema="ecpa-native-observer-control-ready/v2",
                    producer=member["producer"],
                    socket_identity=[info.st_dev, info.st_ino],
                    socket_path=str(sock),
                    policy_sha256=policy_ref["sha256"],
                    receipt_sha256=self.scope.receipt_ref()["sha256"],
                ),
                "source-owned ready bytes differ from exact immutable grant/inode",
            )
            nonce = secrets.token_hex(32)
            command = dict(
                schema=COMMAND,
                domain=DOMAIN,
                operation="describe",
                start_id=policy["start_id"],
                receipt_sha256=policy["receipt_sha256"],
                producer=policy["controller"],
                control_nonce=policy["control_nonce"],
                challenge_nonce=nonce,
            )
            remaining = (deadline_ns - time.monotonic_ns()) / 1e9
            require(remaining > 0, "original ready bound expired before live challenge")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                channel.settimeout(remaining)
                channel.connect(str(sock))
                pid, uid, gid = struct.unpack(
                    "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
                require(
                    uid == os.getuid()
                    and gid == os.getgid()
                    and native.identity(pid) == member["producer"],
                    "ready JSON is not actual source-owned original producer",
                )
                channel.sendall(native.canonical(command) + b"\n")
                response_raw = b""
                while not response_raw.endswith(b"\n"):
                    piece = channel.recv(native.MAX_FRAME + 1)
                    require(
                        piece and len(response_raw) + len(piece) <= native.MAX_FRAME,
                        "producer live describe truncated/oversized",
                    )
                    response_raw += piece
            response = json.loads(response_raw)
            require(
                response_raw == native.canonical(response) + b"\n"
                and response["state"] == "described"
                and response["producer"] == member["producer"]
                and response["controller"] == policy["controller"]
                and response["start_id"] == policy["start_id"]
                and response["receipt_sha256"] == policy["receipt_sha256"]
                and response["challenge_nonce"] == nonce
                and response["generation"] == 0
                and response["contexts"] == policy["initial_contexts"]
                and response["policy_sha256"] == policy_ref["sha256"]
                and response["socket_identity"] == [info.st_dev, info.st_ino]
                and response["native_completion_proved"] is False
                and time.monotonic_ns() <= deadline_ns,
                "actual producer/grant/nonce/original-ready bound mismatch",
            )
            expected = [
                row["sha256"]
                for row in self.receipt["host_sources"]
                if row["path"].endswith("/vllm/plugins/native_observer_rebind.py")
            ]
            require(
                len(set(expected)) == 1 and response["source_sha256"] == expected[0],
                'actual producer control implementation is '
                'outside source-admitted Host tuple',
            )
            endpoint = {**member, "socket_identity": [info.st_dev, info.st_ino]}
            self.endpoints.append(endpoint)
            observation = write_private(
                self.directory / str(pid) / "independent-endpoint-observation.json",
                dict(
                    command=command,
                    response=response,
                    ready_sha256=native.sha(raw),
                    actual_socket=[info.st_dev, info.st_ino],
                    actual_peer=member["producer"],
                    observed_ns=time.monotonic_ns(),
                    source_complete=False,
                ),
            )
            observations.append(observation)
        proof = dict(
            schema="ecpa-h3-independent-live-control-enrollment/v2",
            receipt=self.scope.receipt_ref(),
            original_start_id=self.authority.start["start_id"],
            authority=native.identity(os.getpid()),
            actual_endpoints=self.endpoints,
            producer_policies={key: value[1] for key, value in self.policies.items()},
            original_collector=self.initial_descriptor,
            endpoint_observations=observations,
            ready_deadline_ns=deadline_ns,
            observed_ns=time.monotonic_ns(),
            evidence_scope="private-control-enrollment-only",
            native_completion_proved=False,
        )
        reference = write_private(
            self.directory / "independent-control-enrollment.json", proof
        )
        self.endpoint_proof = (reference, native.canonical(proof))
        self.recheck()
        return self.endpoints
