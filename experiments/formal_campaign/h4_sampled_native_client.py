"""Authenticate the distinct H4 concurrent native collector and full-prefix seals."""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import stat
import struct
import time
from pathlib import Path

from experiments.native_challenge_candidate.request_runner import (
    canonical,
    require,
    sha,
)

MAX_FRAME = 65536


def identity(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    require(fields[0] != "Z", "collector is a zombie")
    ticks = int(fields[19])
    return {
        "pid": pid,
        "start_ticks": ticks,
        "start_identity": f"pid:{pid}:start_ticks:{ticks}",
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "session": int(fields[3]),
    }


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        require(
            stat.S_ISREG(meta.st_mode)
            and meta.st_uid == os.getuid()
            and stat.S_IMODE(meta.st_mode) == 0o600
            and meta.st_size <= MAX_FRAME,
            "private frozen collector spec required",
        )
        return os.read(fd, MAX_FRAME + 1)
    finally:
        os.close(fd)


def authenticate(
    socket_path,
    descriptor,
    spec_path,
    collector_source_path,
    *,
    drain_policy_path,
    schedule_path,
):
    """Validate kernel peer, independent launch descriptor, source and identities."""
    require(drain_policy_path is not None, "explicit request drain policy required")
    from experiments.formal_campaign.h4_sampled_native_schedule import (
        bind_selected_phases,
        read_schedule,
    )

    schedule, schedule_raw = read_schedule(schedule_path)
    require(
        sha(schedule_raw) == descriptor["schedule_sha256"],
        "registered H4 schedule differs",
    )
    expected = descriptor["collector"]
    require(
        descriptor["launcher_observed_identity"] == expected,
        "launcher/kernel identity binding missing",
    )
    require(
        identity(expected["pid"]) == expected,
        "frozen collector process identity changed",
    )
    require(
        sha(Path(f"/proc/{expected['pid']}/cmdline").read_bytes())
        == descriptor["launcher_observed_cmdline_sha256"],
        "collector launch command changed",
    )
    source_digest = sha(collector_source_path.read_bytes())
    require(
        source_digest == descriptor["collector_source_sha256"],
        "frozen collector source changed",
    )
    spec_raw = private_read(spec_path)
    bind_selected_phases(json.loads(spec_raw), schedule)
    require(sha(spec_raw) == descriptor["spec_sha256"], "frozen collector spec changed")
    parent = socket_path.parent.stat()
    require(
        parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700,
        "private collector socket directory required",
    )
    metadata = socket_path.lstat()
    require(
        stat.S_ISSOCK(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and [metadata.st_dev, metadata.st_ino] == descriptor["socket_identity"],
        "collector socket identity changed",
    )
    archive = descriptor["archive_identity"]
    require(
        (parent.st_dev, parent.st_ino)
        == (archive["directory_device"], archive["directory_inode"]),
        "collector archive directory changed",
    )
    dispatched_ns = time.monotonic_ns()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(5)
        channel.connect(str(socket_path))
        pid, uid, _ = struct.unpack(
            "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        require(
            uid == os.getuid() and identity(pid) == expected,
            "kernel peer is not frozen collector",
        )
        channel.sendall(canonical({"op": "describe"}) + b"\n")
        response = b""
        while not response.endswith(b"\n"):
            chunk = channel.recv(MAX_FRAME + 1)
            require(
                chunk and len(response) + len(chunk) <= MAX_FRAME,
                "collector status incomplete/oversized",
            )
            response += chunk
    require(
        identity(pid) == expected, "collector identity changed during authentication"
    )
    status = json.loads(response)
    prefix = status.get("acknowledged_prefix")
    require(
        isinstance(prefix, dict)
        and set(prefix) == {"next_sequence", "last_event_sha256"}
        and type(prefix["next_sequence"]) is int
        and prefix["next_sequence"] >= 1
        and re.fullmatch(r"[0-9a-f]{64}", prefix["last_event_sha256"]) is not None,
        "durable acknowledged prefix missing",
    )
    core_status = {
        k: v
        for k, v in status.items()
        if k not in {"acknowledged_prefix", "issued_monotonic_ns"}
    }
    if drain_policy_path is not None:
        policy_raw = private_read(Path(drain_policy_path))
        require(
            json.loads(policy_raw)["tensor_policy_sha256"]
            == descriptor["policy_sha256"],
            "request drain and independently enrolled tensor policy differ",
        )
        drain = status.get("source_drain")
        require(
            isinstance(drain, dict)
            and set(drain) == {"schema", "policy_sha256", "runtimes"}
            and drain["schema"] == "ecpa-h4-sampled-concurrent-native-drain-policy/v1"
            and drain["policy_sha256"] == sha(policy_raw)
            and isinstance(drain["runtimes"], dict)
            and json.loads(policy_raw)["native_spec_sha256"]
            == descriptor["spec_sha256"],
            "authenticated source drain extension differs",
        )
        core_status.pop("source_drain")
    require(
        core_status
        == {
            "schema": "ecpa-h4-sampled-concurrent-native-collector-status/v1",
            "schedule_sha256": sha(schedule_raw),
            "spec_sha256": descriptor["spec_sha256"],
            "collector_source_sha256": source_digest,
            "collector": expected,
            "socket_identity": descriptor["socket_identity"],
            "socket_path": str(socket_path),
            "archive_identity": archive,
            "classification": "REAL_RUNTIME_UNQUALIFIED",
            "formal_producer_registration": False,
            "failed": False,
        },
        "collector status differs from frozen independent launch",
    )
    validate_request_status(status, json.loads(spec_raw), json.loads(policy_raw))
    completed_ns = time.monotonic_ns()
    return {
        "status": status,
        "status_raw_sha256": sha(response),
        "status_raw_base64": base64.b64encode(response).decode("ascii"),
        "kernel_peer": {"pid": pid, "uid": uid},
        "authentication_clock": {
            "schema": "ecpa-native-status-authentication-clock/v1",
            "dispatch_monotonic_ns": dispatched_ns,
            "completed_monotonic_ns": completed_ns,
            "client": identity(os.getpid()),
            "client_source_sha256": sha(Path(__file__).read_bytes()),
        },
        "formal_result": False,
    }


def validate_request_status(status, spec, policy):
    """Validate snapshot bounds, never infer native effects from a status reply."""
    from experiments.formal_campaign import h4_sampled_native_collector as intake

    phase_ids = [phase["phase_id"] for phase in spec["phases"]]
    require(
        status["schema"] == intake.STATUS
        and status["source_drain"]["schema"] == intake.POLICY
        and len(phase_ids) == intake.REQUESTS
        and len(set(phase_ids)) == len(phase_ids)
        and policy
        == {
            "schema": intake.POLICY,
            "native_spec_sha256": status["spec_sha256"],
            "tensor_policy_sha256": policy["tensor_policy_sha256"],
            "phase_ids": phase_ids,
            "required_ranks": [0, 1],
            "formal_registration": False,
        },
        "request status policy is unbounded or differs",
    )
    states = status["source_drain"]["runtimes"]
    require(len(states) <= len(phase_ids), "too many request runtime mappings")
    seen = set()
    unfinished = 0
    for runtime, state in states.items():
        require(
            isinstance(runtime, str)
            and bool(runtime)
            and set(state)
            == {
                "phase",
                "ranks",
                "complete",
                "sealed_prefix",
                "sealed_prefix_bytes",
                "sealed_prefix_sha256",
                "sealed_monotonic_ns",
            }
            and state["phase"] in spec["phases"]
            and state["phase"]["phase_id"] not in seen
            and type(state["complete"]) is bool,
            "request status phase binding differs",
        )
        seen.add(state["phase"]["phase_id"])
        require(state["ranks"] in ([], [0], [1], [0, 1]), "request drain ranks differ")
        if not state["complete"]:
            unfinished += state["ranks"] != [0, 1]
            require(
                all(
                    state[k] is None
                    for k in (
                        "sealed_prefix",
                        "sealed_prefix_bytes",
                        "sealed_prefix_sha256",
                        "sealed_monotonic_ns",
                    )
                ),
                "incomplete request phase claims a seal",
            )
            continue
        prefix = state["sealed_prefix"]
        require(
            state["ranks"] == [0, 1]
            and isinstance(prefix, dict)
            and set(prefix) == {"next_sequence", "last_event_sha256"}
            and type(prefix["next_sequence"]) is int
            and 1
            <= prefix["next_sequence"]
            <= status["acknowledged_prefix"]["next_sequence"]
            and re.fullmatch(r"[0-9a-f]{64}", prefix["last_event_sha256"]) is not None
            and type(state["sealed_prefix_bytes"]) is int
            and state["sealed_prefix_bytes"] > 0
            and re.fullmatch(r"[0-9a-f]{64}", state["sealed_prefix_sha256"]) is not None
            and type(state["sealed_monotonic_ns"]) is int
            and spec["frozen_monotonic_ns"]
            <= state["sealed_monotonic_ns"]
            <= status["issued_monotonic_ns"],
            "sealed request prefix bounds differ",
        )
        if prefix["next_sequence"] == status["acknowledged_prefix"]["next_sequence"]:
            require(
                prefix == status["acknowledged_prefix"],
                "current request seal root differs",
            )
    require(unfinished <= intake.CONCURRENCY, "H4 unfinished request bound exceeded")
