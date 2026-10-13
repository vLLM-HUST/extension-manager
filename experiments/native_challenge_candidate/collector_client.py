"""Authenticate a source-frozen collector before a nonce HTTP request.

The launcher must supply an independently observed kernel/process descriptor;
the server's own describe reply cannot register itself as trusted.
"""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import stat
import struct
from pathlib import Path

from .request_runner import CLASSIFICATION, canonical, require, sha

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


def authenticate(socket_path, descriptor, spec_path, collector_source_path):
    """Validate kernel peer, independent launch descriptor, source and identities."""
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
    core_status = {k: v for k, v in status.items() if k != "acknowledged_prefix"}
    require(
        core_status
        == {
            "schema": "ecpa-native-semantic-collector-status/v1",
            "spec_sha256": descriptor["spec_sha256"],
            "collector_source_sha256": source_digest,
            "collector": expected,
            "socket_identity": descriptor["socket_identity"],
            "socket_path": str(socket_path),
            "archive_identity": archive,
            "classification": CLASSIFICATION,
            "formal_producer_registration": False,
            "failed": False,
        },
        "collector status differs from frozen independent launch",
    )
    return {
        "status": status,
        "status_raw_sha256": sha(response),
        "status_raw_base64": base64.b64encode(response).decode("ascii"),
        "kernel_peer": {"pid": pid, "uid": uid},
        "formal_result": False,
    }


def read_verified_phase(spec_path, journal_path, phase, expected_status):
    """Consume source-authenticated native facts; never infer internal suffixes."""
    from experiments.exposure_gate import native_semantic_collector as collector

    require(
        sha(Path(collector.__file__).read_bytes())
        == expected_status["status"]["collector_source_sha256"],
        "consumer/collector source versions differ",
    )
    meta = journal_path.lstat()
    archive = expected_status["status"]["archive_identity"]
    require(
        stat.S_ISREG(meta.st_mode)
        and meta.st_uid == os.getuid()
        and stat.S_IMODE(meta.st_mode) == 0o600
        and (meta.st_dev, meta.st_ino)
        == (archive["journal_device"], archive["journal_inode"]),
        "native journal identity changed",
    )
    verified = collector.verify_journal(
        spec_path,
        journal_path,
        acknowledged_prefix=expected_status["status"]["acknowledged_prefix"],
    )
    require(
        verified.get("native_chronology_status") == "verified"
        and type(verified.get("complete_two_rank_transport_phases")) is int
        and verified["complete_two_rank_transport_phases"] > 0,
        "durable native transport/chronology proof incomplete",
    )
    raw = journal_path.read_bytes()
    require(
        sha(raw) == verified["journal_sha256"],
        "native journal changed during verification",
    )
    events = [json.loads(line) for line in raw.splitlines()]
    start = events[0]
    require(
        start["collector"] == expected_status["status"]["collector"]
        and start["archive_identity"] == expected_status["status"]["archive_identity"],
        "journal not owned by authenticated collector",
    )
    expected_phase = {
        k: phase[k]
        for k in (
            "phase_id",
            "client_request_id",
            "challenge_nonce",
            "external_request_id",
            "expected_ranks",
        )
    }
    selected = [
        e
        for e in events[1:]
        if e.get("kind") == "native.accepted" and e["phase"] == expected_phase
    ]
    mappings = [
        json.loads(base64.b64decode(e["raw_base64"]))
        for e in selected
        if json.loads(base64.b64decode(e["raw_base64"]))["schema"]
        == "ecpa-native-request-id-mapping/v1"
    ]
    require(len(mappings) == 1, "missing/nonunique actual native API mapping")
    mapping = mappings[0]
    require(
        mapping["external_request_id"] == phase["expected_response_id"],
        "native mapping does not match frozen external request",
    )
    runtime = mapping["runtime_request_id"]
    uploads = [
        json.loads(base64.b64decode(e["raw_base64"]))
        for e in selected
        if json.loads(base64.b64decode(e["raw_base64"]))["schema"]
        == "ecpa-native-block-table-upload/v1"
    ]
    require(
        uploads and all(e["runtime_request_id"] == runtime for e in uploads),
        "upload does not match actual mapped runtime request",
    )
    require(
        {e["process"]["ordinal"] for e in uploads} == {0, 1},
        "native two-rank coverage incomplete",
    )
    return {
        "classification": CLASSIFICATION,
        "formal_result": False,
        "phase_id": phase["phase_id"],
        "runtime_request_id": runtime,
        "source_authenticated_native_upload_records": len(uploads),
        "native_request_upload_transport_join": True,
        "native_GPU_semantic_qualification": None,
        "KV_MOD_semantic_obligation_satisfied": None,
        "kv_tensor_equivalence": None,
        "attention_consumed_observed_tensor": None,
        "full_generation_quality": None,
        "full_objective_satisfied": None,
        "journal_sha256": verified["journal_sha256"],
    }
