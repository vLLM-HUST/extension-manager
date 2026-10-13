"""Opt-in private handoff of Manager-minted launch bindings.

The receiver observes native IDs; it cannot choose them or bypass reserved-env
ownership. This is an experiment handoff, not formal deployment admission.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import struct
import time
import uuid
from pathlib import Path
from typing import Any

from .runtime_evidence import _EVIDENCE_ENVIRONMENT, _PATH_ENV, _SINK

PROTOCOL = "ecpa-manager-native-phase-handoff/v1"


def process_identity(pid: int) -> dict[str, Any]:
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    if fields[0] == "Z":
        raise ValueError("handoff process is a zombie")
    return {
        "pid": pid,
        "start_ticks": int(fields[19]),
        "session": int(fields[3]),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }


def _private_parent(path: Path) -> None:
    parent = path.parent
    if (
        not path.is_absolute()
        or parent.resolve(strict=True) != parent
        or parent.is_symlink()
    ):
        raise ValueError("handoff requires a canonical private directory")
    meta = parent.stat()
    if meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) & 0o077:
        raise ValueError("handoff directory is not private and owned")


def _socket_metadata(path: Path) -> dict[str, int]:
    _private_parent(path)
    meta = path.lstat()
    if (
        not stat.S_ISSOCK(meta.st_mode)
        or meta.st_uid != os.geteuid()
        or stat.S_IMODE(meta.st_mode) & 0o077
    ):
        raise ValueError("handoff socket is not private and owned")
    return {"device": meta.st_dev, "inode": meta.st_ino}


def _peer(connection: socket.socket) -> tuple[int, int, int]:
    return struct.unpack(
        "3i",
        connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        ),
    )


def manager_source_digests() -> dict[str, str]:
    root = Path(__file__).resolve().parent
    return {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in (
            "cli.py",
            "runtime_evidence.py",
            "runtime_phase_handoff.py",
            "process_supervisor.py",
        )
    }


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _receive(connection: socket.socket) -> bytes:
    raw = b""
    while not raw.endswith(b"\n"):
        chunk = connection.recv(4096)
        if not chunk:
            raise ValueError("handoff closed before bounded record")
        raw += chunk
        if len(raw) > 16384:
            raise ValueError("handoff record exceeds bound")
    return raw


def bind_receiver(path: Path, timeout: float) -> socket.socket:
    _private_parent(path)
    if path.exists() or path.is_symlink():
        raise ValueError("handoff socket path is not fresh")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
        path.chmod(0o600)
        listener.listen(1)
        listener.settimeout(timeout)
        return listener
    except Exception:
        listener.close()
        raise


def publish_native_binding(
    environment: dict[str, str], path: Path, timeout: float = 30
) -> dict[str, str]:
    """Called only after native launch_environment mint, before supervise."""
    metadata = _socket_metadata(path)
    if (
        set(environment) != set(_EVIDENCE_ENVIRONMENT)
        or environment["VLLM_ECPA_EVIDENCE_SINK"] != _SINK
        or environment["VLLM_ECPA_EVIDENCE_STRICT"] != "1"
    ):
        raise ValueError("native runtime evidence binding required")
    launch = uuid.UUID(environment["VLLM_ECPA_LAUNCH_ID"])
    if launch.version != 4 or str(launch) != environment["VLLM_ECPA_LAUNCH_ID"]:
        raise ValueError("native fresh launch UUID required")
    evidence = path.parent / f"{launch}.events.jsonl"
    descriptor = os.open(evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    result = dict(environment)
    result[_PATH_ENV] = str(evidence)
    record = {
        "schema": PROTOCOL,
        "publisher": process_identity(os.getpid()),
        "socket": metadata,
        "published_wall_ns": time.time_ns(),
        "environment": result,
        "manager_source_sha256": manager_source_digests(),
    }
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(str(path))
        pid, uid, _ = _peer(connection)
        if pid != os.getppid() or uid != os.geteuid():
            raise ValueError("handoff receiver is not the actual owned parent")
        if _socket_metadata(path) != metadata:
            raise ValueError("handoff socket identity changed")
        connection.sendall(raw)
        ack = json.loads(_receive(connection))
        if ack != {"schema": PROTOCOL, "binding_sha256": _digest(raw)}:
            raise ValueError("handoff acknowledgement does not bind native record")
    return result


def accept_native_binding(
    listener: socket.socket,
    path: Path,
    owner: dict[str, Any],
    launched_wall_ns: int,
    expected_sources: dict[str, str],
    raw_record_path: Path | None = None,
) -> dict[str, Any]:
    """Accept only the exact live child publisher, never caller-chosen IDs."""
    metadata = _socket_metadata(path)
    connection, _ = listener.accept()
    with connection:
        connection.settimeout(listener.gettimeout())
        pid, uid, _ = _peer(connection)
        if pid != owner["pid"] or uid != os.geteuid():
            raise ValueError("handoff publisher is not the owned Manager process")
        if process_identity(pid) != owner:
            raise ValueError("handoff Manager identity changed")
        raw = _receive(connection)
        if raw_record_path is not None:
            raw_record_path.write_bytes(raw)
        record: dict[str, Any] = json.loads(raw)
        env = record["environment"]
        evidence = Path(env[_PATH_ENV])
        launch = uuid.UUID(env["VLLM_ECPA_LAUNCH_ID"])
        if (
            record["manager_source_sha256"] != expected_sources
            or record["schema"] != PROTOCOL
            or record["publisher"] != owner
            or record["socket"] != metadata
            or not launched_wall_ns <= record["published_wall_ns"] <= time.time_ns()
            or set(env) != set(_EVIDENCE_ENVIRONMENT)
            or env["VLLM_ECPA_EVIDENCE_SINK"] != _SINK
            or env["VLLM_ECPA_EVIDENCE_STRICT"] != "1"
            or launch.version != 4
            or evidence != path.parent / f"{launch}.events.jsonl"
            or evidence.is_symlink()
            or not evidence.is_file()
            or evidence.stat().st_uid != os.geteuid()
            or stat.S_IMODE(evidence.stat().st_mode) & 0o077
            or len(env["VLLM_ECPA_PLAN_ID"]) != 64
            or any(c not in "0123456789abcdef" for c in env["VLLM_ECPA_PLAN_ID"])
        ):
            raise ValueError("native handoff source/identity binding differs")
        record["binding_sha256"] = _digest(raw)
        connection.sendall(
            json.dumps(
                {"schema": PROTOCOL, "binding_sha256": record["binding_sha256"]}
            ).encode()
            + b"\n"
        )
        return record
