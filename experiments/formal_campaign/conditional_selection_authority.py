"""ROOT-owned actual API->scheduler fullRID selection transport candidate.

Independent original enrollment/source admission MUST occur before constructing
this authority. This transport alone does not create that enrollment or qualify
any process. It never issues a deployment receipt and never ACKs policy facts.
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import socket
import struct
import time
from pathlib import Path

SCHEMA = "ecpa-h4-conditional-original-rid-selection/v1"
MAX_PACKET = 131072
KEYS = ("pid", "start_ticks", "session", "boot_id")


def require(value, why):
    if not value:
        raise ValueError(why)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def identity(pid):
    row = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    require(row[0] != "Z", "original participant is zombie")
    return dict(
        pid=pid,
        start_ticks=int(row[19]),
        session=int(row[3]),
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    )


def exact_peer(connection, expected, uid):
    pid, actual_uid, _ = struct.unpack(
        "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    require(
        actual_uid == uid and pid == expected["pid"] and identity(pid) == expected,
        "selection peer not exact enrolled original kernel",
    )


class SelectionAuthority:
    """One live actual epoch, no substitute/new-kernel enrollment or remapping.

    Both exact enrolled kernels are held by pidfd until close; packet count is
    bounded, no short-lived source-guard subprocess gets a retained pidfd.
    """

    def __init__(
        self,
        *,
        socket_path,
        start_id,
        plan_id,
        launch_id,
        nonce,
        api_kernel,
        scheduler_kernel,
        original_schedule,
        output,
    ):
        self.path = Path(socket_path)
        self.output = Path(output)
        require(
            self.path.is_absolute()
            and self.path.resolve() == self.path
            and not self.path.exists()
            and len(os.fsencode(self.path)) <= 107,
            "fresh bounded canonical selection socket",
        )
        require(
            len(original_schedule) == 272
            and len({r["request_id"] for r in original_schedule}) == 272,
            "original272 immutable RID schedule required",
        )
        selected = [r for r in original_schedule if r["selected"]]
        require(
            len(selected) == 32
            and [r["all_index"] for r in selected]
            == list(range(16)) + list(range(16, 272, 16)),
            "original32 selection differs",
        )
        self.schedule = {
            "cmpl-" + r["request_id"] + "-0": bool(r["selected"])
            for r in original_schedule
        }
        self.kernels = dict(api=api_kernel, scheduler=scheduler_kernel)
        require(
            api_kernel != scheduler_kernel
            and identity(api_kernel["pid"]) == api_kernel
            and identity(scheduler_kernel["pid"]) == scheduler_kernel,
            "actual distinct enrolled participants required",
        )
        self.binding = dict(
            schema=SCHEMA,
            start_id=start_id,
            plan_id=plan_id,
            launch_id=launch_id,
            nonce=nonce,
        )
        require(
            isinstance(nonce, str) and len(nonce) == 64, "fresh full nonce required"
        )
        self.runtime = {}
        self.external = {}
        self.sequence = dict(api=0, scheduler=0)
        self.pidfds = []
        self.listener = None
        self.socket_identity = None
        self.fd = None
        try:
            for kernel in self.kernels.values():
                fd = os.pidfd_open(kernel["pid"])
                self.pidfds.append(fd)
                require(
                    identity(kernel["pid"]) == kernel,
                    "participant reused during pidfd capture",
                )
            self.fd = os.open(
                self.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            self.listener.bind(str(self.path))
            os.chmod(self.path, 0o600)
            info = self.path.lstat()
            self.socket_identity = (info.st_dev, info.st_ino)
            self.listener.listen(8)
        except BaseException:
            self.close()
            raise

    def grants(self):
        require(self.listener is not None, "authority closed")
        return dict(
            self.binding,
            socket_path=str(self.path),
            socket_identity=list(self.socket_identity),
            authority_kernel=identity(os.getpid()),
            uid=os.geteuid(),
            kernels=self.kernels,
        )

    def _alive(self):
        poll = select.poll()
        for fd in self.pidfds:
            poll.register(fd, select.POLLIN)
        require(not poll.poll(0), "original API/scheduler epoch died; no replacement")
        require(
            all(identity(k["pid"]) == k for k in self.kernels.values()),
            "enrolled participant changed",
        )
        info = self.path.lstat()
        require(
            (info.st_dev, info.st_ino) == self.socket_identity,
            "selection socket inode replaced",
        )

    def serve_one(self, timeout):
        self._alive()
        self.listener.settimeout(timeout)
        connection, _ = self.listener.accept()
        with connection:
            connection.settimeout(timeout)
            raw = connection.recv(MAX_PACKET + 1)
            require(0 < len(raw) <= MAX_PACKET, "selection packet oversized/empty")
            packet = json.loads(raw)
            require(canonical(packet) == raw, "selection packet noncanonical")
            require(
                all(packet.get(k) == v for k, v in self.binding.items()),
                "wrong original start/Plan/launch/nonce",
            )
            role = packet.get("role")
            require(role in self.kernels, "unknown selection participant")
            exact_peer(connection, self.kernels[role], os.geteuid())
            require(
                packet["sequence"] == self.sequence[role] + 1,
                "replayed/out-of-order selection packet",
            )
            require(
                set(packet)
                == set(self.binding) | {"role", "sequence", "operation", "payload"},
                "unknown selection fields",
            )
            payload = packet["payload"]
            if role == "api":
                require(
                    packet["operation"] == "mapping"
                    and set(payload) == {"external_request_id", "runtime_request_id"},
                    "API may only publish actual mapping",
                )
                external, runtime = (
                    payload["external_request_id"],
                    payload["runtime_request_id"],
                )
                require(
                    external in self.schedule
                    and external not in self.external
                    and runtime not in self.runtime
                    and isinstance(runtime, str)
                    and runtime,
                    "unknown/duplicate original API RID",
                )
                selected = self.schedule[external]
                self.external[external] = runtime
                self.runtime[runtime] = selected
                result = dict(selected=selected)
            else:
                require(
                    packet["operation"] == "query"
                    and set(payload) == {"runtime_request_ids"},
                    "scheduler may only read API mappings",
                )
                rids = payload["runtime_request_ids"]
                require(
                    type(rids) is list
                    and len(rids) <= 272
                    and len(set(rids)) == len(rids)
                    and all(rid in self.runtime for rid in rids),
                    "unknown/unmapped scheduler RID; cannot skip as unselected",
                )
                result = dict(selected=[rid for rid in rids if self.runtime[rid]])
            self._alive()
            self.sequence[role] = packet["sequence"]
            record = dict(
                packet=packet,
                packet_sha256=hashlib.sha256(raw).hexdigest(),
                result=result,
                peer=self.kernels[role],
                observed_monotonic_ns=time.monotonic_ns(),
            )
            remaining = memoryview(canonical(record) + b"\n")
            while remaining:
                count = os.write(self.fd, remaining)
                require(count > 0, "selection durable log short write")
                remaining = remaining[count:]
            os.fsync(self.fd)
            connection.sendall(
                canonical(
                    dict(
                        self.binding,
                        sequence=packet["sequence"],
                        result=result,
                        request_sha256=hashlib.sha256(raw).hexdigest(),
                    )
                )
            )

    def close(self):
        if self.listener is not None:
            self.listener.close()
            self.listener = None
        if self.socket_identity is not None:
            try:
                info = self.path.lstat()
                if (info.st_dev, info.st_ino) == self.socket_identity:
                    self.path.unlink()
            except FileNotFoundError:
                pass
        for fd in self.pidfds:
            os.close(fd)
        self.pidfds = []
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
