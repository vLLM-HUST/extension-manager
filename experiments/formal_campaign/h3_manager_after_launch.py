"""Actual Manager after-Popen fault actuator, not a formal registration issuer.

Only the installed-manager arm has this actor. The original worker-recovery
registration/intake remains unchanged and must not admit this new cell.
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import signal
import socket
import stat
import struct
import time
from pathlib import Path

SCHEMA = "ecpa-source-manager-after-launch/v1"
ENV = "ECPA_MANAGER_AFTER_LAUNCH_BARRIER"
MAX_FRAME = 65536
_BARRIERS = {}


class _DeclaredBarrier:
    __slots__ = ()

    def reference(self):
        return json.loads(_barrier_value(self)["reference"])


def _barrier_value(value, *, consume=False):
    _require(
        type(value) is _DeclaredBarrier and value in _BARRIERS,
        "source-owned root barrier capability required",
    )
    record = _BARRIERS[value]
    _require(record["pid"] == os.getpid(), "root barrier cannot cross fork")
    if consume:
        del _BARRIERS[value]
    return record


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def kernel(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    if fields[0] == "Z":
        raise ValueError("phase actor is already a zombie")
    return dict(
        pid=pid,
        start_ticks=int(fields[19]),
        session=int(fields[3]),
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    )


def _require(value, message):
    if not value:
        raise ValueError(message)


def _save(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def _read(connection, deadline):
    raw = b""
    while not raw.endswith(b"\n"):
        remaining = (deadline - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            raise TimeoutError("original Manager phase readiness deadline")
        connection.settimeout(remaining)
        piece = connection.recv(MAX_FRAME + 1)
        _require(piece and len(raw) + len(piece) <= MAX_FRAME, "incomplete phase event")
        raw += piece
    value = json.loads(raw)
    _require(raw == canonical(value) + b"\n", "noncanonical phase event")
    return value


def _connect_private_manager(path, expected, deadline_ns):
    """Readiness only: no command/retry is sent before successful connect."""
    path = Path(path)
    fence = None
    while time.monotonic_ns() < deadline_ns:
        _require(
            kernel(expected["pid"]) == expected, "Manager epoch changed before connect"
        )
        if not path.exists():
            time.sleep(0.01)
            continue
        info = path.lstat()
        _require(
            stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid(),
            "phase socket owner/type differs",
        )
        if stat.S_IMODE(info.st_mode) != 0o600:
            time.sleep(0.01)
            continue
        identity = (info.st_dev, info.st_ino, info.st_uid, info.st_mode)
        if fence is None:
            fence = identity
        _require(identity == fence, "phase socket inode changed during readiness")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(max(0.001, (deadline_ns - time.monotonic_ns()) / 1e9))
            connection.connect(str(path))
            pid, uid, _ = struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            _require(
                pid == expected["pid"]
                and uid == os.getuid()
                and kernel(pid) == expected,
                "phase server is not actual Manager",
            )
            return connection
        except ConnectionRefusedError:
            connection.close()
            time.sleep(0.01)
        except BaseException:
            connection.close()
            raise
    raise TimeoutError("original phase deadline expired before source connect")


def _descendant(child, parent):
    """Require the independently owned Manager/Host ancestry while both live."""
    _require(kernel(parent["pid"]) == parent, "independent root epoch changed")
    current, seen = child["pid"], set()
    _require(kernel(current) == child, "phase child epoch changed")
    while current != parent["pid"]:
        _require(current > 1 and current not in seen, "phase actor is not root owned")
        seen.add(current)
        fields = Path(f"/proc/{current}/stat").read_text().rsplit(")", 1)[1].split()
        current = int(fields[1])


def _kill_held_manager(manager, deadline_ns):
    """PIDFD operation on a live actual descendant; never a qualification token."""
    _descendant(manager, kernel(os.getpid()))
    fd = os.pidfd_open(manager["pid"])
    try:
        _require(kernel(manager["pid"]) == manager, "fault actor epoch changed")
        before = time.monotonic_ns()
        if before >= deadline_ns:
            raise TimeoutError("original phase deadline expired before fault")
        signal.pidfd_send_signal(fd, signal.SIGKILL)
        sent = time.monotonic_ns()
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        death = bool(
            poller.poll(
                max(0, (before + 30_000_000_000 - time.monotonic_ns()) // 1_000_000)
            )
        )
        return dict(
            fault_before_ns=before,
            fault_sent_ns=sent,
            death_observed_ns=time.monotonic_ns() if death else None,
            recovery_deadline_ns=before + 30_000_000_000,
        )
    finally:
        os.close(fd)


def declare(directory, *, start_id, deadline_ns, nonce):
    """Called by the real root before Popen; no caller clock or actor override."""
    _require(
        type(deadline_ns) is int and deadline_ns > time.monotonic_ns(),
        "original future readiness deadline required",
    )
    _require(
        type(nonce) is str
        and len(nonce) == 64
        and all(c in "0123456789abcdef" for c in nonce),
        "64hex nonce required",
    )
    _require(
        type(start_id) is str
        and start_id.startswith("manager-crash-after-launch-r")
        and start_id.endswith("-ecpa"),
        "actual Manager arm only",
    )
    directory = Path(directory)
    _require(
        directory.is_absolute() and directory.resolve() == directory,
        "canonical private phase directory required",
    )
    directory.mkdir(mode=0o700)
    fd = os.open(directory, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        _require(before.st_uid == os.getuid(), "phase directory owner differs")
        os.fchmod(fd, 0o700)
        after = directory.lstat()
        _require(
            (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
            and stat.S_IMODE(after.st_mode) == 0o700,
            "phase directory identity or private mode changed",
        )
        value = dict(
            schema=SCHEMA,
            cell_id="manager-crash-after-launch",
            start_id=start_id,
            nonce=nonce,
            root=kernel(os.getpid()),
            deadline_ns=deadline_ns,
            socket_path=str(directory / "phase.sock"),
        )
        _require(len(os.fsencode(value["socket_path"])) < 108, "Unix path too long")
        raw = canonical(value)
        file_fd = os.open(
            "declaration.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd
        )
        with os.fdopen(file_fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    token = _DeclaredBarrier()
    reference = {"path": str(directory / "declaration.json"), "sha256": sha(raw)}
    _BARRIERS[token] = {
        "pid": os.getpid(),
        "reference": canonical(reference),
        "raw": raw,
    }
    return token


class ManagerPhaseKilled(RuntimeError):
    """Intentional actual fault; caller still owes recovery/intake/root cleanup."""

    def __init__(self, result, process, sessions):
        super().__init__(
            "actual Manager killed at its source-owned after-launch barrier"
        )
        self.result = result
        self.process, self.sessions = process, list(sessions)


class ManagerCleanupFailed(OSError):
    """The actual post-fault cleanup failed; never attempt the next candidate."""


def callback_for_phase(*, phase, guard, declaration, output):
    """Fresh native/source guard first; returned closure acts only on that phase.

    The declaration and new supervisor source must be covered by the future
    independent source/input inventory. A caller dictionary cannot replace the
    actual NativePlanGuard. This does not mint a native completion or admission.
    """
    from experiments.formal_campaign.h3_native_plan_guard import NativePlanGuard

    _require(
        type(guard) is NativePlanGuard, "independent typed native source guard required"
    )
    _require(
        phase["origin"] == "manager-native-handoff"
        and guard.policy["origin"] == "installed-manager",
        "baseline has no Manager actor",
    )
    _require(
        guard.policy["source_arguments"]["publisher_argv"] == phase["argv"],
        "registered actual Manager command differs",
    )
    barrier = _barrier_value(declaration, consume=True)
    declaration = json.loads(barrier["reference"])
    guard.verify_plan_current()
    raw = Path(declaration["path"]).read_bytes()
    _require(
        raw == barrier["raw"] and sha(raw) == declaration["sha256"],
        "phase declaration bytes changed",
    )
    config = json.loads(raw)
    _require(
        raw == canonical(config) and config["root"] == kernel(os.getpid()),
        "phase declaration is not held by this actual root",
    )
    sources = guard.policy["source_arguments"]["native_sources"]
    _require(
        phase["environment"].get(ENV) == declaration["path"],
        "actual phase environment lacks registered barrier",
    )
    output = Path(output)
    _require(output.is_dir(), "original root must create the start-owned output")
    invoked = False

    def act(process, binding, owned):
        nonlocal invoked
        _require(not invoked, "phase fault callback is one use")
        invoked = True
        guard.verify_plan_current()
        _require(
            Path(declaration["path"]).read_bytes() == raw,
            "phase declaration changed after source guard",
        )
        manager = kernel(process.pid)
        _require(binding["publisher"] == manager, "authenticated publisher differs")
        _descendant(manager, config["root"])
        argv = [
            v.decode()
            for v in Path(f"/proc/{process.pid}/cmdline").read_bytes().split(b"\0")
            if v
        ]
        _require(argv == phase["argv"], "actual Manager argv differs")
        launch = guard.launch
        native = {
            key: binding["environment"][key]
            for key in ("VLLM_ECPA_PLAN_ID", "VLLM_ECPA_LAUNCH_ID")
        }
        native.update(
            {
                "ECPA_SEMANTIC_" + env: str(launch[key])
                for env, key in (
                    ("EXECUTION_PLAN_ID", "execution_plan_id"),
                    ("CONTROLLER_INSTANCE", "controller_instance"),
                    ("CANDIDATE_GENERATION", "candidate_generation"),
                    ("MEMBERSHIP_EPOCH", "membership_epoch"),
                )
            }
        )
        request = dict(
            schema=SCHEMA,
            operation="hold-after-launch",
            start_id=config["start_id"],
            nonce=config["nonce"],
            expected_manager=manager,
            expected_native=native,
        )
        request_raw = canonical(request) + b"\n"
        socket_path = Path(config["socket_path"])
        with _connect_private_manager(
            socket_path, manager, config["deadline_ns"]
        ) as connection:
            connection.sendall(request_raw)
            event = _read(connection, config["deadline_ns"])
            _require(
                event["schema"] == SCHEMA
                and event["phase"] == config["cell_id"]
                and event["start_id"] == config["start_id"]
                and event["nonce"] == config["nonce"]
                and event["root"] == config["root"]
                and event["manager"] == manager
                and event["native"] == native
                and event["request_sha256"] == sha(request_raw)
                and event["config_sha256"] == sha(raw)
                and event["model_request_id"] is None
                and event["commit_proved"] is False
                and event["native_completion_proved"] is False,
                "actual source phase event binding differs",
            )
            _descendant(event["child"], manager)
            _require(
                event["child"]["session"] == event["child"]["pid"],
                "actual supervised child is not its captured session leader",
            )
            # Host may legitimately setproctitle after exec. The actual Popen
            # argv comes from the authenticated, independently admitted Manager
            # code, not a later mutable /proc cmdline or caller assertion.
            actual_argv = event["actual_command"]
            _require(
                type(actual_argv) is list
                and actual_argv
                and all(type(arg) is str for arg in actual_argv)
                and event["actual_command_sha256"] == sha(canonical(actual_argv)),
                "source-captured actual Host Popen command differs",
            )
            source = event["source"]
            _require(
                source["path"].endswith("/vllm_hust_ext/process_supervisor.py")
                and sources.get(source["path"], "").removeprefix("sha256:")
                == source["sha256"]
                and sha(Path(source["path"]).read_bytes()) == source["sha256"],
                "phase product source not independently admitted",
            )
            observed = time.monotonic_ns()
            _require(
                event["child_popen_ns"]
                <= event["observed_monotonic_ns"]
                <= observed
                < config["deadline_ns"],
                "phase clock order differs",
            )
            # Retain the actual child session BEFORE killing its parent. Existing
            # root cleanup must include it even if the Manager can no longer reap.
            from experiments.formal_campaign.h3_worker_relaunch import owned_sessions

            sessions, descendants = owned_sessions(manager)
            _require(
                descendants.get(event["child"]["pid"]) == event["child"],
                "actual Host is absent from independent pre-fault ownership",
            )
            for item in sessions:
                if item not in owned:
                    owned.append(item)
            _save(output / "manager-after-launch.event.json", event)
            _save(
                output / "manager-after-launch.owned.json",
                {
                    "manager": manager,
                    "sessions": sessions,
                    "descendants": list(descendants.values()),
                    "observed_monotonic_ns": time.monotonic_ns(),
                },
            )
            timing = _kill_held_manager(manager, config["deadline_ns"])
            result = dict(
                schema="ecpa-manager-phase-actuation/v1",
                event_sha256=sha(canonical(event)),
                manager=manager,
                child=event["child"],
                formal_start_validated=False,
                objective_met=None,
                model_request_id=None,
                recovery_observed=False,
                captured_owned_sessions=sessions,
                captured_owned_kernels=list(descendants.values()),
                **timing,
            )
            _save(output / "manager-after-launch.fault.json", result)
            raise ManagerPhaseKilled(result, process, owned)

    return act
