"""Signal-safe supervision for commands launched by the Manager."""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import socket
import stat
import struct
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from types import FrameType

DEFAULT_SHUTDOWN_GRACE_SECONDS = 10.0
# Bounded first-deployment formal stop budget, pinned in the executed command.
FORMAL_SHUTDOWN_GRACE_SECONDS = 30
_POLL_SECONDS = 0.05
_KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)


_MANAGER_AFTER_LAUNCH_ENV = "ECPA_MANAGER_AFTER_LAUNCH_BARRIER"
_MANAGER_PHASE_SCHEMA = "ecpa-source-manager-after-launch/v1"
_MANAGER_PHASE_MAX = 65536


def _manager_phase_kernel(pid: int) -> dict[str, object]:
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    if fields[0] == "Z":
        raise ValueError("manager phase process is a zombie")
    return dict(
        pid=pid,
        start_ticks=int(fields[19]),
        session=int(fields[3]),
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    )


def _manager_phase_canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _manager_phase_read(
    connection: socket.socket, deadline: int, cancelled: Callable[[], bool]
) -> tuple[dict[str, object], bytes]:
    raw = b""
    while not raw.endswith(b"\n"):
        if cancelled():
            raise InterruptedError(
                "Manager phase interrupted by original managed signal"
            )
        remaining = (deadline - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            raise TimeoutError("original Manager phase readiness deadline expired")
        connection.settimeout(min(remaining, 0.05))
        try:
            piece = connection.recv(_MANAGER_PHASE_MAX + 1)
        except TimeoutError:
            continue
        if not piece or len(raw) + len(piece) > _MANAGER_PHASE_MAX:
            raise ValueError("bounded complete Manager phase command required")
        raw += piece
    value = json.loads(raw)
    if type(value) is not dict or raw != _manager_phase_canonical(value) + b"\n":
        raise ValueError("canonical Manager phase command required")
    return value, raw


def _manager_after_launch_barrier(
    config_path: str,
    child: subprocess.Popen[bytes],
    environment: Mapping[str, str],
    command: Sequence[str],
    child_popen_ns: int,
    cancelled: Callable[[], bool],
) -> None:
    """Observe actual successful Popen; never call this a commit or readiness."""
    path = Path(config_path)
    if not path.is_absolute() or path.resolve() != path or path.is_symlink():
        raise ValueError("canonical Manager phase declaration required")
    parent = path.parent
    root_meta = parent.lstat()
    if (
        not stat.S_ISDIR(root_meta.st_mode)
        or root_meta.st_uid != os.getuid()
        or stat.S_IMODE(root_meta.st_mode) != 0o700
    ):
        raise ValueError("private owned Manager phase directory required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if (
            not stat.S_ISREG(meta.st_mode)
            or meta.st_uid != os.getuid()
            or stat.S_IMODE(meta.st_mode) != 0o600
            or meta.st_size > _MANAGER_PHASE_MAX
        ):
            raise ValueError("private bounded Manager phase declaration required")
        raw = os.read(fd, _MANAGER_PHASE_MAX + 1)
        after = os.fstat(fd)
        if (
            meta.st_dev,
            meta.st_ino,
            meta.st_size,
            meta.st_mtime_ns,
            meta.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(raw) != meta.st_size:
            raise ValueError("Manager phase declaration changed")
    finally:
        os.close(fd)
    config = json.loads(raw)
    if (
        set(config)
        != {
            "schema",
            "cell_id",
            "start_id",
            "nonce",
            "root",
            "deadline_ns",
            "socket_path",
        }
        or config["schema"] != _MANAGER_PHASE_SCHEMA
        or config["cell_id"] != "manager-crash-after-launch"
        or not isinstance(config["start_id"], str)
        or not config["start_id"].startswith("manager-crash-after-launch-r")
        or type(config["deadline_ns"]) is not int
        or not re.fullmatch("[0-9a-f]{64}", config["nonce"])
    ):
        raise ValueError("exact source Manager after-launch declaration required")
    native_keys = (
        "VLLM_ECPA_PLAN_ID",
        "VLLM_ECPA_LAUNCH_ID",
        "ECPA_SEMANTIC_EXECUTION_PLAN_ID",
        "ECPA_SEMANTIC_CONTROLLER_INSTANCE",
        "ECPA_SEMANTIC_CANDIDATE_GENERATION",
        "ECPA_SEMANTIC_MEMBERSHIP_EPOCH",
    )
    native = {key: environment.get(key) for key in native_keys}
    if not all(type(value) is str and value for value in native.values()):
        raise ValueError("actual validated Manager native/semantic binding is required")
    if child.poll() is not None:
        raise ValueError(
            "actual launched child exited before Manager phase observation"
        )
    manager = _manager_phase_kernel(os.getpid())
    launched = _manager_phase_kernel(child.pid)
    socket_path = Path(config["socket_path"])
    if (
        socket_path.parent != parent
        or socket_path.resolve() != socket_path
        or len(os.fsencode(socket_path)) > 107
        or socket_path.exists()
    ):
        raise ValueError("fresh bounded private Manager phase socket required")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        server.listen(1)
        remaining = (config["deadline_ns"] - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            raise TimeoutError("original Manager phase deadline expired")
        while True:
            if cancelled():
                raise InterruptedError(
                    "Manager phase interrupted by original managed signal"
                )
            remaining = (config["deadline_ns"] - time.monotonic_ns()) / 1e9
            if remaining <= 0:
                raise TimeoutError("original Manager phase deadline expired")
            server.settimeout(min(remaining, 0.05))
            try:
                connection, _ = server.accept()
                break
            except TimeoutError:
                continue
        with connection:
            pid, uid, gid = struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if (
                uid != os.getuid()
                or gid != os.getgid()
                or _manager_phase_kernel(pid) != config["root"]
            ):
                raise ValueError(
                    "Manager phase challenger is not exact independent root"
                )
            request, request_raw = _manager_phase_read(
                connection, config["deadline_ns"], cancelled
            )
            expected = dict(
                schema=_MANAGER_PHASE_SCHEMA,
                operation="hold-after-launch",
                start_id=config["start_id"],
                nonce=config["nonce"],
                expected_manager=manager,
                expected_native=native,
            )
            if request != expected or child.poll() is not None:
                raise ValueError(
                    "phase challenge differs from actual Manager/native/child binding"
                )
            if _manager_phase_kernel(child.pid) != launched:
                raise ValueError(
                    "actual child epoch changed during Manager phase challenge"
                )
            event = dict(
                schema=_MANAGER_PHASE_SCHEMA,
                phase="manager-crash-after-launch",
                start_id=config["start_id"],
                nonce=config["nonce"],
                manager=manager,
                child=launched,
                root=config["root"],
                native=native,
                request_sha256=hashlib.sha256(request_raw).hexdigest(),
                config_sha256=hashlib.sha256(raw).hexdigest(),
                actual_command=list(command),
                actual_command_sha256=hashlib.sha256(
                    _manager_phase_canonical(list(command))
                ).hexdigest(),
                child_popen_ns=child_popen_ns,
                observed_monotonic_ns=time.monotonic_ns(),
                source={
                    "path": str(Path(__file__).resolve()),
                    "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                },
                model_request_id=None,
                commit_proved=False,
                native_completion_proved=False,
            )
            event_raw = _manager_phase_canonical(event) + b"\n"
            if len(event_raw) > _MANAGER_PHASE_MAX:
                raise ValueError(
                    "actual Manager phase event exceeds original frame bound"
                )
            connection.sendall(event_raw)
            # Root's original phase actuator must capture this evidence and kill
            # this exact Manager via pidfd. EOF is failure, never continuation.
            release, _ = _manager_phase_read(
                connection, config["deadline_ns"], cancelled
            )
            if release != dict(
                schema=_MANAGER_PHASE_SCHEMA,
                operation="release",
                nonce=config["nonce"],
                event_sha256=hashlib.sha256(
                    _manager_phase_canonical(event)
                ).hexdigest(),
            ):
                raise ValueError("Manager phase release differs from observed event")
            if _manager_phase_kernel(pid) != config["root"]:
                raise ValueError("root phase controller epoch changed")


def _managed_signals() -> tuple[signal.Signals, ...]:
    names = ("SIGTERM", "SIGINT", "SIGHUP")
    return tuple(getattr(signal, name) for name in names if hasattr(signal, name))


def _signal_launch_tree(process: subprocess.Popen[bytes], signum: int) -> None:
    """Signal the launch tree without ever signalling the Manager itself."""

    if os.name == "posix":
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signum)
        return
    if signum == _KILL_SIGNAL:
        process.kill()
    else:
        process.terminate()


def _signal_launch_leader(process: subprocess.Popen[bytes], signum: int) -> None:
    """Let the entry process coordinate an orderly shutdown of its children."""

    if process.poll() is not None:
        return
    if os.name == "posix":
        with suppress(ProcessLookupError):
            os.kill(process.pid, signum)
        return
    process.terminate()


def _launch_tree_exists(process: subprocess.Popen[bytes]) -> bool:
    if os.name != "posix":
        return process.poll() is None
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_launch_tree(process: subprocess.Popen[bytes], deadline: float) -> bool:
    while _launch_tree_exists(process):
        if time.monotonic() >= deadline:
            return False
        time.sleep(_POLL_SECONDS)
    return True


def _cleanup_survivors(process: subprocess.Popen[bytes], deadline: float) -> None:
    """Stop descendants that outlive the direct child."""

    if not _launch_tree_exists(process):
        return
    _signal_launch_tree(process, signal.SIGTERM)
    if _wait_for_launch_tree(process, deadline):
        return
    _signal_launch_tree(process, _KILL_SIGNAL)


def supervise(
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    shutdown_grace_seconds: float = DEFAULT_SHUTDOWN_GRACE_SECONDS,
    executable: str | None = None,
    pass_fds: Sequence[int] = (),
) -> int:
    """Run a command and own the lifetime of the process tree it creates.

    On POSIX the child becomes a new session leader. Signals received by the
    Manager first reach the session leader so it can shut down its own workers.
    A second signal or expiration of the grace period escalates to group-wide
    SIGKILL. The direct child is always reaped, and surviving descendants are
    terminated before the Manager returns.
    """

    if shutdown_grace_seconds < 0:
        raise ValueError("shutdown grace period must not be negative")

    child: subprocess.Popen[bytes] | None = None
    received: list[int] = []
    signal_started_at: list[float] = []
    previous_handlers: dict[
        signal.Signals,
        Callable[[int, FrameType | None], object] | int | None,
    ] = {}

    def forward(signum: int, _frame: FrameType | None) -> None:
        first_signal = not received
        received.append(signum)
        if first_signal:
            signal_started_at.append(time.monotonic())
        if child is not None:
            if len(received) > 1:
                _signal_launch_tree(child, _KILL_SIGNAL)
            else:
                _signal_launch_leader(child, signum)

    managed_signals = _managed_signals()
    for managed_signal in managed_signals:
        previous_handlers[managed_signal] = signal.getsignal(managed_signal)
        signal.signal(managed_signal, forward)

    try:
        child_environment = dict(env)
        phase_config = child_environment.pop(_MANAGER_AFTER_LAUNCH_ENV, None)
        child = subprocess.Popen(
            command,
            env=child_environment,
            start_new_session=os.name == "posix",
            executable=executable,
            pass_fds=tuple(pass_fds),
        )
        child_popen_ns = time.monotonic_ns()
        if phase_config is not None:
            try:
                _manager_after_launch_barrier(
                    phase_config,
                    child,
                    env,
                    command,
                    child_popen_ns,
                    cancelled=lambda: bool(received),
                )
            except InterruptedError:
                deadline = (
                    signal_started_at[0] if received else time.monotonic()
                ) + shutdown_grace_seconds
                _cleanup_survivors(child, deadline)
                if received:
                    return 128 + received[0]
                raise
            except BaseException:
                _cleanup_survivors(child, time.monotonic() + shutdown_grace_seconds)
                raise
        if received:
            if len(received) > 1:
                _signal_launch_tree(child, _KILL_SIGNAL)
            else:
                _signal_launch_leader(child, received[0])

        escalated = False
        while True:
            try:
                return_code = child.wait(timeout=_POLL_SECONDS)
                break
            except subprocess.TimeoutExpired:
                if (
                    received
                    and not escalated
                    and time.monotonic() - signal_started_at[0]
                    >= shutdown_grace_seconds
                ):
                    _signal_launch_tree(child, _KILL_SIGNAL)
                    escalated = True

        cleanup_deadline = (
            signal_started_at[0] + shutdown_grace_seconds
            if received
            else time.monotonic() + shutdown_grace_seconds
        )
        _cleanup_survivors(child, cleanup_deadline)
        if received:
            return 128 + received[0]
        return return_code
    finally:
        if child is not None and child.poll() is None:
            _signal_launch_tree(child, _KILL_SIGNAL)
            child.wait()
        for managed_signal, previous_handler in previous_handlers.items():
            signal.signal(managed_signal, previous_handler)
