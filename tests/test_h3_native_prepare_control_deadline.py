"""CPU control transport timing; no model, native evidence or qualification."""

import json
import os
import socket
import threading
import time

import pytest

from experiments.formal_campaign.h3_owned_worker_carrier import (
    NativeRegisteredAuthority,
    RegisteredAuthority,
)


def bound_client(path, cls=NativeRegisteredAuthority):
    value = object.__new__(cls)
    value._verify_authority = lambda: None  # These tests isolate transport timing.
    value.registration_sha = "sha256:" + "a" * 64
    value.grant = {"grant_holder": "fixture", "grant_token": 1}
    value.socket = str(path)
    value.process = {"pid": os.getpid()}
    value.uid, value.gid = os.getuid(), os.getgid()
    return value


def test_actual_unix_prepare_can_finish_after_five_seconds_within_original_ready_bound(
    tmp_path,
):
    path = tmp_path / "control.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)
    received = []

    def respond():
        with server:
            channel, _ = server.accept()
            with channel:
                data = b""
                while not data.endswith(b"\n"):
                    data += channel.recv(4096)
                received.append(json.loads(data))
                time.sleep(5.1)
                channel.sendall(
                    b'{"ok":true,"native_state":"source-prepared-private-only"}\n'
                )

    worker = threading.Thread(target=respond)
    worker.start()
    try:
        result = bound_client(path).prepare_native_epoch(
            phase_index=0,
            handoff={"path": "fixture", "sha256": "sha256:" + "b" * 64},
            ready_deadline_ns=time.monotonic_ns() + 8_000_000_000,
        )
        assert result["native_state"] == "source-prepared-private-only"
        assert len(received) == 1
        assert received[0]["operation"] == "prepare_native_epoch"
        assert set(received[0]) == {
            "operation",
            "registration_sha256",
            "holder",
            "token",
            "phase_index",
            "handoff",
        }
    finally:
        worker.join(timeout=10)
    assert not worker.is_alive()


def test_native_prepare_expired_original_ready_bound_rejects_before_connection(
    tmp_path,
):
    with pytest.raises(ValueError, match="original Host readiness deadline"):
        bound_client(tmp_path / "absent").prepare_native_epoch(
            phase_index=0, handoff={}, ready_deadline_ns=time.monotonic_ns() - 1
        )


@pytest.mark.parametrize(
    "cls,operation",
    [
        (RegisteredAuthority, "prepare_native_epoch"),
        (NativeRegisteredAuthority, "admit_generation"),
        (NativeRegisteredAuthority, "close_generation"),
    ],
)
def test_extended_response_bound_cannot_change_other_control_operations(
    tmp_path, cls, operation
):
    with pytest.raises(ValueError, match="native preparation only"):
        bound_client(tmp_path / "absent", cls)._call(
            operation, {}, response_deadline_ns=time.monotonic_ns() + 8_000_000_000
        )


def test_read_deadline_is_absolute_and_timeouts_have_operation_context(tmp_path):
    path = tmp_path / "control.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)
    calls = []

    def respond():
        with server:
            channel, _ = server.accept()
            with channel:
                data = b""
                while not data.endswith(b"\n"):
                    data += channel.recv(4096)
                calls.append(data)
                for part in (b'{"ok":', b"true", b"}\n"):
                    time.sleep(0.12)
                    try:
                        channel.sendall(part)
                    except BrokenPipeError:
                        break

    worker = threading.Thread(target=respond)
    worker.start()
    try:
        with pytest.raises(
            TimeoutError, match="prepare_native_epoch timed out during response"
        ):
            bound_client(path).prepare_native_epoch(
                phase_index=0,
                handoff={},
                ready_deadline_ns=time.monotonic_ns() + 250_000_000,
            )
    finally:
        worker.join(timeout=2)
    assert len(calls) == 1  # No mutation retries after a timeout.


def test_ordinary_calls_still_use_five_second_transport_timeout(monkeypatch, tmp_path):
    timeouts = []

    class Channel:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, value):
            timeouts.append(value)

        def connect(self, path):
            raise TimeoutError("fixture")

    monkeypatch.setattr(socket, "socket", lambda *args: Channel())
    with pytest.raises(TimeoutError, match="admit_generation timed out during connect"):
        bound_client(tmp_path / "control").call("admit_generation", generation=1)
    assert timeouts == [5]
