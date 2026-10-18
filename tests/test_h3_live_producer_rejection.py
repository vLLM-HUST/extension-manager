"""Owned real UDS rejection evidence is diagnostic, never a prepared ACK."""

import os
import secrets
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest

from experiments.formal_campaign import h3_observer_live_rebind as rebind


@pytest.mark.parametrize("kind", ["rejected", "promoted", "wrong-schema"])
def test_authenticated_rejection_retains_exact_wire_and_never_prepares(kind):
    with tempfile.TemporaryDirectory(prefix="h3reject-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        path = root / "control.sock"
        reply = dict(
            schema=rebind.REPLY,
            state="rejected",
            reason="collector status failed or differs from frozen owner/source",
            native_completion_proved=False,
        )
        if kind == "promoted":
            reply["native_completion_proved"] = True
        if kind == "wrong-schema":
            reply["schema"] = "foreign"
        command = dict(operation="prepare", transition_nonce=secrets.token_hex(32))
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        path.chmod(0o600)
        server.listen(1)
        server.settimeout(2)
        info = path.stat()
        endpoint = dict(
            socket_path=str(path),
            socket_identity=[info.st_dev, info.st_ino],
            producer=rebind.native.identity(os.getpid()),
        )
        failures = []

        def actor():
            try:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(2)
                    raw = b""
                    while not raw.endswith(b"\n"):
                        raw += connection.recv(rebind.native.MAX_FRAME + 1)
                    assert raw == rebind.native.canonical(command) + b"\n"
                    connection.sendall(rebind.native.canonical(reply) + b"\n")
            except Exception as error:
                failures.append(error)

        thread = threading.Thread(target=actor)
        thread.start()
        try:
            with pytest.raises(ValueError) as captured:
                rebind.call(endpoint, command, time.monotonic_ns() + 2_000_000_000)
            if kind == "rejected":
                assert isinstance(captured.value, rebind.ProducerRejected)
                evidence = captured.value.evidence
                assert evidence["response"] == reply
                assert evidence["response_sha256"] == rebind.native.sha(
                    rebind.native.canonical(reply) + b"\n"
                )
                assert evidence["command_sha256"] == rebind.native.sha(
                    rebind.native.canonical(command) + b"\n"
                )
                assert evidence["producer"] == endpoint["producer"]
                assert evidence["socket_identity"] == endpoint["socket_identity"]
                assert evidence["native_completion_proved"] is False
            else:
                assert not isinstance(captured.value, rebind.ProducerRejected)
        finally:
            thread.join(3)
            server.close()
            assert not thread.is_alive()
            assert failures == []
