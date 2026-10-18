"""Future real CPU socket/pidfd negative tests; never executed in this packet."""

import multiprocessing
import os
import socket
import threading

import pytest
from experiments.formal_campaign.conditional_selection_authority import (
    SelectionAuthority,
    canonical,
    identity,
)
from experiments.formal_campaign.qualify_conditional import request_schedule


def _wait_child(connection):
    connection.recv()


def test_unknown_scheduler_rid_cannot_be_treated_as_unselected(tmp_path):
    # The original API peer is a genuine separate CPU process. Scheduler is this
    # actual process, permitting SO_PEERCRED and exact kernel checks without mocks.
    parent, child = multiprocessing.Pipe()
    process = multiprocessing.Process(target=_wait_child, args=(child,))
    process.start()
    authority = None
    try:
        authority = SelectionAuthority(
            socket_path=tmp_path / "s",
            start_id="unregistered-conditional-cpu",
            plan_id="a" * 64,
            launch_id="cpu-original-launch",
            nonce="b" * 64,
            api_kernel=identity(process.pid),
            scheduler_kernel=identity(os.getpid()),
            original_schedule=request_schedule("unregistered-conditional-cpu"),
            output=tmp_path / "raw",
        )
        errors = []

        def receive():
            try:
                authority.serve_one(2)
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=receive)
        thread.start()
        packet = dict(
            authority.binding,
            role="scheduler",
            sequence=1,
            operation="query",
            payload={"runtime_request_ids": ["unknown-real-runtime-RID"]},
        )
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
            client.connect(str(tmp_path / "s"))
            client.sendall(canonical(packet))
            assert client.recv(1024) == b""
        thread.join(3)
        assert not thread.is_alive()
        assert len(errors) == 1 and "unknown/unmapped" in str(errors[0])
        assert (tmp_path / "raw").read_bytes() == b""
    finally:
        if authority is not None:
            authority.close()
        parent.send("stop")
        process.join(3)
        if process.is_alive():
            process.terminate()
            process.join()


def test_duplicate_original_schedule_refused_before_socket_binding(tmp_path):
    rows = request_schedule("unregistered-conditional-cpu")
    rows[-1] = dict(rows[0])
    with pytest.raises(ValueError, match="original272"):
        SelectionAuthority(
            socket_path=tmp_path / "s",
            start_id="unregistered-conditional-cpu",
            plan_id="a" * 64,
            launch_id="cpu-launch",
            nonce="b" * 64,
            api_kernel={},
            scheduler_kernel={},
            original_schedule=rows,
            output=tmp_path / "raw",
        )
    assert not (tmp_path / "s").exists() and not (tmp_path / "raw").exists()
