"""Actual owned-child exit races; no Host/model/device or formal qualification."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from experiments.formal_campaign import h3_observer_runner as runner
from experiments.formal_campaign import h3_worker_relaunch as ownership
from vllm_hust_ext.exposure_gate import GateError


@pytest.fixture
def child():
    process = subprocess.Popen(
        [sys.executable, "-c", "import sys;sys.stdin.buffer.read(1)"],
        stdin=subprocess.PIPE,
        start_new_session=True,
    )
    owner = ownership.identity(process.pid)
    try:
        yield process, owner
    finally:
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        process.wait(timeout=3)
        assert not Path(f"/proc/{process.pid}").exists()
        report = os.environ.get("ECPA_OWNERSHIP_RACE_TEST_REPORT")
        if report:
            with Path(report).open("a") as stream:
                stream.write(
                    json.dumps(
                        dict(
                            kernel=owner,
                            returncode=process.returncode,
                            remaining_proc=False,
                            test_child_only=True,
                        )
                    )
                    + "\n"
                )


def finish(process):
    process.stdin.close()
    assert process.wait(timeout=3) == 0


def test_actual_exit_between_optional_probe_and_strict_capture(child, monkeypatch):
    process, owner = child
    retained = [dict(owner)]
    exits = []
    strict = ownership.owned_sessions
    calls = []

    def actual_race(expected):
        calls.append(expected)
        finish(process)
        return strict(expected)

    monkeypatch.setattr(runner, "owned_sessions", actual_race)
    assert runner._optional_owned_descendants(process, owner, exits) == {}
    assert calls == [owner]
    assert retained == [owner]
    assert exits[0]["kernel"] == owner
    assert exits[0]["state"] == "ENOENT"
    assert exits[0]["popen_returncode"] == 0
    assert runner._optional_owned_descendants(process, owner, exits) == {}
    assert len(exits) == 1
    # Mandatory initial/phase capture remains strict, even for the same child.
    with pytest.raises(ownership.OwnershipCaptureOwnerUnavailable):
        ownership.owned_sessions(owner)
    with pytest.raises(ownership.OwnershipCaptureOwnerUnavailable):
        runner.observe_phase({}, owner)


def test_same_epoch_actual_zombie_is_not_fresh_ancestry(child):
    process, owner = child
    process.stdin.close()
    deadline = time.monotonic() + 3
    while True:
        raw = Path(f"/proc/{process.pid}/stat").read_text()
        if raw.rsplit(")", 1)[1].split()[0] == "Z":
            break
        assert time.monotonic() < deadline
        time.sleep(0.005)
    exits = []
    assert runner._optional_owned_descendants(process, owner, exits) == {}
    assert exits[0]["state"] == "ENOENT"
    assert exits[0]["proc_stat_raw"] is None
    assert exits[0]["popen_returncode"] == 0


def test_optional_live_capture_keeps_actual_strict_ancestry(child):
    process, owner = child
    exits = []
    table = runner._optional_owned_descendants(process, owner, exits)
    assert table[owner["pid"]] == owner
    assert exits == []


def test_typed_entry_error_does_not_hide_still_live_owner(child, monkeypatch):
    process, owner = child

    def unavailable(_):
        raise ownership.OwnershipCaptureOwnerUnavailable("original entry failed")

    monkeypatch.setattr(runner, "owned_sessions", unavailable)
    with pytest.raises(
        ownership.OwnershipCaptureOwnerUnavailable, match="original entry failed"
    ):
        runner._optional_owned_descendants(process, owner, [])
    assert process.poll() is None


def test_nested_error_propagates_even_if_owner_actually_exits(child, monkeypatch):
    process, owner = child
    error = ValueError("nested session leader changed")

    def nested_failure(_):
        finish(process)
        raise error

    monkeypatch.setattr(runner, "owned_sessions", nested_failure)
    exits = []
    with pytest.raises(ValueError) as raised:
        runner._optional_owned_descendants(process, owner, exits)
    assert raised.value is error
    assert exits == []


def test_unrecognized_typed_subclass_is_not_accepted(child, monkeypatch):
    process, owner = child

    class UnknownCaptureFailure(ownership.OwnershipCaptureOwnerUnavailable):
        pass

    def unknown(_):
        finish(process)
        raise UnknownCaptureFailure("not the exact original entry error")

    monkeypatch.setattr(runner, "owned_sessions", unknown)
    with pytest.raises(UnknownCaptureFailure):
        runner._optional_owned_descendants(process, owner, [])


@pytest.mark.parametrize("field", ["start_ticks", "session", "boot_id"])
def test_replaced_epoch_and_boot_are_never_skipped(child, field):
    process, owner = child
    changed = dict(owner)
    changed[field] = owner[field] + 1 if isinstance(owner[field], int) else "oldboot"
    with pytest.raises(GateError, match="changed|replaced"):
        runner._optional_owned_descendants(process, changed, [])
    assert process.poll() is None


def test_disappeared_epoch_requires_real_popen_exit(child, monkeypatch):
    process, owner = child
    finish(process)
    with monkeypatch.context() as patch:
        patch.setattr(process, "poll", lambda: None)
        with pytest.raises(GateError, match="lacks actual Popen exit"):
            runner._optional_owned_descendants(process, owner, [])


def test_actual_exit_after_live_stat_read_is_not_false_integrity_error(
    child, monkeypatch
):
    process, owner = child
    original = Path.read_text
    fired = []

    def read_then_exit(path, *args, **kwargs):
        raw = original(path, *args, **kwargs)
        if path == Path(f"/proc/{process.pid}/stat") and not fired:
            assert raw.rsplit(")", 1)[1].split()[0] != "Z"
            fired.append(True)
            finish(process)
        return raw

    monkeypatch.setattr(Path, "read_text", read_then_exit)
    exits = []
    assert runner._optional_owned_descendants(process, owner, exits) == {}
    assert fired == [True]
    assert exits[0]["popen_returncode"] == 0
    assert exits[0]["kernel"] == owner


def test_actual_exit_to_zombie_after_first_poll_keeps_exact_epoch(child, monkeypatch):
    process, owner = child
    actual_poll = process.poll
    fired = []

    def poll_then_exit():
        result = actual_poll()
        if not fired:
            assert result is None
            fired.append(True)
            process.stdin.close()
            deadline = time.monotonic() + 3
            while True:
                raw = Path(f"/proc/{process.pid}/stat").read_text()
                if raw.rsplit(")", 1)[1].split()[0] == "Z":
                    break
                assert time.monotonic() < deadline
                time.sleep(0.005)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(process, "poll", poll_then_exit)
        exits = []
        assert runner._optional_owned_descendants(process, owner, exits) == {}
    assert exits[0]["state"] == "Z"
    assert exits[0]["kernel"] == owner
    assert exits[0]["proc_stat_raw"].rsplit(")", 1)[1].split()[0] == "Z"
    assert exits[0]["popen_returncode"] == 0
