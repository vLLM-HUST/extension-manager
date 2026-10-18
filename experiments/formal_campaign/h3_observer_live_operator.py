"""Explicit original-arm operator process; actual invocation is always charged."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import select
import stat
import subprocess
import sys
import time
from pathlib import Path

from experiments.formal_campaign.h3_dynamic_authority import require
from experiments.formal_campaign.h3_observer_live_launcher import write_private
from experiments.formal_campaign.h3_observer_live_registration import validate_for_start


def _send(stream, value):
    raw = (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n"
    )
    require(len(raw) <= 64 * 1024, "bounded operator control frame required")
    stream.write(raw)
    stream.flush()


def _receive(descriptor, deadline_ns, *, current=lambda: None):
    raw = b""
    while not raw.endswith(b"\n"):
        current()
        remaining = (
            None if deadline_ns is None else (deadline_ns - time.monotonic_ns()) / 1e9
        )
        require(
            remaining is None or remaining > 0,
            "operator control absolute deadline expired",
        )
        ready, _, _ = select.select(
            [descriptor], [], [], min(0.1, remaining) if remaining is not None else 0.1
        )
        if not ready:
            continue
        piece = os.read(descriptor, 64 * 1024 + 1 - len(raw))
        require(
            piece and len(raw) + len(piece) <= 64 * 1024,
            "operator control EOF/oversize",
        )
        raw += piece
    value = json.loads(raw)
    require(
        raw
        == json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n",
        "operator control noncanonical/trailing frame",
    )
    return value


def _reference(path, mode=0o600):
    path = Path(path)
    require(
        path.is_absolute() and path.resolve() == path,
        "canonical operator input required",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == os.getuid()
            and (
                (mode is None and not before.st_mode & 0o022)
                or (mode is not None and stat.S_IMODE(before.st_mode) == mode)
            ),
            "owned regular operator input required",
        )
        digest = hashlib.sha256()
        while True:
            raw = os.read(fd, 128 * 1024)
            if not raw:
                break
            digest.update(raw)
        after = os.fstat(fd)
        current = path.lstat()
        fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mode",
            "st_uid",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        require(
            all(
                getattr(before, k) == getattr(after, k) == getattr(current, k)
                for k in fields
            ),
            "operator input changed during read",
        )
        return {"path": str(path), "sha256": "sha256:" + digest.hexdigest()}
    finally:
        os.close(fd)


def _fault_evidence(output, start_id, authority, qualified_ns):
    names = (
        "observer-fault-raw.json",
        "runner-fault.json",
        "runner-observer-dead.json",
    )
    refs = [_reference(output / name) for name in names]
    raw, fault, dead = [json.loads(Path(ref["path"]).read_bytes()) for ref in refs]
    require(
        raw["schema"] == "ecpa-h3-observer-loss-raw/v1"
        and raw["start_id"] == start_id
        and raw["binding"]["start_id"] == start_id
        and raw["binding"]["authority"] == authority
        and raw["fault"] == fault
        and fault["signal"] == "SIGKILL"
        and raw["binding"]["observer"] == fault["target"]
        and qualified_ns
        < fault["triggered_ns"]
        <= dead["observed_dead_ns"]
        == raw["pidfd_observed_dead_ns"],
        "actual original observer fault/pidfd proof differs",
    )
    require(
        all(_reference(ref["path"]) == ref for ref in refs),
        "fault proof changed during read",
    )
    return fault, refs


class PreparedOperator:
    """A live Popen/anonymous-pipe handle; never constructed from a ready flag."""

    def __init__(self, process, kernel, pidfd, command, output, parent, nonce):
        self.process, self.kernel, self.pidfd = process, kernel, pidfd
        self.command, self.output, self.parent, self.nonce = (
            command,
            output,
            parent,
            nonce,
        )
        self.ready, self.prearm_ref, self.used = None, None, False

    def current(self):
        from experiments.formal_campaign.h3_worker_relaunch import identity

        require(
            self.process.poll() is None and identity(self.process.pid) == self.kernel,
            "prearmed original operator epoch exited/changed",
        )
        require(
            not select.select([self.pidfd], [], [], 0)[0],
            "prearmed operator pidfd is dead",
        )
        argv = [
            p.decode()
            for p in Path(f"/proc/{self.process.pid}/cmdline").read_bytes().split(b"\0")
            if p
        ]
        require(argv == self.command, "prearmed original operator argv changed")

    def close(self, cleanup):
        try:
            if self.process.stdin:
                self.process.stdin.close()
            # A reaped operator can still own surviving session members. The
            # unchanged carrier cleanup proves exact kernels and external-owner
            # exclusions before signalling; never skip it just for poll()!=None.
            cleanup(self.process, self.kernel, 5, [self.kernel])
        finally:
            if self.process.stdout:
                self.process.stdout.close()
            if self.pidfd is not None:
                os.close(self.pidfd)
                self.pidfd = None


def prepare(scope, recipe, output, *, timeout_s, cleanup):
    from experiments.formal_campaign.h3_worker_relaunch import identity

    command = scope.value()["declaration"]["operator"]["command"]
    parent, nonce = identity(os.getpid()), secrets.token_hex(32)
    started = time.monotonic_ns()
    prepared = None
    with (output / "live-operator.stderr").open("xb") as stderr:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            start_new_session=True,
        )
        write_private(
            output / "live-operator-launch.json",
            dict(
                pid=process.pid,
                parent=parent,
                command=command,
                started_ns=started,
                formal_result=False,
            ),
        )
        try:
            kernel = identity(process.pid)
            pidfd = os.pidfd_open(process.pid)
            prepared = PreparedOperator(
                process, kernel, pidfd, command, output, parent, nonce
            )
            prepared.current()
            _send(
                process.stdin, {"operation": "prearm", "parent": parent, "nonce": nonce}
            )
            ready = _receive(
                process.stdout.fileno(),
                started + int(timeout_s * 1e9),
                current=prepared.current,
            )
            require(
                set(ready)
                == {
                    "schema",
                    "start_id",
                    "operator",
                    "parent",
                    "nonce",
                    "live_receipt",
                    "recipe",
                    "source",
                    "authority",
                    "qualification_completed_ns",
                }
                and ready["schema"] == "ecpa-h3-original-operator-qualified-ready/v1"
                and ready["operator"] == kernel
                and ready["parent"] == parent
                and ready["nonce"] == nonce
                and ready["start_id"] == scope.value()["start"]["start_id"]
                and ready["live_receipt"] == scope.receipt_ref()
                and ready["recipe"] == _reference(output / "runtime-recipe.json")
                and all(
                    ready["authority"][k] == v
                    for k, v in recipe["authority"]["process_identity"].items()
                )
                and ready["source"] == _reference(Path(command[1]), None)
                and started
                <= ready["qualification_completed_ns"]
                <= time.monotonic_ns(),
                "source-owned operator ready handshake differs",
            )
            prepared.current()
            received = time.monotonic_ns()
            with (output / "live-operator.stdout").open("xb") as stdout:
                _send(stdout, ready)
            prepared.ready = ready
            prepared.prearm_ref = write_private(
                output / "live-operator-prearm.json",
                dict(
                    schema="ecpa-h3-original-operator-prearmed/v1",
                    command=command,
                    ready=ready,
                    process_started_ns=started,
                    ready_received_ns=received,
                    formal_result=False,
                ),
            )
            prepared.prearm_ref = _reference(output / "live-operator-prearm.json")
            return prepared
        except BaseException:
            if prepared is not None:
                prepared.close(cleanup)
            else:
                # No guessed PID/session fallback. The original independent
                # runner retains this owned Popen and performs its strict drain.
                if process.stdin:
                    process.stdin.close()
                if process.stdout:
                    process.stdout.close()
                process.wait(timeout=5)
            raise


def invoke(scope, args, recipe, registration, output, *, prepared):
    require(
        type(prepared) is PreparedOperator and not prepared.used,
        "one actual prearmed original operator required",
    )
    prepared.current()
    fault, refs = _fault_evidence(
        output,
        args.start_id,
        prepared.ready["authority"],
        prepared.ready["qualification_completed_ns"],
    )
    deadline = fault["triggered_ns"] + 30_000_000_000
    require(
        time.monotonic_ns() < deadline,
        "original30s bound expired before explicit operator action",
    )
    started = time.monotonic_ns()
    prepared.used = True
    action = dict(
        schema="ecpa-h3-actual-explicit-operator-action/v2",
        start_id=args.start_id,
        command=prepared.command,
        operator_pid=prepared.process.pid,
        operator_kernel=prepared.kernel,
        kernel_observation_error=None,
        started_ns=started,
        original_deadline_ns=deadline,
        operator_actions=1,
        prearm=prepared.prearm_ref,
        formal_result=False,
    )
    write_private(output / "live-operator-action.json", action)
    _send(
        prepared.process.stdin,
        {"operation": "repair", "nonce": prepared.nonce, "fault_evidence": refs},
    )
    returncode = prepared.process.wait(
        timeout=max(0.001, (deadline - time.monotonic_ns()) / 1e9)
    )
    finished = time.monotonic_ns()
    write_private(
        output / "live-operator-terminal.json",
        dict(
            action=action,
            returncode=returncode,
            finished_ns=finished,
            deadline_met=finished <= deadline,
            formal_result=False,
        ),
    )
    require(
        returncode == 0 and finished <= deadline,
        "actual explicit operator repair failed or exceeded original30s",
    )
    result = json.loads((output / "live-operator-result.json").read_bytes())
    require(
        result["start_id"] == args.start_id
        and result["actual_operator_pid"] == prepared.process.pid
        and result["formal_result"] is False,
        "operator result belongs to another original actor/start",
    )
    return result["reply"]


def main():
    from experiments.formal_campaign.h3_observer_carrier import (
        NativeRegisteredAuthority,
    )
    from experiments.formal_campaign.h3_observer_registration import (
        validate_receipt_for_start,
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intent", type=Path, required=True)
    parser.add_argument("--live-receipt", type=Path, required=True)
    parser.add_argument("--start-id", required=True)
    parser.add_argument("--runtime-recipe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    from experiments.formal_campaign.h3_worker_relaunch import identity

    parent = identity(os.getppid())

    def parent_current():
        require(identity(parent["pid"]) == parent, "original carrier parent changed")

    challenge = _receive(sys.stdin.buffer.fileno(), None, current=parent_current)
    require(
        set(challenge) == {"operation", "parent", "nonce"}
        and challenge["operation"] == "prearm"
        and challenge["parent"] == parent
        and type(challenge["nonce"]) is str
        and len(challenge["nonce"]) == 64,
        "actual inherited carrier prearm challenge required",
    )
    scope = validate_for_start(
        args.intent, args.live_receipt, args.start_id, check_remote=True
    )
    value = scope.value()
    spec = value["base_campaign"]["path"]
    receipt = value["base_receipt"]["path"]
    registered = validate_receipt_for_start(
        spec, receipt, args.start_id, check_remote=True
    )
    recipe = json.loads(args.runtime_recipe.read_bytes())
    authority = NativeRegisteredAuthority(recipe, registered, args.start_id)
    authority.live_scope = scope
    capabilities = authority.preflight()
    require(
        "ecpa-h3-observer-live-transport-control/v2" in capabilities["profiles"]
        and capabilities.get("live_receipt") == scope.receipt_ref(),
        "actual authority v2 permission does not bind this operator start",
    )
    scope.native_admission(args.start_id)
    qualified = time.monotonic_ns()
    ready = dict(
        schema="ecpa-h3-original-operator-qualified-ready/v1",
        start_id=args.start_id,
        operator=identity(os.getpid()),
        parent=parent,
        nonce=challenge["nonce"],
        live_receipt=scope.receipt_ref(),
        recipe=_reference(args.runtime_recipe),
        source=_reference(Path(__file__).resolve(), None),
        authority=authority.process,
        qualification_completed_ns=qualified,
    )
    parent_current()
    _send(sys.stdout.buffer, ready)
    trigger = _receive(sys.stdin.buffer.fileno(), None, current=parent_current)
    require(
        set(trigger) == {"operation", "nonce", "fault_evidence"}
        and trigger["operation"] == "repair"
        and trigger["nonce"] == challenge["nonce"],
        "prearmed operator trigger differs",
    )
    fault, refs = _fault_evidence(
        args.output.parent, args.start_id, authority.process, qualified
    )
    require(trigger["fault_evidence"] == refs, "actual fault evidence substitution")
    require(
        time.monotonic_ns() < fault["triggered_ns"] + 30_000_000_000,
        "original30s expired before same-process repair",
    )
    scope.native_admission(args.start_id)
    authority._verify_authority()
    require(
        authority.call("query")["route"]["generation"] is None,
        "original route must close before observer repair",
    )
    parent_current()
    reply = authority.restart_live_observer(original_fault_ns=fault["triggered_ns"])
    write_private(
        args.output,
        dict(
            start_id=args.start_id,
            reply=reply,
            formal_result=False,
            actual_operator_pid=os.getpid(),
            recorded_ns=time.monotonic_ns(),
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
