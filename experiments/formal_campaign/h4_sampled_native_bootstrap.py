"""Prepare the actual H4 collector after observing a real Host epoch.

This module starts no model and produces no semantic success claim. The caller
must observe the API and both workers before invoking it, and retain the full
original Plan. Bootstrap inputs are written once for that observed epoch.
"""

from __future__ import annotations

import json
import os
import select
import stat
import subprocess
import sys
import time
from pathlib import Path

from experiments.exposure_gate import native_semantic_bootstrap
from experiments.formal_campaign import (
    h4_sampled_native_client,
    h4_sampled_native_collector,
)
from experiments.formal_campaign.h3_worker_recovery import (
    capture_parent_worker_ancestry,
)
from experiments.formal_campaign.h4_sampled_native_source_scope import (
    checked_spec_bytes,
    scope_native_senders,
)
from experiments.native_kv_tensor_candidate import (
    artifact_bootstrap,
    artifact_transport,
)

native = h4_sampled_native_collector.native
require = h4_sampled_native_collector.require


def make_private_directory(path):
    """Normalize only a fresh pinned directory; never modify prior evidence."""
    path = Path(path)
    require(
        path.is_absolute() and path.resolve() == path and not path.is_symlink(),
        "fresh canonical private directory required",
    )
    path.mkdir(mode=0o700, exist_ok=False)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        linked = path.lstat()
        require(
            stat.S_ISDIR(before.st_mode)
            and before.st_uid == os.getuid()
            and (before.st_dev, before.st_ino) == (linked.st_dev, linked.st_ino)
            and not os.listdir(fd),
            "fresh directory identity/ownership differs",
        )
        os.fchmod(fd, 0o700)
        after = os.fstat(fd)
        linked = path.lstat()
        require(
            (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
            and (linked.st_dev, linked.st_ino) == (before.st_dev, before.st_ino)
            and stat.S_IMODE(after.st_mode) == stat.S_IMODE(linked.st_mode) == 0o700,
            "fresh directory exact0700 normalization failed",
        )
    finally:
        os.close(fd)
    return path


def write_private(path, value):
    raw = native.canonical(value)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    return Path(path)


def verify_senders(senders):
    require(
        [(s["process"]["role"], s["process"]["ordinal"]) for s in senders]
        == [("api-server", 0), ("worker", 0), ("worker", 1)],
        "actual H4 native epoch requires API and both TP2 worker slots",
    )
    require(len({s["process"]["pid"] for s in senders}) == 3, "native peers alias")
    for sender in senders:
        process = sender["process"]
        require(
            all(process[k] == v for k, v in native.identity(process["pid"]).items()),
            "observed native kernel epoch changed",
        )
        require(
            native.sha(Path(f"/proc/{process['pid']}/cmdline").read_bytes())
            == sender["cmdline_sha256"],
            "observed native argv changed",
        )
        native.source_digests(sender["source_files"])
    for sender in senders[1:]:
        capture_parent_worker_ancestry(senders[0]["process"], sender["process"])


def start_native_epoch(
    *,
    output,
    senders,
    phases,
    native_plan_id,
    native_launch_id,
    kv_requirements,
    tensor_requirements,
    native_context_path,
    tensor_context_path,
    source_files,
    schedule_path,
):
    """Start actual peer-authenticated intake; return its owned Popen and descriptor.

    ``phases`` comes from the frozen32-selected-request client spec; requirements
    from the admitted original workload/config. No prompt, RPC or Plan is changed.
    Both context paths must have been declared in the real Host environment.
    """
    from experiments.formal_campaign.h4_sampled_native_schedule import (
        bind_selected_phases,
        read_schedule,
    )

    schedule, _ = read_schedule(schedule_path)
    bind_selected_phases({"phases": phases}, schedule)
    output = Path(output)
    require(output.resolve() == output, "native output must be canonical")
    make_private_directory(output)
    require(len(phases) == 32, "H4 native epoch must retain all32 selected client IDs")
    verify_senders(senders)
    senders, source_files = scope_native_senders(senders, source_files)
    native.source_digests(source_files)
    spec_path = write_private(
        output / "native-spec.json",
        {
            "schema": native.KV_SPEC_V2,
            "classification": "CPU_REVIEW_CANDIDATE_ONLY",
            "formal_producer_registration": False,
            "native_plan_id": native_plan_id,
            "native_launch_id": native_launch_id,
            "frozen_monotonic_ns": time.monotonic_ns(),
            "max_event_age_ns": 5_000_000_000,
            "max_uploads_per_rank": 256,
            "senders": senders,
            "phases": phases,
            "kv_requirements": kv_requirements,
        },
    )
    directories = {}
    for sender in senders[1:]:
        pid = sender["process"]["pid"]
        path = output / f"worker-{pid}"
        make_private_directory(path)
        info = path.stat()
        directories[str(pid)] = {
            "path": str(path),
            "identity": [info.st_dev, info.st_ino],
        }
    policy_path = write_private(
        output / "tensor-policy.json",
        {
            "schema": artifact_transport.RUNTIME_POLICY,
            "classification": "REAL_RUNTIME_UNQUALIFIED",
            "formal_registration": False,
            "native_spec_sha256": native.sha(spec_path.read_bytes()),
            "worker_directories": directories,
            "requirements": tensor_requirements,
        },
    )
    drain_path = write_private(
        output / "drain-policy.json",
        {
            "schema": h4_sampled_native_collector.POLICY,
            "native_spec_sha256": native.sha(spec_path.read_bytes()),
            "tensor_policy_sha256": native.sha(policy_path.read_bytes()),
            "phase_ids": [p["phase_id"] for p in phases],
            "required_ranks": [0, 1],
            "formal_registration": False,
        },
    )
    checked_spec_bytes(json.loads(spec_path.read_bytes()))
    # The unchanged Host bootstrap uses the same bounded reader. Fail before
    # starting a collector if the actual32-selected-request spec cannot be consumed.
    for path in (spec_path, policy_path, drain_path):
        native.read_private(path, 0o600)
    socket_path = output / "native.sock"
    log = (output / "collector.stderr").open("xb")
    process = subprocess.Popen(
        [
            sys.executable,
            str(Path(h4_sampled_native_collector.__file__).resolve()),
            "--schedule",
            str(schedule_path),
            "--spec",
            str(spec_path),
            "--policy",
            str(policy_path),
            "--drain-policy",
            str(drain_path),
            "--journal",
            str(output / "native.jsonl"),
            "--socket",
            str(socket_path),
            "--owned-stdin-lifetime",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=log,
        start_new_session=True,
    )
    log.close()
    try:
        # Keep even failed actual starts, including PID and stderr. No synthetic
        # enrollment is generated if the process fails before readiness.
        write_private(
            output / "collector-start.json",
            {
                "pid": process.pid,
                "observed_monotonic_ns": time.monotonic_ns(),
                "formal_result": False,
            },
        )
        require(
            select.select([process.stdout], [], [], 10)[0], "native collector not ready"
        )
        line = process.stdout.readline()
        require(bool(line), "native collector exited before actual readiness")
        ready = json.loads(line)
        actual = native.identity(process.pid)
        require(ready["collector"] == actual, "native collector announced wrong kernel")
        descriptor = ready | {
            "launcher_observed_identity": actual,
            "launcher_observed_cmdline_sha256": native.sha(
                Path(f"/proc/{process.pid}/cmdline").read_bytes()
            ),
        }
        h4_sampled_native_client.authenticate(
            socket_path,
            descriptor,
            spec_path,
            Path(h4_sampled_native_collector.__file__),
            drain_policy_path=drain_path,
            schedule_path=schedule_path,
        )
        verify_senders(senders)
        native_semantic_bootstrap.write_context(
            Path(native_context_path),
            spec_path=spec_path,
            ready=ready,
            source_files=source_files,
        )
        artifact_bootstrap.write_context(
            Path(tensor_context_path),
            spec_path=spec_path,
            policy_path=policy_path,
            ready=ready,
            source_files=source_files,
        )
        verify_senders(senders)
        write_private(output / "collector-descriptor.json", descriptor)
        return process, descriptor
    except BaseException:
        if process.stdin:
            process.stdin.close()
        process.wait(timeout=10)
        raise
