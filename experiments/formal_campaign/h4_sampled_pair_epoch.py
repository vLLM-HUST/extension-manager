"""Candidate actual Host ownership bridge; no source readiness is native proof."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from experiments.formal_campaign.h3_native_authority import (
    native_host_roster,
    observed_host_kernel,
    verify_native_membership,
)
from experiments.formal_campaign.h3_native_plan_guard import NativePlanGuard
from experiments.formal_campaign.h3_worker_relaunch import cleanup
from experiments.pair_semantic_candidate import authority as pair
from experiments.pair_semantic_candidate.binding import IDS, PROFILER
from vllm_hust_ext.host_evidence import parse_host_event

from .h4_sampled_host_launch import launch_phase

canonical, require = pair.canonical, pair.require


def private_root(path, *, create=False):
    path = Path(path)
    require(
        path.is_absolute() and path.resolve() == path, "canonical run root required"
    )
    if create:
        path.mkdir(mode=0o700, exist_ok=False)
        path.chmod(0o700)  # parent setgid inheritance must not leave mode02700.
    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o700
        and info.st_uid == os.getuid(),
        "run root must be real owned private0700",
    )
    return path


def preflight_paths(root, phase, *, require_fresh=True):
    root = Path(root)
    require(
        root.is_absolute() and root.resolve() == root, "absolute future root required"
    )
    # These are declared paths, never prospective PID/socket identities.
    paths = [root / "n" / "native.sock"]
    if phase["handoff_path"] is not None:
        paths.append(Path(phase["handoff_path"]))
    for path in paths:
        require(
            path.is_absolute() and len(os.fsencode(path)) < 108,
            "registered Unix socket path exceeds kernel limit",
        )
        if require_fresh:
            require(not path.exists() and not path.is_symlink(), "stale control path")
    require(
        Path(phase["cwd"]).is_absolute(), "actual registered publisher cwd required"
    )


def observe_native_epoch(
    phase, arm, output, guard, *, timeout_seconds=900, on_popen=None
):
    """Use actual Manager peer/ACK or baseline path, then retain original events.

    This calls the existing process-owned launch helper, never a CPU stand-in.
    The caller owns cleanup even if downstream bootstrap/client later fail.
    """
    require(
        type(guard) is NativePlanGuard and guard.paired, "full two-MOD guard required"
    )
    require(set(guard.policy["bundle_ids"]) == IDS, "both actual MODs must be enabled")
    output = private_root(output, create=True)
    preflight_paths(output, phase)
    process = owner = owned = None
    try:
        process, owner, owned, observed = launch_phase(
            phase, arm, output, 0, timeout_seconds, on_popen=on_popen
        )
        members = json.loads((output / "phase0.actual-membership.json").read_bytes())
        handoff = json.loads(
            (output / "phase0.native-source-handoff.json").read_bytes()
        )
        journal = Path(handoff["host_evidence"]["path"])
        raw = journal.read_bytes()
        records = [parse_host_event(line) for line in raw.splitlines()]
        parent = next(m for m in members if m["role"] == "api-server")
        plan_id = parent["event"]["plan_id"]
        launch_id = parent["event"]["launch_id"]
        roster = native_host_roster(records, plan_id, launch_id)
        require(
            {"api-server/0", "engine-core-scheduler/0", "worker/0", "worker/1"}
            <= set(roster),
            "actual full API/scheduler/TP2 roster absent",
        )
        kernels = {slot: observed_host_kernel(p) for slot, p in roster.items()}
        peers = []
        for member in members:
            original = member["event"]["process"]
            kernel = observed_host_kernel(original)
            slot = f"{original['role']}/{original['ordinal']}"
            require(
                canonical(original) == canonical(roster[slot])
                and canonical(kernel) == canonical(kernels[slot]),
                "native sender differs from original source-owned Host roster",
            )
            status = Path(f"/proc/{kernel['pid']}/status").read_text().splitlines()
            uid = int(next(x for x in status if x.startswith("Uid:")).split()[2])
            gid = int(next(x for x in status if x.startswith("Gid:")).split()[2])
            require(
                uid == os.getuid() and gid == os.getgid(), "peer credential mismatch"
            )
            peers.append(
                dict(
                    process={**original, **kernel},
                    peer_uid=uid,
                    peer_gid=gid,
                    cmdline_sha256=hashlib.sha256(
                        Path(f"/proc/{kernel['pid']}/cmdline").read_bytes()
                    ).hexdigest(),
                    source_files=phase["native_bootstrap"]["source_files"],
                )
            )
        verify_native_membership(peers, members, plan_id, launch_id)
        semantic = json.loads(Path(phase["semantic_launch_spec"]["path"]).read_bytes())
        enrollment = dict(
            native_plan_id=plan_id,
            native_launch_id=launch_id,
            source_peers=peers,
            semantic_context={
                k: semantic[k]
                for k in (
                    "execution_plan_id",
                    "controller_instance",
                    "candidate_generation",
                    "membership_epoch",
                )
            },
        )
        # launch_phase authenticated real SO_PEERCRED/ACK (Manager) or actual
        # baseline publisher+Host ancestry; no predeclared future handoff root.
        guard.handoffs.add(hashlib.sha256(canonical(handoff)).hexdigest())
        bound = guard.bind_actual(enrollment, handoff, roster, kernels, journal)
        bound.validate_current(enrollment, journal)
        return dict(
            process=process,
            owner=owner,
            owned=owned,
            observed=observed,
            enrollment=enrollment,
            bound=bound,
            host_journal=journal,
            roster=roster,
            kernels=kernels,
            peers=peers,
            output=output,
        )
    except BaseException:
        if process is not None:
            cleanup(process, owner, 10, owned)
        raise


def verify_h4_request_current(
    epoch, native_report, *, runtime_request_id, transaction_id
):
    """Discharge full KV only from the independent H4-owned native verifier."""
    from .h4_sampled_native_verifier import require_verified_h4_native_request

    verified = require_verified_h4_native_request(native_report)
    bound = epoch["bound"]
    snapshot = bound.validate_current(epoch["enrollment"], epoch["host_journal"])
    require(
        verified.runtime_request_id == runtime_request_id
        and verified.transaction_id == transaction_id
        and verified.native_plan_id == snapshot.plan_id.rsplit(":", 1)[-1]
        and verified.native_launch_id == snapshot.native_launch_id,
        "H4 full native token belongs to another actual request/Plan/launch",
    )
    occurrence = hashlib.sha256(
        ("request_finished\0" + runtime_request_id).encode()
    ).hexdigest()
    callbacks = [parse_host_event(line) for line in snapshot._raw.splitlines()]
    require(
        any(
            e["event"] == "effective"
            and e["observation_kind"] == "runtime_effective"
            and e["detail"] == "request-lifecycle-eventbus:request_finished"
            and e["occurrence_id"] == occurrence
            and tuple(e["entry_point"][k] for k in ("group", "name", "value"))
            == pair.ENTRIES[PROFILER]
            and canonical(e["process"])
            == canonical(
                epoch["roster"].get(f"{e['process']['role']}/{e['process']['ordinal']}")
            )
            for e in callbacks
        ),
        "H4 pair lacks actual same-runtime profiler finished callback",
    )
    return snapshot
