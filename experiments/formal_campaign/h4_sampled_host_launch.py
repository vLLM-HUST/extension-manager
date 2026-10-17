"""H4 actual Host launch, preserving the published source-owned handoff path.

Derived from exacte606 launch_phase only; the original H3 module is unchanged.
The only behavioral additions are actual Popen RAW clocks and a resource-sampler
hook. No extra serving/qualification HTTP request is introduced.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from experiments.formal_campaign.h3_owned_worker_carrier import (
    checked_reference,
    load,
    reference,
    save_new,
)
from experiments.formal_campaign.h3_worker_recovery import (
    capture_parent_worker_ancestry,
    require,
)
from experiments.formal_campaign.h3_worker_relaunch import (
    cleanup,
    identity,
    owned_sessions,
    worker,
)
from vllm_hust_ext.host_evidence import parse_host_event
from vllm_hust_ext.plan_artifact import read_plan_artifact
from vllm_hust_ext.runtime_phase_handoff import accept_native_binding, bind_receiver


def launch_phase(phase, arm, output, index, timeout, *, on_popen=None):
    """Launch the real pinned Host; bind events to actual native origin."""
    from .h4_sampled_registration import preflight_native_spec
    preflight_native_spec(phase)  # before listener setup or any product Popen
    environment = dict(phase["environment"])
    argv = list(phase["argv"])
    listener = None
    socket_path = Path(phase["handoff_path"]) if phase["handoff_path"] else None
    if phase["origin"] == "manager-native-handoff":
        require(
            socket_path is not None and not socket_path.exists(),
            "fresh Manager handoff socket required",
        )
        listener = bind_receiver(socket_path, timeout)
    else:
        plan = read_plan_artifact(checked_reference(phase["plan_artifact"]))
        if phase.get("semantic_launch_spec"):
            from vllm_hust_ext.discovery import discover_bundles
            from vllm_hust_ext.semantic_runtime_binding import (
                semantic_context_environment,
                validate_semantic_launch_spec,
            )

            path = checked_reference(phase["semantic_launch_spec"])
            declared = load(path)
            bundles = discover_bundles(
                [s["bundle_id"] for s in declared["enabled_bundles"]]
            )
            semantic = validate_semantic_launch_spec(path, bundles)
            require(
                plan.plan_id == semantic["execution_plan_id"],
                "baseline full Plan differs from actual semantic spec",
            )
            environment.update(semantic_context_environment(path, semantic))
            runtime_plan = semantic["native_plan_id"]
        else:
            runtime_plan = plan.plan_id
        environment.update(
            VLLM_ECPA_PLAN_ID=runtime_plan,
            VLLM_ECPA_LAUNCH_ID=phase["launch_id"],
            VLLM_HUST_EXT_EVIDENCE_PATH=phase["evidence_path"],
        )
    require(
        not Path(phase["evidence_path"]).exists(), "fresh Host evidence stream required"
    )
    started_wall = time.time_ns()
    with (output / f"phase{index}.log").open("xb") as log:
        product_popen_before_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        product_popen_before_monotonic_ns = time.monotonic_ns()
        process = subprocess.Popen(
            argv,
            cwd=phase["cwd"],
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        product_popen_after_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    early_owner = identity(process.pid)
    try:
        save_new(output / f"phase{index}.product-popen-timing.json", {
            "schema": "ecpa-h4-sampled-real-product-popen/v1",
            "clock": "CLOCK_MONOTONIC_RAW",
            "before_ns": product_popen_before_ns, "after_ns": product_popen_after_ns,
            "before_monotonic_ns": product_popen_before_monotonic_ns,
            "actual_kernel": identity(process.pid), "argv": argv,
        })
        if on_popen is not None:
            on_popen(process)
    except BaseException:
        cleanup(process, early_owner, 10, [early_owner])
        raise
    save_new(
        output / f"phase{index}.launch-observation.json",
        {"pid": process.pid, "launched_monotonic_ns": time.monotonic_ns()},
    )
    owner, owned = None, []
    try:
        owner = identity(process.pid)
        owned = [owner]
        save_new(output / f"phase{index}.live-owner.json", owner)
        if listener is not None:
            bound = accept_native_binding(
                listener,
                socket_path,
                owner,
                started_wall,
                phase["manager_source_sha256"],
                output / f"phase{index}.handoff-unvalidated.json",
            )
            save_new(output / f"phase{index}.native-binding.json", bound)
            env = bound["environment"]
            evidence_path = Path(env["VLLM_HUST_EXT_EVIDENCE_PATH"])
            plan_id, launch_id = env["VLLM_ECPA_PLAN_ID"], env["VLLM_ECPA_LAUNCH_ID"]
        else:
            evidence_path = Path(phase["evidence_path"])
            plan_id, launch_id = (
                environment["VLLM_ECPA_PLAN_ID"],
                environment["VLLM_ECPA_LAUNCH_ID"],
            )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            require(
                process.poll() is None,
                "actual Host exited before process-owned readiness",
            )
            if evidence_path.exists():
                workers = [
                    worker(
                        {
                            "evidence_protocol": "vllm-host-worker-event/v1",
                            "target_ordinal": ordinal,
                            "plan_id": plan_id,
                        },
                        {"evidence_path": str(evidence_path), "launch_id": launch_id},
                        owner,
                        started_wall,
                    )
                    for ordinal in phase["required_worker_ordinals"]
                ]
                if all(item is not None for item in workers):
                    target = next(
                        item
                        for item in workers
                        if item["ordinal"] == phase["worker_ordinal"]
                    )
                    records = [
                        parse_host_event(line)
                        for line in evidence_path.read_bytes().splitlines()
                        if line
                    ]
                    parents = [
                        r
                        for r in records
                        if r["event"] == "invoked"
                        and r["process"]["role"] == "api-server"
                        and r["process"].get("assignment_source") == "host"
                        and r["launch_id"] == launch_id
                        and r["plan_id"] == plan_id
                    ]
                    unique = {r["process"]["pid"] for r in parents}
                    require(
                        len(unique) <= 1,
                        "multiple API parents in this exact Host phase",
                    )
                    if parents:
                        parent = identity(parents[-1]["process"]["pid"]) | {
                            "launch_id": launch_id
                        }
                        worker_kernel = target["identity"] | {"launch_id": launch_id}
                        target_worker_ancestry = capture_parent_worker_ancestry(
                            parent, worker_kernel
                        )
                        sessions, descendants = owned_sessions(owner)
                        require(
                            parent["pid"] in descendants
                            and worker_kernel["pid"] in descendants,
                            "Host phase escaped owned adapter subtree",
                        )
                        owned.extend(sessions)
                        membership = [
                            {
                                "role": "api-server",
                                "ordinal": 0,
                                "identity": parent,
                                "event": parents[-1],
                            }
                        ]
                        for member in workers:
                            member_kernel = member["identity"] | {
                                "launch_id": launch_id
                            }
                            ancestry = capture_parent_worker_ancestry(
                                parent, member_kernel
                            )
                            membership.append(
                                {
                                    "role": "worker",
                                    "ordinal": member["ordinal"],
                                    "identity": member_kernel,
                                    "event": member["raw"],
                                    "parent_worker_ancestry": ancestry,
                                }
                            )
                        save_new(
                            output / f"phase{index}.actual-membership.json", membership
                        )
                        if phase.get("semantic_launch_spec"):
                            descriptor = evidence_path.stat()
                            if listener is not None:
                                handoff = {
                                    "record": bound,
                                    "raw": reference(
                                        output
                                        / f"phase{index}.handoff-unvalidated.json"
                                    ),
                                }
                            else:
                                handoff = {
                                    "origin": "host-baseline",
                                    "record": {
                                        "publisher": owner,
                                        "environment": environment,
                                    },
                                }
                            handoff["host_evidence"] = {
                                "path": str(evidence_path),
                                "identity": [
                                    descriptor.st_dev,
                                    descriptor.st_ino,
                                    descriptor.st_uid,
                                ],
                            }
                            save_new(
                                output / f"phase{index}.native-source-handoff.json",
                                handoff,
                            )
                        observed = {
                            "parent": parent,
                            "worker": worker_kernel,
                            "parent_event": parents[-1],
                            "worker_event": target["raw"],
                            "parent_worker_ancestry": target_worker_ancestry,
                            "owned_sessions": [s["pid"] for s in sessions],
                            "observed_ns": time.monotonic_ns(),
                            "route_generation": 0,
                        }
                        return process, owner, owned, observed
            time.sleep(0.02)
        raise TimeoutError("real Host process evidence readiness deadline")
    except Exception:
        if owner is not None:
            cleanup(process, owner, 10, owned)
        else:
            process.wait(timeout=10)
        raise
    finally:
        if listener is not None:
            listener.close()
            if socket_path.exists():
                socket_path.unlink()
