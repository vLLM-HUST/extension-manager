"""Write fresh actual-installed pair Plan inputs; never launch or install."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
from pathlib import Path

from vllm_hust_ext import semantic_runtime_binding as runtime
from vllm_hust_ext.discovery import discover_bundles
from vllm_hust_ext.plan_artifact import parse_plan_artifact, plan_artifact_bytes

from .binding import IDS, KV, compile_pair_plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kv-base-plan", type=Path, required=True)
    parser.add_argument("--kv-contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    base = parse_plan_artifact(args.kv_base_plan.read_bytes())
    contract = json.loads(args.kv_contract.read_bytes())
    bundles = discover_bundles(tuple(sorted(IDS)))
    # Source declaration in actual Host47 EngineCoreProc.__init__ calls
    # bind_process_identity('engine-core-scheduler', dp_rank) before loading.
    # Runtime authority must still observe this slot and its actual PID/epoch.
    slots = {"api-server": (0,), "engine-core-scheduler": (0,)}
    pair_base, plan, native, pair = compile_pair_plan(
        base, bundles, contract, profiler_slots=slots
    )
    output = args.output.resolve()
    output.mkdir(mode=0o700, exist_ok=False)
    output.chmod(0o700)

    def save(name, value):
        raw = (
            value
            if type(value) is bytes
            else json.dumps(
                value, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        )
        path = output / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        return path

    base_path = save("pair-base-plan.json", plan_artifact_bytes(pair_base))
    plan_path = save("pair-plan.json", plan_artifact_bytes(plan))
    binding_path = save("native-binding.json", native)
    kv_path = save("original-kv-contract.json", contract)
    profiler_path = save("profiler-loader-contract.json", pair["profiler_contract"])
    mapping = save("native-plugin-map.json", {KV: pair["plugin_identities"][KV]})
    launch = runtime.make_semantic_launch_spec(
        bundles,
        base_plan_path=base_path,
        plan_path=plan_path,
        binding_path=binding_path,
        contract_paths=(kv_path, profiler_path),
        plugin_map_path=mapping,
        controller_instance="controller:real-pair-" + secrets.token_hex(16),
        candidate_generation=1,
        membership_epoch=0,
    )
    launch_path = save("pair-launch-spec.json", launch)
    runtime.validate_semantic_launch_spec(launch_path, bundles)
    save("pair-binding.json", pair)
    protocol_path = (
        Path(__file__).resolve().parents[1] / "formal_campaign/protocol.json"
    )
    protocol_raw = protocol_path.read_bytes()
    protocol = json.loads(protocol_raw)
    cells = protocol["h4"]["required_cells"]
    schedule = protocol["schedule"]
    save(
        "h4-original-cohort.json",
        {
            "classification": (
                "original H4 schedule/thresholds retained; "
                "pair launch/workload not yet registered"
            ),
            "protocol": {
                "path": str(protocol_path),
                "sha256": hashlib.sha256(protocol_raw).hexdigest(),
            },
            "h4": protocol["h4"],
            "schedule": schedule,
            "pair_plan_id": plan.plan_id,
            "cells": [
                {
                    "cell_id": cell,
                    "planned_starts": [
                        {
                            "repetition": repetition,
                            "arm_order": order,
                            "arm": arm,
                        }
                        for repetition, row in enumerate(schedule, 1)
                        for order, arm in enumerate(row, 1)
                    ],
                }
                for cell in cells
            ],
            "formal_starts": 0,
            "performance_result": False,
            "formal_result": False,
            "remaining_registration": [
                (
                    "one matched actual model/workload/topology/version/"
                    "warm-state tuple for all three arms"
                ),
                "source-owned live native release carrier",
                "fresh original H4 deployment registration",
            ],
        },
    )
    save(
        "qualification-status.json",
        {
            "classification": "actual installed pair static Plan preparation only",
            "NPU_started": False,
            "formal_result": False,
            "runtime_observed": False,
            "public_route_authorized": False,
            "required_original_runtime_evidence": [
                "independently admitted full five-component source tuple",
                "original Manager handoff and exact source-owned Host kernel roster",
                "KV actual worker0/1 loader invoked and all-layer native completion",
                "profiler api-server/0 and engine-core-scheduler/0 loader invoked",
                (
                    "original Host effective/runtime_effective finished callback "
                    "with native consumer actual runtime request id"
                ),
                (
                    "original authority-owned lease/generation/membership/one-use "
                    "release and raw public200"
                ),
                "new formal matched original three-arm H4 cohort registration",
            ],
        },
    )
    print(
        json.dumps(
            {
                "output": str(output),
                "plan_id": plan.plan_id,
                "both_plugins": sorted(IDS),
                "runtime_observed": False,
                "formal_result": False,
            }
        )
    )


if __name__ == "__main__":
    main()
