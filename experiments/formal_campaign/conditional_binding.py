"""Source-owned actual conditional Manager launch; no caller-selected native ID."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .conditional_common import checked, load, require


def host_command(base, bundles, configuration):
    from vllm_hust_ext.cli import (
        _activation_config,
        _merge_command_config,
        _merge_provider_plan,
    )
    from vllm_hust_ext.core import plan_for

    result = _merge_command_config(list(base), _activation_config(bundles))
    for bundle in bundles:
        result = _merge_provider_plan(
            result, plan_for(bundle, configuration.extension(bundle.bundle_id))
        )
    return result


def activation_command(phase_ref, phase):
    return [
        phase["python"],
        "-B",
        "-m",
        "experiments.formal_campaign.conditional_activation",
        "--phase",
        phase_ref["path"],
        "--phase-sha256",
        phase_ref["sha256"],
        "--",
        *phase["host_argv"],
    ]


def validate_launch_spec(path, bundles, actual_command):
    from vllm_hust_ext.config import load_config

    from .conditional_registration import validate_for_start
    from .h3_worker_relaunch import identity

    raw = Path(path).read_bytes()
    spec = json.loads(raw)
    require(
        spec["schema"] == "ecpa-h4-conditional-live-manager-launch/v1",
        "distinct actual conditional launch domain required",
    )
    parent = spec["actual_parent"]
    require(
        parent["pid"] == os.getppid() and identity(os.getppid()) == parent,
        "conditional launcher not actual original parent epoch",
    )
    command = Path(f"/proc/{parent['pid']}/cmdline").read_bytes().split(b"\0")
    require(
        b"experiments.formal_campaign.conditional_runtime" in command,
        "parent is not source-owned conditional runtime entry",
    )
    campaign, launch, workload, inputs, start, material = validate_for_start(
        spec["receipt"], spec["start_id"], fresh_source=False
    )
    phase = load(start["phase"])
    require(
        start["arm"] == "ecpa", "Manager cannot publish a baseline conditional epoch"
    )
    sdk = Path(inputs["repositories"]["manager"]["path"])
    require(
        checked(
            inputs["protocol_sources"][
                "experiments/formal_campaign/conditional_runtime.py"
            ]
        )
        == (sdk / "experiments/formal_campaign/conditional_runtime.py").read_bytes(),
        "parent runtime source changed",
    )
    require(
        spec["phase"] == start["phase"] and spec["plan"] == start["plan"],
        "conditional caller substituted registered Plan/phase",
    )
    configuration = load_config(Path(phase["manager_config"]["path"]))
    require(
        os.environ.get("VLLM_HUST_EXT_CONFIG") == phase["manager_config"]["path"],
        "actual Manager configuration differs",
    )
    expected = host_command(
        activation_command(start["phase"], phase), bundles, configuration
    )
    require(
        list(actual_command) == expected,
        "actual Manager rendering changed registered Host invocation",
    )
    require(
        raw == Path(path).read_bytes(),
        "conditional launch bytes changed across validation",
    )
    return dict(
        native_plan_id=material["plan_id"].rsplit(":", 1)[-1],
        execution_plan_id=material["plan_id"],
    )
