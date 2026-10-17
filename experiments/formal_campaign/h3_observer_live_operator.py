"""Explicit original-arm operator process; actual invocation is always charged."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

from experiments.formal_campaign.h3_dynamic_authority import require
from experiments.formal_campaign.h3_observer_live_launcher import write_private
from experiments.formal_campaign.h3_observer_live_registration import validate_for_start


def invoke(scope, args, recipe, registration, output):
    declaration = scope.value()["declaration"]
    command = declaration["operator"]["command"]
    fault = json.loads((output / "runner-fault.json").read_bytes())
    deadline = fault["triggered_ns"] + 30_000_000_000
    require(
        time.monotonic_ns() < deadline,
        "original30s bound expired before explicit operator action",
    )
    started = time.monotonic_ns()
    with (
        (output / "live-operator.stdout").open("xb") as stdout,
        (output / "live-operator.stderr").open("xb") as stderr,
    ):
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr
        )
        from experiments.formal_campaign.h3_worker_relaunch import identity

        kernel = None
        kernel_error = None
        try:
            kernel = identity(process.pid)
        except (OSError, ValueError) as error:
            kernel_error = type(error).__name__ + ": " + str(error)
        action = dict(
            schema="ecpa-h3-actual-explicit-operator-action/v2",
            start_id=scope.value()["start"]["start_id"],
            command=command,
            operator_pid=process.pid,
            operator_kernel=kernel,
            kernel_observation_error=kernel_error,
            started_ns=started,
            original_deadline_ns=deadline,
            operator_actions=1,
            formal_result=False,
        )
        # Durable before waiting: an action is charged even if it times out/fails.
        write_private(output / "live-operator-action.json", action)
        returncode = process.wait(
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
    path = output / "live-operator-result.json"
    result = json.loads(path.read_bytes())
    require(
        result["start_id"] == scope.value()["start"]["start_id"]
        and result["formal_result"] is False,
        "operator result belongs to another original start",
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
    fault = json.loads((args.output.parent / "runner-fault.json").read_bytes())
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
