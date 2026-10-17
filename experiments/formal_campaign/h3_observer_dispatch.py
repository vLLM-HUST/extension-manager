"""Dedicated observer-loss issuer and original Latin-nine dispatcher.

No fallback to a worker receipt, worker fault, fake recovery or narrower window.
Only fresh source-registered original observer-loss packets may execute.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from experiments.formal_campaign import h3_observer_registration as registration
from experiments.formal_campaign.h3_dynamic_authority import require
from experiments.formal_campaign.h3_owned_worker_carrier import save_new


def run_nine(campaign, receipt, output):
    # Full independent source/runtime/Plan validation precedes the first launch.
    spec, original, _ = registration.validate_receipt(
        campaign, receipt, check_remote=True
    )
    require(original["cell_id"] == "observer-loss", "wrong original H3 cell")
    protocol = json.loads((Path(__file__).parent / "protocol.json").read_bytes())
    ordered = []
    for repetition, arms in enumerate(protocol["schedule"], 1):
        for order, arm in enumerate(arms, 1):
            found = [
                s
                for s in spec["starts"]
                if s["repetition"] == repetition
                and s["arm"] == arm
                and s["arm_order"] == order
            ]
            require(len(found) == 1, "original Latin-nine slot missing")
            ordered.append(found[0])
    output = Path(output).resolve()
    require(
        not output.exists(),
        "original nine output must be fresh; no retry/resume overwrite",
    )
    from experiments.formal_campaign.h3_observer_paths import create_private_directory

    create_private_directory(output, parents=True)
    rows = []
    from experiments.formal_campaign.h3_observer_runner import execute

    for start in ordered:
        recipe = json.loads(
            registration.checked_reference(start["recipe_template"]).read_bytes()
        )
        start_output = Path(
            recipe["arms"][start["arm"]]["phases"][0]["native_bootstrap"]["output"]
        ).parent
        require(
            start_output.is_relative_to(output),
            "registered original start output outside private packet",
        )
        result = execute(
            Path(campaign),
            Path(receipt),
            start["start_id"],
            start_output,
            native=True,
            check_remote=True,
        )
        rows.append({"start_id": start["start_id"], "result": result})
        save_new(output / f"slot-{len(rows):02d}.json", rows[-1])
        # Qualified failed objectives remain rows and do not induce retries.
        # Missing source admission or unsafe cleanup stops subsequent launches.
        cleanup = result.get("cleanup", {}) if result is not None else {}
        cleanup_ok = set(cleanup) == {
            "processes_reclaimed",
            "ports_reclaimed",
            "devices_reclaimed",
            "external_services_preserved",
        } and all(value is True for value in cleanup.values())
        if (
            result is None
            or not result.get("formal_start_validated")
            or not cleanup_ok
            or result.get("cleanup_errors")
        ):
            save_new(
                output / "terminal.json",
                {
                    "rows": rows,
                    "completed_slots": len(rows),
                    "original_slots": 9,
                    "retry_count": 0,
                    "status": "stopped-unverified-or-unclean",
                },
            )
            return rows
    save_new(
        output / "terminal.json",
        {
            "rows": rows,
            "completed_slots": 9,
            "original_slots": 9,
            "retry_count": 0,
            "status": "source-observed-original-nine",
        },
    )
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("issue", "run-nine"))
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.operation == "issue":
        registration.issue(args.campaign, args.receipt)
    else:
        require(args.output is not None, "fresh original nine output required")
        run_nine(args.campaign, args.receipt, args.output)


if __name__ == "__main__":
    main()
