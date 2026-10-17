"""Explicit v2 source publication/runner entry; never promotes old-domain intake."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from experiments.formal_campaign import h3_observer_live_registration as registration
from experiments.formal_campaign.h3_dynamic_authority import require
from experiments.formal_campaign.h3_observer_live_launcher import write_private


def run_nine(intent_path, receipt_path):
    intent = json.loads(Path(intent_path).read_bytes())
    rows = []
    from experiments.formal_campaign.h3_observer_runner import execute

    for declaration in intent["starts"]:
        scope = registration.validate_for_start(
            intent_path, receipt_path, declaration["start_id"], check_remote=True
        )
        value = scope.value()
        output = Path(declaration["grant_directory"]).parent
        result = execute(
            value["base_campaign"]["path"],
            value["base_receipt"]["path"],
            declaration["start_id"],
            output,
            native=True,
            check_remote=True,
            live_intent=intent_path,
            live_receipt=receipt_path,
        )
        rows.append({"start_id": declaration["start_id"], "result": result})
        # No retry or qualification by control success. Only independently
        # source-admitted actual faults with exact current-run cleanup permit
        # the next original Latin slot; objective failure is retained as failure.
        cleanup = result.get("cleanup", {}) if result is not None else {}
        clean = set(cleanup) == {
            "processes_reclaimed",
            "ports_reclaimed",
            "devices_reclaimed",
            "external_services_preserved",
        }
        clean = clean and all(value is True for value in cleanup.values())
        if (
            result is None
            or not result.get("formal_start_validated")
            or not clean
            or result.get("cleanup_errors")
        ):
            return rows
    require(len(rows) == 9, "original Latin nine schedule incomplete")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("issue", "run-nine"))
    parser.add_argument("--intent", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.operation == "issue":
        registration.issue(args.intent, args.receipt)
    else:
        require(args.output is not None, "fresh outcome path required")
        write_private(
            args.output,
            {
                "rows": run_nine(args.intent, args.receipt),
                "formal_result": False,
                "retry_count": 0,
            },
        )


if __name__ == "__main__":
    main()
