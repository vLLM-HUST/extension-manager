"""Query/close only the exact currently alive registered Manager-phase authority.

This does not signal, claim cleanup, or discover an actor from a filename glob.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from experiments.formal_campaign import h3_manager_phase_registration as registration
from experiments.formal_campaign.h3_manager_phase_runner import (
    ManagerRegisteredAuthority,
)
from experiments.formal_campaign.h3_owned_worker_carrier import (
    checked_reference,
    load,
    require,
)


def main():
    import json

    p = argparse.ArgumentParser(description=__doc__)
    for key in ("campaign", "receipt", "campaign-root"):
        p.add_argument("--" + key, type=Path, required=True)
    p.add_argument("operation", choices=("state", "close"))
    args = p.parse_args()
    spec = load(args.campaign)
    alive = []
    for start in spec["starts"]:
        recipe = load(checked_reference(start["recipe_template"]))
        output = Path(
            recipe["arms"][start["arm"]]["phases"][0]["native_bootstrap"]["output"]
        ).parent
        require(
            output.parent == args.campaign_root,
            "registered start escaped exact campaign root",
        )
        marker = output / "authority-popen.json"
        if not marker.exists():
            continue
        expected = load(marker)["kernel"]
        try:
            raw_stat = Path(f"/proc/{expected['pid']}/stat").read_text()
        except (FileNotFoundError, ProcessLookupError):
            continue
        fields = raw_stat.rsplit(")", 1)[1].split()
        current = dict(
            pid=int(raw_stat.split("(", 1)[0]),
            start_ticks=int(fields[19]),
            session=int(fields[3]),
            boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        )
        require(current == expected, "retained authority PID was reused")
        if fields[0] == "Z":
            continue
        alive.append((start, output))
    require(len(alive) == 1, "exactly one alive registered authority required")
    start, output = alive[0]
    capability = registration.validate_receipt_for_start(
        args.campaign, args.receipt, start["start_id"]
    )
    recipe = load(output / "actual-recipe.json")
    context, _, _ = capability.selected(start["start_id"])
    registration.validate_materialization(context, start, recipe)
    authority = ManagerRegisteredAuthority(recipe, capability, start["start_id"])
    state = authority.call("query")
    if args.operation == "close":
        authority.call("close_generation", expected_generation=state["generation"])
        state = authority.call("query")
    print(json.dumps(state, sort_keys=True))


if __name__ == "__main__":
    main()
