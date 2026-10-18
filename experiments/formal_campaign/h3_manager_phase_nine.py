"""Distinct original Latin-nine Manager-phase queue; no retries or fake baselines."""

from __future__ import annotations

import argparse
from pathlib import Path

from experiments.formal_campaign import h3_manager_phase_registration as registration
from experiments.formal_campaign.h3_manager_phase_intake import observe
from experiments.formal_campaign.h3_manager_phase_runner import _save, execute
from experiments.formal_campaign.h3_owned_worker_carrier import (
    checked_reference,
    load,
    require,
)


def run(spec_path, receipt_path, log_root):
    log_root = Path(log_root)
    log_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    receipt_path = Path(receipt_path)
    require(
        not receipt_path.exists(), "first full issuer must produce a fresh receipt once"
    )
    registration.issue(spec_path, receipt_path)
    spec = load(spec_path)
    starts = sorted(spec["starts"], key=lambda s: (s["repetition"], s["arm_order"]))
    require(len(starts) == 9, "retain all original Latin-nine declarations")
    results = []
    for index, start in enumerate(starts, 1):
        recipe = load(checked_reference(start["recipe_template"]))
        output = Path(
            recipe["arms"][start["arm"]]["phases"][0]["native_bootstrap"]["output"]
        ).parent
        rc = execute(spec_path, receipt_path, start["start_id"], output)
        # rc0 alone never admits a row; exact source/raw/native/cleanup replay
        # decides whether there was an authenticated actual Manager phase fault.
        row = observe(spec_path, receipt_path, start["start_id"], output)
        _save(
            log_root / f"{index:02d}-{start['start_id']}.json",
            dict(returncode=rc, result=row),
        )
        results.append(row)
        if row.get("formal_start_validated"):
            if not all(row["cleanup"].values()) or row["cleanup_errors"]:
                raise RuntimeError("actual cleanup failure; original queue stops")
        else:
            require(
                start["manager_phase_support"] == "unsupported-no-manager"
                and row["start_validation"] == "unsupported-no-manager"
                and rc == 2,
                "unqualified non-baseline start cannot continue original queue",
            )
    result = dict(
        schema="ecpa-h3-manager-phase-nine-observation/v1",
        required_starts=9,
        declarations_seen=len(results),
        actual_source_admitted=sum(
            r.get("formal_start_validated") is True for r in results
        ),
        unsupported_baseline_slots=[
            r["start_id"]
            for r in results
            if r["start_validation"] == "unsupported-no-manager"
        ],
        objective_passes=sum(r.get("objective_met") is True for r in results),
        campaign_complete=all(r.get("formal_start_validated") is True for r in results),
        full_original225_complete=False,
        results=results,
    )
    _save(log_root / "terminal.json", result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("campaign", "receipt", "log-root"):
        p.add_argument("--" + key, type=Path, required=True)
    a = p.parse_args()
    run(a.campaign, a.receipt, a.log_root)


if __name__ == "__main__":
    main()
