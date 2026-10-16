"""Exact original H3 cell dispatch shared by issuer, runner and raw intake.

A cell name is not an implementation. No unsupported cell falls through to a
Manager SIGKILL/prepare experiment.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PREPARE = {"manager-crash-after-prepare"}
WORKER = {"worker-crash", "worker-replacement"}
REJECTION = {
    "unsupported-plugin-below-range",
    "unsupported-plugin-above-range",
    "unsupported-api-protocol-capability",
}


def cell_policy(cell_id: str) -> str:
    original = json.loads((HERE / "protocol.json").read_text())["h3"]["required_cells"]
    if cell_id not in original:
        raise ValueError("H3 cell is absent from the frozen original matrix")
    if cell_id in PREPARE:
        return "native-prepare"
    if cell_id in WORKER:
        return "worker-recovery"
    if cell_id in REJECTION:
        return "pre-serving-rejection"
    return "unimplemented-actuator"


def validate_cell_execution(
    campaign: dict, *, arm: str | None = None, launching: bool = False
) -> str:
    policy = cell_policy(campaign["cell_id"])
    if policy == "worker-recovery":
        from experiments.formal_campaign.h3_worker_recovery import validate_carrier

        validate_carrier(campaign, check_sources=launching)
    elif policy != "native-prepare":
        # A rejection actuator needs a distinct pre-serving oracle. It must not
        # reuse the current crash raw format or invent a signal/fault marker.
        raise ValueError(
            f"H3 {policy}: no registered source-owned carrier for {campaign['cell_id']}"
        )
    if launching and policy == "native-prepare":
        definition = next(a for a in campaign["arms"] if a["id"] == arm)
        phase = definition.get("phase_barrier")
        if not phase or phase["support"] != "supported":
            raise ValueError(
                "arm lacks its own durable prepare protocol; no launch or fault"
            )
        if arm != "ecpa":
            raise ValueError("baseline lacks an independent native prepare protocol")
    return policy


def validate_raw_kind(campaign: dict, raw: dict) -> str:
    policy = cell_policy(campaign["cell_id"])
    expected = {
        "native-prepare": "ecpa-h3-raw-recovery/v2",
        "worker-recovery": "ecpa-h3-worker-raw-recovery/v1",
    }.get(policy)
    if expected is None or raw.get("schema") != expected:
        raise ValueError(
            f"H3 {policy} requires its own registered raw carrier; "
            "legacy prepare evidence is inapplicable"
        )
    return policy
