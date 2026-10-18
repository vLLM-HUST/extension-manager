"""Distinct original Manager-after-launch registration; never worker-cell admission.

All nine original declarations, five repositories, real runtime/wheels, both
native Plans and all workload/source guards are independently checked. The two
baselines are explicitly unsupported actors, not invented Manager processes.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from experiments.formal_campaign import h3_dynamic_registration as common
from experiments.formal_campaign import h3_native_registration as native
from experiments.formal_campaign.h3_dynamic_authority import canonical, require
from experiments.formal_campaign.h3_manager_after_launch import ENV

DOMAIN = "ecpa-h3-manager-phase-campaign/v1"
RECEIPT = "ecpa-h3-manager-phase-deployment-receipt/v1"
CAMPAIGN_SCHEMA = "h3-manager-phase-campaign.schema.json"
AUTHORITY_SOURCE = "h3_manager_phase_authority.py"
FAULT_ROLE = "manager"
PROTOCOL_FILES = native.PROTOCOL_FILES + (
    "h3_manager_after_launch.py",
    "h3_manager_phase_registration.py",
    "h3_manager_phase_authority.py",
    "h3_manager_phase_runner.py",
    "h3_manager_phase_delivery.py",
    "h3_manager_phase_intake.py",
    "h3_manager_phase_cleanup.py",
    "h3_manager_phase_nine.py",
    "h3_manager_phase_control.py",
    CAMPAIGN_SCHEMA,
)
EXTERNAL_PROTOCOL_FILES = native.EXTERNAL_PROTOCOL_FILES
validate_policy = native.validate_policy
installed_payloads = native.installed_payloads
source_artifacts = native.source_artifacts
verify_contract_source = native.verify_contract_source
verify_native_plans = native.verify_native_plans
build_plan_guards = native.build_plan_guards
validate_receipt_destination = native.validate_receipt_destination
authority_arguments = native.authority_arguments
materialize_recipe = common.materialize_recipe
validate_materialization = common.validate_materialization
_SCOPES = {}


def validate_original_cell(original):
    require(
        original["cell_id"] == "manager-crash-after-launch"
        and original["fault"]["target_role"] == "manager"
        and original["fault"]["signal"] == "SIGKILL"
        and original["objective"]["max_recovery_ms"] == 30000,
        "this domain supports only the original Manager after-launch cell/30s",
    )


def validate_start(spec, original, start, recipe, policy):
    native.validate_start(spec, original, start, recipe, policy)
    phases = recipe["arms"][start["arm"]]["phases"]
    require(
        all(
            "--max-num-seqs" in p["argv"]
            and p["argv"][p["argv"].index("--max-num-seqs") + 1] == "1"
            for p in phases
        ),
        "original max-num-seqs1 must not change",
    )
    if start["arm"] != "ecpa":
        require(
            start["manager_phase_support"] == "unsupported-no-manager"
            and all(ENV not in p["environment"] for p in phases),
            "baseline has no real Manager phase actor",
        )
        return
    require(
        start["manager_phase_support"] == "actual-manager-after-launch"
        and ENV in phases[0]["environment"]
        and ENV not in phases[1]["environment"],
        "only original initial Manager launch has the phase barrier",
    )
    path = Path(phases[0]["environment"][ENV])
    output = Path(phases[0]["native_bootstrap"]["output"]).parent
    require(
        path.is_absolute()
        and path.resolve() == path
        and path.name == "declaration.json"
        and path.is_relative_to(output)
        and len(os.fsencode(path.parent / "phase.sock")) < 108,
        "registered root barrier must stay inside actual start output",
    )
    import hashlib

    from vllm_hust_ext import process_supervisor

    supervisor = Path(process_supervisor.__file__).resolve()
    actual_digest = hashlib.sha256(supervisor.read_bytes()).hexdigest()
    declared_guard = native.load(native.checked_reference(phases[0]["native_guard"]))
    require(
        declared_guard["source_arguments"]["native_sources"]
        .get(str(supervisor), "")
        .removeprefix("sha256:")
        == actual_digest,
        "actual installed Manager barrier absent from fresh native source/input audit",
    )
    require(
        any(
            r["path"].endswith("/vllm_hust_ext/process_supervisor.py")
            for r in policy["source_refs"]
        ),
        "source-owned actual Manager supervisor absent from source admission",
    )


def extra_fresh_paths(start, recipe):
    paths = native.extra_fresh_paths(start, recipe)
    if start["arm"] == "ecpa":
        path = Path(recipe["arms"]["ecpa"]["phases"][0]["environment"][ENV])
        paths += [str(path), str(path.parent / "phase.sock")]
    return paths


class ManagerStart:
    """Private owner-process capability for exactly one independently fresh start."""

    __slots__ = ()

    def _value(self, start_id):
        require(
            type(self) is ManagerStart and self in _SCOPES,
            "Manager start capability was not independently issued",
        )
        pid, raw = _SCOPES[self]
        value = json.loads(raw)
        require(
            pid == os.getpid() and value["start_id"] == start_id,
            "Manager start capability cannot change start or cross fork",
        )
        return value

    def selected(self, start_id):
        v = self._value(start_id)
        return v["context"], v["original"], v["start"]

    def authority_binding(self, start_id):
        return self._value(start_id)["authority_binding"]

    def guard_receipt(self, start_id):
        return {"source_observation": self._value(start_id)["source_observation"]}


def validate_campaign(spec, *, spec_path):
    return common._validate_campaign(
        spec, profile=sys.modules[__name__], spec_path=spec_path
    )


def issue(spec_path, output):
    return common._issue(spec_path, output, profile=sys.modules[__name__])


def validate_receipt_for_start(
    spec_path, receipt_path, start_id, *, check_remote=False
):
    spec, original, receipt = common._validate_receipt(
        spec_path,
        receipt_path,
        profile=sys.modules[__name__],
        check_remote=check_remote,
        _selected_start_id=start_id,
    )
    start = next(s for s in spec["starts"] if s["start_id"] == start_id)
    row = next(s for s in receipt["starts"] if s["start_id"] == start_id)
    value = dict(
        start_id=start_id,
        start=start,
        original=original,
        context={k: v for k, v in spec.items() if k != "starts"},
        authority_binding=row,
        source_observation=receipt["source_observation"],
    )
    token = ManagerStart()
    _SCOPES[token] = (os.getpid(), canonical(value))
    return token


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    issue(args.campaign, args.output)


if __name__ == "__main__":
    main()
