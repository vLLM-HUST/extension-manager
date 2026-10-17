"""Register, predict and independently score one H2 external-writer source case.

No Host, model, Kubernetes command or controller is started by these entrypoints.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from vllm_hust_ext.config import ExtensionConfig
from vllm_hust_ext.core import plan_dict, plan_for, status_for
from vllm_hust_ext.discovery import InstalledBundle
from vllm_hust_ext.manifest import load_manifest
from vllm_hust_ext.providers.replica_registration import (
    MODE,
    issue_registration,
    load_registered_case,
    read_ref,
    registered_scope,
    write_exclusive,
)
from vllm_hust_ext.providers.replica_writers import inspect_pinned_configuration


def derive(case):
    """Use actual core.status_for and core.plan_for through builtin provider_for."""
    case.validate_current()
    manifest_path = Path(case.request["provider_manifest"]["path"])
    manifest = load_manifest(manifest_path)
    bundle = InstalledBundle(
        bundle_id=manifest.bundle_id,
        distribution_name="registered-source:production-stack-provider",
        distribution_version=manifest.bundle_version,
        manifest_path=manifest_path,
        manifest=manifest,
        entry_points=(),
    )
    extension = ExtensionConfig(False, case.configuration)
    with registered_scope(case):
        # Normal production factory is used, with external entrypoints disabled
        # as in existing H2 source-corpus collectors. No monkeypatch/alternate SDK.
        status = status_for(bundle, extension, include_external_providers=False)
        plan = plan_for(bundle, extension, include_external_providers=False)
    outcomes = inspect_pinned_configuration(
        case.configuration, case.objects(), source_root=case.receipt["source_root"]
    )
    conflicts = [o for o in outcomes if o.decision == "conflict"]
    if conflicts and (
        "incompatible" not in status.as_dict()["states"]
        or not any(line.startswith(MODE + ":") for line in status.evidence)
    ):
        raise ValueError("SDK provider did not consume registered derived facts")
    return {
        "prediction": "reject" if conflicts else "unknown",
        "derived_outcomes": [
            {
                "decision": o.decision,
                "reason": o.reason,
                "target": list(o.target) if o.target else None,
                "owners": list(o.owners),
            }
            for o in outcomes
        ],
        "sdk_status": status.as_dict(),
        "sdk_plan": plan_dict(plan),
        "legacy_report_used": False,
        "non_conflict_is_not_general_admit": True,
    }


def predict(receipt_ref):
    case = load_registered_case(receipt_ref)
    destination = Path(case.request["prediction_path"])
    if destination.exists():
        raise ValueError("registered prediction destination is not fresh")
    started = time.monotonic_ns()
    derived = derive(case)
    case.validate_current()
    document = {
        "schema": "ecpa-H2-source-derived-writer-prediction/v1",
        "mode": MODE,
        "case_id": case.request["case_id"],
        "registration": receipt_ref,
        "request": case.receipt["request"],
        "oracle_freeze": case.receipt["oracle_freeze"],
        "oracle": case.receipt["oracle"],
        "protocol_sources": case.receipt["protocol_sources"],
        "registered_clock_ns": case.receipt["registered_clock_ns"],
        "prediction_started_ns": started,
        "prediction_finished_ns": time.monotonic_ns(),
        "derived": derived,
        "runtime_claim": False,
        "performance_claim": False,
    }
    write_exclusive(destination, document)
    return document


def score(prediction_ref):
    """Recompute the exact derived path; never score a legacy reporter rejection."""
    document = json.loads(read_ref(prediction_ref))
    case = load_registered_case(document["registration"])
    if (
        document.get("schema") != "ecpa-H2-source-derived-writer-prediction/v1"
        or document.get("mode") != MODE
        or document["case_id"] != case.request["case_id"]
        or prediction_ref["path"] != case.request["prediction_path"]
        or document["request"] != case.receipt["request"]
        or document["oracle_freeze"] != case.receipt["oracle_freeze"]
        or document["oracle"] != case.receipt["oracle"]
        or document["protocol_sources"] != case.receipt["protocol_sources"]
        or document["runtime_claim"] is not False
        or document["performance_claim"] is not False
    ):
        raise ValueError("prediction provenance/domain mismatch")
    clocks = [
        document[k]
        for k in (
            "registered_clock_ns",
            "prediction_started_ns",
            "prediction_finished_ns",
        )
    ]
    if (
        any(type(c) is not int for c in clocks)
        or clocks[0] != case.receipt["registered_clock_ns"]
        or not 0 < clocks[0] <= clocks[1] <= clocks[2] <= time.monotonic_ns()
    ):
        raise ValueError("registration/prediction clock ordering mismatch")
    derived = derive(case)
    if json.dumps(document["derived"], sort_keys=True) != json.dumps(
        derived, sort_keys=True
    ):
        raise ValueError("derived path does not reproduce original SDK prediction")
    oracle = json.loads(read_ref(case.receipt["oracle"]))
    if oracle.get("case_id") != case.request["case_id"] or oracle.get(
        "verdict"
    ) not in {"admit", "reject"}:
        raise ValueError("independent oracle does not give a definitive case label")
    return {
        "case_id": case.request["case_id"],
        "mode": MODE,
        "prediction": derived["prediction"],
        "oracle_decision": oracle["verdict"],
        "score_eligible": derived["prediction"] in {"admit", "reject"},
        "matched": derived["prediction"] == oracle["verdict"],
        "runtime_claim": False,
        "performance_claim": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    register = sub.add_parser("register")
    register.add_argument("--request", required=True)
    register.add_argument("--request-sha256", required=True)
    register.add_argument("--oracle-freeze", required=True)
    register.add_argument("--oracle-freeze-sha256", required=True)
    register.add_argument("--source-root", required=True)
    register.add_argument("--output", required=True)
    for command, key in (("predict", "receipt"), ("score", "prediction")):
        child = sub.add_parser(command)
        child.add_argument("--" + key, required=True)
        child.add_argument("--sha256", required=True)
    args = parser.parse_args()
    if args.command == "register":
        result = issue_registration(
            {"path": args.request, "sha256": args.request_sha256},
            {"path": args.oracle_freeze, "sha256": args.oracle_freeze_sha256},
            args.source_root,
            args.output,
        )
    elif args.command == "predict":
        result = predict({"path": args.receipt, "sha256": args.sha256})
    else:
        result = score({"path": args.prediction, "sha256": args.sha256})
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
