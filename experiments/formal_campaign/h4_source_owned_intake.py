"""Independent H4 activation/resource intake for the explicit original scope."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from experiments.formal_campaign.h4_owned_resources import verify_archive


def checked(root, reference):
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
        raise ValueError("H4 source-owned artifact lacks strict reference")
    path = (root / reference["path"]).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("H4 source-owned artifact escapes run root or is absent")
    raw = path.read_bytes()
    if "sha256:" + hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        raise ValueError("H4 source-owned raw artifact digest differs")
    return path


def verify_cost_observation(raw, cost, launch, archive, expected_root, product):
    """Join excluded audit clocks and actual product timing to observed epochs."""
    if (
        cost["schema"] != "ecpa-h4-source-owned-cost-observation/v1"
        or launch["schema"] != "ecpa-h4-product-launch-timing/v1"
        or cost["clock"] != "CLOCK_MONOTONIC_RAW"
        or launch["clock"] != "CLOCK_MONOTONIC_RAW"
        or cost["phase_bins"] != "unobserved"
        or cost["measurement_scope"] != "actual-product-Popen-to-health200"
        or launch["wrapper_kernel"] != expected_root
        or launch["product_kernel"] != product
        or archive.get("measurement_root") != product
    ):
        raise ValueError("H4 cost scope or independently sampled product epoch differs")
    health = cost["health_observation"]
    begin, end = launch["product_popen_before_ns"], health["observed_ns"]
    clocks = (
        cost["wrapper_start_ns"],
        launch["qualification_begin_ns"],
        launch["qualification_end_ns"],
        begin,
        launch["product_popen_after_ns"],
        end,
    )
    if (
        any(type(t) is not int or t <= 0 for t in clocks)
        or tuple(sorted(clocks)) != clocks
        or launch["qualification_end_ns"] != begin
        or end <= begin
        or health["status_code"] != 200
        or (raw["startup_start_ns"], raw["ready_ns"]) != (begin, end)
        or any(value is not None for value in raw["startup_phases"].values())
    ):
        raise ValueError("H4 actual Popen/health timing or unobserved bins differ")
    phases = cost["common_qualification_phases"]
    order = ("discovery", "validation", "planning", "rendering", "evidence_setup")
    if set(phases) != set(order):
        raise ValueError("common qualification raw phases are incomplete")
    cursor = None
    for phase in order:
        interval = phases[phase]
        start, finish = interval["start_ns"], interval["end_ns"]
        if (
            type(start) is not int
            or type(finish) is not int
            or start < 0
            or finish < start
            or (cursor is not None and start != cursor)
        ):
            raise ValueError("common qualification raw phase clocks differ")
        cursor = finish
    if cursor != cost["wrapper_start_ns"]:
        raise ValueError("common qualification was included in product startup")
    return {
        "scope": cost["measurement_scope"],
        "phase_bins": "unobserved",
        "qualification_excluded": True,
    }


def verify_start(record, raw, artifact_root):
    """A failed attempt does not assert absent activation/resource evidence."""
    root = Path(artifact_root).resolve()
    from experiments.formal_campaign import source_provenance

    receipt = json.loads(
        checked(root, record["artifacts"]["deployment_receipt"]).read_bytes()
    )
    if not set(receipt.get("source_provenance_protocol_binding", {})).issuperset(
        source_provenance.H4_SOURCE_OWNED_FILES
    ):
        raise ValueError("H4 source-owned helpers are outside admitted source")
    snapshot = json.loads(
        checked(root, record["artifacts"]["process_snapshot"]).read_bytes()
    )
    if snapshot["process_identity"] != record["process_identity"]:
        raise ValueError("H4 source-owned observer root differs")
    claim = snapshot.get("source_owned_pair")
    if not isinstance(claim, dict) or set(claim) != {
        "resources",
        "activation",
        "cost_observation",
    }:
        raise ValueError("H4 source-owned raw archive declaration absent")
    complete = record["status"] == "complete"
    paths = {}
    for name, reference in claim.items():
        if reference is None:
            if complete:
                raise ValueError("complete H4 start lacks source-owned raw evidence")
        else:
            paths[name] = checked(root, reference)
    if not complete:
        return {
            "activation_verified": False,
            "resource_coverage": "unverified-failed-start",
        }
    identity = record["process_identity"]
    expected = {
        "pid": identity["server_pid"],
        "start_ticks": identity["server_start_ticks"],
        "session": identity["server_pid"],
        "boot_id": identity["boot_id"],
    }
    values = {
        key: raw["resources"][key]
        for key in ("cpu_ms", "peak_host_rss_bytes", "peak_device_memory_bytes")
    }
    archive = verify_archive(paths["resources"], expected, values)
    if archive["device_coverage"] != "observed":
        raise ValueError("complete H4 resource study lacks actual device observation")
    from experiments.formal_campaign.h4_pair_activation import (
        verify_archived_activation,
    )

    run_dir = root / record["start_id"]
    if (
        paths["activation"]
        != (run_dir / "activation" / "activation-guard-receipt.json").resolve()
    ):
        raise ValueError("H4 activation receipt belongs to another start")
    result = verify_archived_activation(
        run_dir, raw["launch_definition"], expected, resource_archive=paths["resources"]
    )
    ready = json.loads((run_dir / "activation" / "activation-ready.json").read_bytes())
    product = (
        ready["actual_manager"] if ready["arm"] == "ecpa" else ready["actual_host"]
    )
    cost = json.loads(paths["cost_observation"].read_bytes())
    launch_path = checked(root, cost["product_launch"])
    if (
        launch_path
        != (run_dir / "activation" / "actual-product-launch-timing.json").resolve()
    ):
        raise ValueError("H4 product timing belongs to another start")
    launch = json.loads(launch_path.read_bytes())
    intent = json.loads(
        (run_dir / "activation" / "actual-launch-intent.json").read_bytes()
    )
    if launch["argv"] != intent["argv"]:
        raise ValueError("product cost timing command differs from actual Popen")
    spec = json.loads((run_dir / "activation" / "spec.json").read_bytes())
    if cost["health_observation"]["url"] != spec["health_url"]:
        raise ValueError(
            "product readiness endpoint differs from registered configuration"
        )
    timing = verify_cost_observation(raw, cost, launch, archive, expected, product)
    return {
        "cost_observation": timing,
        "activation_verified": True,
        "resource_coverage": "complete",
        "activation": result,
    }
