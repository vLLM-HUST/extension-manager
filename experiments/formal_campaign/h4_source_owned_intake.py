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
    if not isinstance(claim, dict) or set(claim) != {"resources", "activation"}:
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
    return {
        "activation_verified": True,
        "resource_coverage": "complete",
        "activation": result,
    }
