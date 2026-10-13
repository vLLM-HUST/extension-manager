"""Prepare a registration-bound proxy authorization after process freeze."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from experiments.exposure_gate.loopback_traffic import frozen_target_set_sha256
from vllm_hust_ext.formal_proxy_membership import derive_formal_proxy_membership

SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def prepare_formal_proxy_authorization(
    output: Path,
    *,
    plan_path: Path,
    event_dir: Path,
    event_directory_identity: tuple[int, int],
    process_transition: dict[str, Any],
    required_processes: list[dict[str, Any]],
    bindings: list[dict[str, str]],
    registration: dict[str, str],
    candidate_generation: int = 1,
) -> dict[str, Any]:
    """Write the exact input consumed by a separately launched proxy.

    This is intentionally unavailable before the runner has frozen real host
    process epochs.  Missing parent/engine/worker roles, an unregistered proxy,
    or a reused output path aborts preparation.
    """
    if (
        not plan_path.is_absolute()
        or not plan_path.is_file()
        or plan_path.is_symlink()
        or not event_dir.is_absolute()
        or event_dir.is_symlink()
    ):
        raise ValueError("formal proxy paths must be existing absolute real paths")
    metadata = event_dir.stat()
    if (metadata.st_dev, metadata.st_ino) != event_directory_identity:
        raise ValueError("formal proxy host journal directory identity changed")
    if (
        isinstance(candidate_generation, bool)
        or not isinstance(candidate_generation, int)
        or candidate_generation < 1
    ):
        raise ValueError("formal proxy candidate generation is invalid")
    registration_fields = {
        "schema",
        "evidence_class",
        "authority",
        "proxy_command_digest",
        "review_receipt_sha256",
        "reviewer_kind",
    }
    if (
        not isinstance(registration, dict)
        or set(registration) != registration_fields
        or registration["schema"] != "ecpa-formal-proxy-registration/v1"
        or registration["evidence_class"] != "formal-real"
        or registration["authority"] != "independent-loopback-proxy"
        or registration["reviewer_kind"] != "automated-independent"
        or SHA256.fullmatch(str(registration["proxy_command_digest"])) is None
        or SHA256.fullmatch(str(registration["review_receipt_sha256"])) is None
    ):
        raise ValueError("formal proxy registration is invalid")
    execution = process_transition.get("execution_identity")
    if not isinstance(execution, dict):
        raise ValueError("formal proxy execution identity is missing")
    members = derive_formal_proxy_membership(process_transition)
    hosts = {row["host"] for row in members}
    if len(hosts) != 1:
        raise ValueError("formal proxy currently requires one host")
    target_set_sha256 = frozen_target_set_sha256(required_processes)
    membership_sha256 = (
        "sha256:"
        + hashlib.sha256(_canonical({"process_membership": members})).hexdigest()
    )
    registration_sha256 = (
        "sha256:" + hashlib.sha256(_canonical(registration)).hexdigest()
    )
    value = {
        "schema": "ecpa-loopback-formal-host-authorization/v1",
        "plan_path": str(plan_path),
        "journal_dir": str(event_dir),
        "journal_device": metadata.st_dev,
        "journal_inode": metadata.st_ino,
        "launch_id": execution["launch_id"],
        "controller_instance": execution["controller_instance"],
        "candidate_generation": candidate_generation,
        "membership_epoch": process_transition["frozen_at_ns"],
        "target_set_sha256": target_set_sha256,
        "process_membership": members,
        "process_membership_sha256": membership_sha256,
        "registration": registration,
        "registration_sha256": registration_sha256,
        "local_host": next(iter(hosts)),
        "bindings": bindings,
        "required_processes": required_processes,
    }
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        payload = _canonical(value) + b"\n"
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    return value
