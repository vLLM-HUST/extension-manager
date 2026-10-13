"""Prepare a registration-bound proxy authorization after process freeze."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

try:
    from experiments.exposure_gate.loopback_traffic import frozen_target_set_sha256
except ModuleNotFoundError:  # Direct execution from this experiment directory.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "exposure_gate"))
    from loopback_traffic import frozen_target_set_sha256  # noqa: E402
from vllm_hust_ext.formal_proxy_membership import derive_formal_proxy_membership

SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
HERE = Path(__file__).resolve().parent
PUBLIC_PORT = 8187
REGISTRATION_FIELDS = {
    "schema",
    "evidence_class",
    "authority",
    "proxy_command_digest",
    "proxy_source_sha256",
    "review_receipt_sha256",
    "reviewer_kind",
    "public_port",
    "backend_port",
    "predecessor_port",
    "grant_holder",
    "grant_token",
    "grant_expires_at",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def validate_formal_proxy_registration(value: Any) -> dict[str, Any]:
    """Validate the independently reviewed, exact authority launch contract."""
    if (
        not isinstance(value, dict)
        or set(value) != REGISTRATION_FIELDS
        or value.get("schema") != "ecpa-formal-proxy-registration/v1"
        or value.get("evidence_class") != "formal-real"
        or value.get("authority") != "independent-loopback-proxy"
        or value.get("reviewer_kind") != "automated-independent"
        or any(
            SHA256.fullmatch(str(value.get(field))) is None
            for field in (
                "proxy_command_digest",
                "proxy_source_sha256",
                "review_receipt_sha256",
            )
        )
        or value.get("public_port") != PUBLIC_PORT
        or any(
            isinstance(value.get(field), bool)
            or not isinstance(value.get(field), int)
            or not 1 <= value[field] <= 65535
            for field in ("backend_port", "predecessor_port")
        )
        or len(
            {
                value.get("public_port"),
                value.get("backend_port"),
                value.get("predecessor_port"),
            }
        )
        != 3
        or not isinstance(value.get("grant_holder"), str)
        or not value["grant_holder"]
        or value["grant_holder"].strip() != value["grant_holder"]
        or any(
            isinstance(value.get(field), bool)
            or not isinstance(value.get(field), int)
            or value[field] < 1
            for field in ("grant_token", "grant_expires_at")
        )
    ):
        raise ValueError("formal proxy registration is invalid")
    return dict(value)


def formal_proxy_source_sha256() -> str:
    """Digest the exact independently launched authority implementation."""
    source = (HERE / "../exposure_gate/loopback_traffic.py").resolve()
    return "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()


def formal_proxy_command_material(
    run_dir: Path, registration: dict[str, Any]
) -> dict[str, Any]:
    """Return exact argv and digest for review before registration issuance."""
    registration = validate_formal_proxy_registration(registration)
    if not run_dir.is_absolute():
        raise ValueError("formal proxy run directory must be absolute")
    source = (HERE / "../exposure_gate/loopback_traffic.py").resolve()
    source_digest = formal_proxy_source_sha256()
    if registration["proxy_source_sha256"] != source_digest:
        raise ValueError("formal proxy source differs from registration")
    command = [
        str(Path(sys.executable).resolve()),
        str(source),
        "--socket",
        str(run_dir / "authority.sock"),
        "--journal",
        str(run_dir / "authority-journal.jsonl"),
        "--listen-port",
        str(registration["public_port"]),
        "--predecessor-port",
        str(registration["predecessor_port"]),
        "--candidate-port",
        str(registration["backend_port"]),
        "--predecessor-snapshot",
        '{"generation":0}',
        "--grant-holder",
        registration["grant_holder"],
        "--grant-token",
        str(registration["grant_token"]),
        "--grant-expires-at",
        str(registration["grant_expires_at"]),
        "--observer-config",
        str(run_dir / "formal-proxy-authorization.json"),
    ]
    return {
        "argv": command,
        "digest": "sha256:"
        + hashlib.sha256(_canonical({"argv": command})).hexdigest(),
        "source_sha256": source_digest,
    }


def formal_proxy_command(run_dir: Path, registration: dict[str, Any]) -> list[str]:
    """Build the deterministic command whose digest must be preregistered."""
    material = formal_proxy_command_material(run_dir, registration)
    if material["digest"] != registration["proxy_command_digest"]:
        raise ValueError("formal proxy command differs from registration")
    return list(material["argv"])


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
    registration = validate_formal_proxy_registration(registration)
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
        "authorization_path": str(output),
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
