"""Local CPU-review candidate, never a registered semantic admission producer.

Only observes host request/block-table metadata after the synchronous model
barrier. It does not observe GPU table upload, tensor contents or model quality.
Copying this file to Host and applying the pinned hook still requires a newly
frozen wheel/source registration and real qualification; the formal gate stays
closed. Sink success means the configured writer reports durable raw bytes.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "ecpa-worker-host-blocktable-projection/v1"
OPERATION = "worker-host-blocktable-projection-applied"
SCOPE_FIELDS = {
    "plan_id",
    "launch_id",
    "controller_instance",
    "candidate_generation",
    "membership_epoch",
    "source_provider_sha256",
    "source_host_sha256",
}


@dataclass(frozen=True)
class PublicationAck:
    """Local writer ACK after file+directory fsync, not formal source authority."""

    raw_sha256: str
    filename: str
    directory_device: int
    directory_inode: int
    source_pid: int


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def current_process(host_scope: dict) -> dict:
    process = host_scope["process"]
    pid = os.getpid()
    raw = Path(f"/proc/{pid}/stat").read_bytes()
    ticks = int(raw[raw.rfind(b")") + 2 :].split()[19])
    if (
        process.get("assignment_source") != "host"
        or process.get("role") != "worker"
        or process.get("pid") != pid
        or process.get("start_identity") != f"pid:{pid}:start_ticks:{ticks}"
    ):
        raise ValueError("semantic producer requires current Host-assigned worker")
    return process | {
        "start_ticks": ticks,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }


def projection_receipt(
    provider: Any,
    scheduler_output: Any,
    request_id: str,
    pending: Any,
    scope: dict,
    host_scope: dict,
) -> dict:
    if set(scope) != SCOPE_FIELDS or any(
        value in (None, "") for value in scope.values()
    ):
        raise ValueError("semantic scope is incomplete")
    if host_scope.get("binding_status") != "bound" or any(
        host_scope.get(k) != scope[k] for k in ("plan_id", "launch_id")
    ):
        raise ValueError("semantic scope differs from Host launch")
    for name in ("candidate_generation", "membership_epoch"):
        if type(scope[name]) is not int or scope[name] < 0:
            raise ValueError("invalid semantic generation or membership epoch")
    for name in ("source_provider_sha256", "source_host_sha256"):
        value = scope[name]
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError("semantic source hash is absent")
        int(value, 16)
    if not isinstance(request_id, str) or not request_id:
        raise ValueError("runtime request identity is absent")
    if request_id not in scheduler_output.num_scheduled_tokens:
        raise ValueError("request did not cross acknowledged scheduled barrier")
    runner = provider.runner
    request = runner.requests[request_id]
    group = provider.attention_group_index
    destination = list(pending.block_ids)
    if (
        not destination
        or any(type(x) is not int or x < 0 for x in destination)
        or len(set(destination)) != len(destination)
    ):
        raise ValueError("invalid destination blocks")
    if (
        type(pending.semantic_anchor) is not int
        or type(pending.physical_anchor) is not int
        or not 0 < pending.physical_anchor < pending.semantic_anchor
    ):
        raise ValueError("compression anchor predicate is false")
    index = runner.input_batch.req_id_to_index[request_id]
    table = runner.input_batch.block_table.block_tables[group]
    observed = list(map(int, table.get_numpy_array()[index, : len(destination)]))
    active = provider.active[request_id]
    if (
        list(request.block_ids[group]) != destination
        or observed != destination
        or active.semantic_anchor != pending.semantic_anchor
        or active.physical_anchor != pending.physical_anchor
    ):
        raise ValueError("host block-table projection predicate is false")
    transaction = {
        "runtime_request_id": request_id,
        "attention_group": group,
        "semantic_anchor": pending.semantic_anchor,
        "physical_anchor": pending.physical_anchor,
        "destination_block_ids": destination,
    }
    receipt = {
        "schema": SCHEMA,
        "operation": OPERATION,
        "predicate": (
            "request-and-host-input-table-equal-destination-and-active-anchors"
        ),
        "scope": scope,
        "process": current_process(host_scope),
        "transaction": transaction,
        "transaction_id": digest(canonical(scope | transaction)),
        "observed_monotonic_ns": time.monotonic_ns(),
        "producer_sha256": digest(Path(__file__).read_bytes()),
        "formal_producer_registration": False,
        "gpu_table_upload_observed": False,
        "kv_tensor_equivalence": None,
        "model_quality": None,
    }
    receipt["event_id"] = digest(canonical(receipt))
    return receipt


def emit_worker_projection(
    provider: Any,
    scheduler_output: Any,
    request_id: str,
    pending: Any,
    *,
    scope: dict,
    host_scope: dict,
    durable_sink: Callable[[bytes], PublicationAck | None],
) -> bool:
    """No successful receipt on failed predicate, write, or explicit sink NACK.

    The callback contract ACKs only after exact bytes are fsynced plus any
    creating-directory metadata is fsynced. A callback claiming true is not
    independently trusted or a formal producer registration.
    """
    try:
        receipt = projection_receipt(
            provider, scheduler_output, request_id, pending, scope, host_scope
        )
        raw = canonical(receipt)
        acknowledgement = durable_sink(raw)
        return (
            isinstance(acknowledgement, PublicationAck)
            and acknowledgement.raw_sha256 == digest(raw)
            and acknowledgement.source_pid == os.getpid()
            and acknowledgement.filename == digest(raw) + ".json"
        )
    except Exception:  # noqa: BLE001 - observation failure never grants evidence.
        return False


def verify_receipt(
    raw: bytes,
    *,
    expected_scope: dict,
    expected_process: dict,
    expected_transaction: dict,
    expected_producer_sha256: str,
    expected_directory_identity: tuple[int, int],
    publication_ack: PublicationAck | None = None,
) -> dict:
    if (
        not isinstance(publication_ack, PublicationAck)
        or publication_ack.raw_sha256 != digest(raw)
        or publication_ack.filename != digest(raw) + ".json"
        or publication_ack.source_pid != expected_process["pid"]
        or (publication_ack.directory_device, publication_ack.directory_inode)
        != expected_directory_identity
    ):
        raise ValueError("typed publication acknowledgement is unavailable")
    receipt = json.loads(raw)
    expected_fields = {
        "schema",
        "operation",
        "predicate",
        "scope",
        "process",
        "transaction",
        "transaction_id",
        "observed_monotonic_ns",
        "producer_sha256",
        "formal_producer_registration",
        "gpu_table_upload_observed",
        "kv_tensor_equivalence",
        "model_quality",
        "event_id",
    }
    if (
        set(receipt) != expected_fields
        or receipt["schema"] != SCHEMA
        or receipt["operation"] != OPERATION
        or receipt["predicate"]
        != "request-and-host-input-table-equal-destination-and-active-anchors"
        or receipt["scope"] != expected_scope
        or receipt["process"] != expected_process
        or receipt["transaction"] != expected_transaction
        or receipt["producer_sha256"] != expected_producer_sha256
        or receipt["formal_producer_registration"] is not False
        or receipt["gpu_table_upload_observed"] is not False
        or receipt["kv_tensor_equivalence"] is not None
        or receipt["model_quality"] is not None
        or type(receipt["observed_monotonic_ns"]) is not int
        or receipt["observed_monotonic_ns"] <= 0
    ):
        raise ValueError("typed projection receipt differs from frozen expectation")
    body = {k: v for k, v in receipt.items() if k != "event_id"}
    if receipt["event_id"] != digest(canonical(body)) or receipt[
        "transaction_id"
    ] != digest(canonical(expected_scope | expected_transaction)):
        raise ValueError("typed projection receipt hash changed")
    return receipt


def write_durable_receipt(
    root: Path, raw: bytes, expected_directory_identity: tuple[int, int]
) -> PublicationAck | None:
    """Publish file-fsynced bytes, then ACK only after directory fsync.

    Publication can be visible before directory fsync. Readers MUST reject raw
    presence without a matching trusted writer ACK. This local candidate has
    no authenticated source-owned ACK channel or formal registration.
    """
    import stat

    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    pending_created = published = False
    name = digest(raw) + ".json"
    pending = ".pending-" + digest(raw)
    try:
        metadata = os.fstat(directory)
        if (
            (metadata.st_dev, metadata.st_ino) != expected_directory_identity
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ValueError("semantic receipt directory changed or is not private")
        fd = os.open(
            pending,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        pending_created = True
        try:
            data = memoryview(raw)
            while data:
                written = os.write(fd, data)
                if written <= 0:
                    raise OSError("semantic receipt write made no progress")
                data = data[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(
            pending,
            name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
        published = True
        os.unlink(pending, dir_fd=directory)
        pending_created = False
        os.fsync(directory)
        return PublicationAck(
            digest(raw), name, metadata.st_dev, metadata.st_ino, os.getpid()
        )
    except (OSError, ValueError):
        if published:
            os.unlink(name, dir_fd=directory)
        if pending_created:
            os.unlink(pending, dir_fd=directory)
        return None
    finally:
        os.close(directory)
