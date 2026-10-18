"""Fail-open runtime bridge and the single bounded JSONL exporter."""

from __future__ import annotations

import atexit
import hashlib
import logging
import os
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from vllm_request_lifecycle_profiler.kv_recovery_profile_protocol import (
    KVRecoveryProfileConfig,
    ProfileLossInterval,
    ProfileRecord,
    ProfileRecordRef,
    ProfileRecordType,
    build_profile_data_record,
    build_profile_loss_interval_record,
    build_profile_start_record,
    build_profile_summary_record,
    profile_record_line,
)
from vllm_request_lifecycle_profiler.kv_recovery_profile_protocol import (
    LossReason as ProfileLossReason,
)
from vllm_request_lifecycle_profiler.runtime_protocol import (
    CLOSE_TIMEOUT_MS,
    DATA_CAPACITY_RECORDS,
    KV_RECOVERY_COMMUNICATION_MODE,
    MAX_BATCH_BYTES,
    MAX_BATCH_RECORDS,
    MAX_QUEUED_BYTES,
    RESERVED_CAPACITY_RECORDS,
    TERMINAL_EVENTS,
    WRITE_INTERVAL_MS,
    EdgeDraft,
    EventDraft,
    RecordRef,
    RuntimeProvenance,
    build_edge_record,
    build_event_record,
    build_loss_interval_record,
    build_process_start_record,
    build_process_summary_record,
    canonical_json_line,
    new_process_uuid,
    new_trace_id,
    read_clock_domain_id,
)

logger = logging.getLogger(__name__)

TRACE_EXPORT_ENV = "VLLM_RLP_TRACE_EXPORT_PATH"
TRACE_PARENT_COMMIT_ENV = "VLLM_RLP_PROFILER_PARENT_COMMIT"
TRACE_RUNTIME_COMMIT_ENV = "VLLM_RLP_RUNTIME_CORE_COMMIT"
TRACE_DEVICE_COMMIT_ENV = "VLLM_RLP_DEVICE_PLUGIN_COMMIT"
TRACE_COMMUNICATION_MODE_ENV = "VLLM_RLP_COMMUNICATION_MODE"
TRACE_KV_RECOVERY_RUN_ID_ENV = "VLLM_RLP_KV_RECOVERY_RUN_ID"

_DIAGNOSTIC_REASON_ORDER = (
    "init_failure",
    "schema_incompatible",
    "serialization_failure",
    "queue_overflow",
    "writer_failure",
    "close_timeout",
    "clock_domain_unavailable",
    "terminal_conflict",
    "invalid_metadata",
    "unsupported_mode",
)
_DIAGNOSTIC_REASONS = frozenset(_DIAGNOSTIC_REASON_ORDER)


@dataclass(frozen=True)
class RuntimeTraceConfig:
    export_path: Path | None
    provenance: RuntimeProvenance | None = None
    communication_mode: str = "none"
    invalid_reason: str | None = None
    kv_recovery_profile_config: KVRecoveryProfileConfig | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> RuntimeTraceConfig:
        source = os.environ if env is None else env
        raw_path = source.get(TRACE_EXPORT_ENV, "").strip()
        if not raw_path:
            return cls(export_path=None)
        communication_mode = source.get(TRACE_COMMUNICATION_MODE_ENV, "none").strip()
        if communication_mode not in {"none", KV_RECOVERY_COMMUNICATION_MODE}:
            return cls(
                export_path=Path(raw_path),
                communication_mode=communication_mode,
                invalid_reason="unsupported_mode",
            )
        commit_values = (
            source.get(TRACE_PARENT_COMMIT_ENV, "").strip(),
            source.get(TRACE_RUNTIME_COMMIT_ENV, "").strip(),
            source.get(TRACE_DEVICE_COMMIT_ENV, "").strip(),
        )
        try:
            provenance = RuntimeProvenance(*commit_values)
        except ValueError:
            return cls(
                export_path=Path(raw_path),
                communication_mode=communication_mode,
                invalid_reason="schema_incompatible",
            )
        profile_config = None
        if communication_mode == KV_RECOVERY_COMMUNICATION_MODE:
            try:
                profile_config = KVRecoveryProfileConfig(
                    run_id=source.get(TRACE_KV_RECOVERY_RUN_ID_ENV, "").strip()
                )
            except ValueError:
                return cls(
                    export_path=Path(raw_path),
                    provenance=provenance,
                    communication_mode=communication_mode,
                    invalid_reason="schema_incompatible",
                )
        return cls(
            export_path=Path(raw_path),
            provenance=provenance,
            communication_mode=communication_mode,
            kv_recovery_profile_config=profile_config,
        )

    @property
    def requested(self) -> bool:
        return self.export_path is not None

    @property
    def enabled(self) -> bool:
        return (
            self.export_path is not None
            and self.provenance is not None
            and self.communication_mode in {"none", KV_RECOVERY_COMMUNICATION_MODE}
            and (
                self.communication_mode != KV_RECOVERY_COMMUNICATION_MODE
                or self.kv_recovery_profile_config is not None
            )
            and self.invalid_reason is None
        )


@dataclass(frozen=True)
class CloseResult:
    close_outcome: str
    summary_written: bool
    attempted_data_count: int
    written_event_count: int
    written_edge_count: int
    dropped_data_count: int
    dropped_control_count: int
    profile_summary_written: bool = False
    profile_attempted_data_count: int = 0
    profile_dropped_data_count: int = 0
    profile_dropped_control_count: int = 0


@dataclass(frozen=True)
class _QueuedRecord:
    raw: bytes
    record_type: str
    record_seq: int | None
    reserved: bool
    observed_timestamp_ns: int | None = None
    stream: str = "base"


@dataclass
class _OpenLoss:
    reason: str
    first_record_seq: int
    last_record_seq: int
    event_count: int
    edge_count: int
    first_timestamp_ns: int
    last_timestamp_ns: int


@dataclass
class _OpenProfileLoss:
    reason: ProfileLossReason
    first_record_seq: int
    last_record_seq: int
    counts: dict[ProfileRecordType, int]
    first_timestamp_ns: int
    last_timestamp_ns: int


@dataclass
class _ProfileWriterState:
    config: KVRecoveryProfileConfig
    shard_path: Path
    incomplete_shard_path: Path | None = None
    reservation_identity: tuple[int, int] | None = None
    fd: int = -1
    queued_bytes: int = 0
    ordinary_queued: int = 0
    reserved_queued: int = 0
    next_record_seq: int = 0
    next_loss_interval_seq: int = 0
    open_loss: _OpenProfileLoss | None = None
    attempted_data_count: int = 0
    written_block_set_chunk_count: int = 0
    written_wait_set_chunk_count: int = 0
    written_transfer_event_count: int = 0
    written_recovery_event_count: int = 0
    written_loss_interval_count: int = 0
    dropped_data_count: int = 0
    dropped_control_count: int = 0
    writer_failure_count: int = 0
    summary_written: bool = False
    records: list[ProfileRecord] = field(default_factory=list)
    losses: list[ProfileLossInterval] = field(default_factory=list)
    content_hash: object = field(default_factory=hashlib.sha256)


WriteFunction = Callable[[int, bytes | memoryview], int]
ClockFunction = Callable[[], int]
ProcessUuidFactory = Callable[[], str]


class JsonlTraceSink:
    """The v1alpha1 bounded exporter.

    Construction waits for bounded exporter initialization. Producer calls
    only validate, serialize, and enqueue bounded records. The writer thread
    owns the persistent descriptor for its complete lifetime, including
    ``process_start`` and ``process_summary``.
    """

    def __init__(
        self,
        base_path: Path,
        provenance: RuntimeProvenance,
        *,
        communication_mode: str = "none",
        kv_recovery_profile_config: KVRecoveryProfileConfig | None = None,
        clock_ns: ClockFunction = time.monotonic_ns,
        clock_domain_reader: Callable[[], str] = read_clock_domain_id,
        process_uuid_factory: ProcessUuidFactory = new_process_uuid,
        write_function: WriteFunction = os.write,
        writer_start_gate: threading.Event | None = None,
    ) -> None:
        if communication_mode not in {"none", KV_RECOVERY_COMMUNICATION_MODE}:
            raise ValueError("communication_mode is not implemented")
        if (
            kv_recovery_profile_config is not None
            and communication_mode != kv_recovery_profile_config.communication_mode
        ):
            raise ValueError("profile config and communication mode differ")
        self.base_path = Path(base_path)
        self.provenance = provenance
        self.communication_mode = communication_mode
        self._clock_ns = clock_ns
        # Resolve the same-host clock before a shard can be created. A failed
        # reader therefore cannot leak an fd or an empty evidence file.
        self.clock_domain_id = clock_domain_reader()
        self._process_uuid_factory = process_uuid_factory
        self._write_function = write_function
        self._uses_native_write = write_function is os.write
        self._writer_start_gate = writer_start_gate
        self._owner_pid = os.getpid()
        self.process_uuid = ""
        self.shard_path = self.base_path
        self.incomplete_shard_path: Path | None = None
        self._reservation_identity: tuple[int, int] | None = None
        self._fd = -1
        self._staging_fd = -1
        self._profile = (
            _ProfileWriterState(kv_recovery_profile_config, self.base_path)
            if kv_recovery_profile_config is not None
            else None
        )

        self._condition = threading.Condition()
        self._close_lock = threading.Lock()
        self._quarantine_lock = threading.Lock()
        self._writer_ready = threading.Event()
        self._queue: deque[_QueuedRecord] = deque()
        self._inflight_batch: list[_QueuedRecord] = []
        self._queued_bytes = 0
        self._ordinary_queued = 0
        self._reserved_queued = 0
        self._next_record_seq = 0
        self._next_span_seq = 0
        self._next_loss_interval_seq = 0
        self._open_loss: _OpenLoss | None = None
        self._attempted_data_count = 0
        self._written_event_count = 0
        self._written_edge_count = 0
        self._written_loss_interval_count = 0
        self._dropped_data_count = 0
        self._dropped_control_count = 0
        self._writer_failure_count = 0
        self._diagnostic_counts: dict[str, int] = {}
        self._pending_diagnostics: set[str] = set()
        self._logged_diagnostics: set[str] = set()
        self._closing = False
        self._closed = False
        self._writer_failed = False
        self._abandoned = False
        self._forked = False
        self._close_result: CloseResult | None = None
        # CPython executes one dict.setdefault call while holding the GIL. It
        # is the single-winner claim shared by the normal condition path and
        # the deadline fallback that must return without acquiring that lock.
        self._completion_claim: dict[str, CloseResult] = {}
        self._close_deadline_ns: int | None = None
        self._summary_written = False
        self._writer_outcome: str | None = None
        self._init_error: Exception | None = None
        self._content_hash = hashlib.sha256()

        self._writer = threading.Thread(
            target=self._writer_main,
            name=f"rlp-jsonl-init-{self._owner_pid}",
            daemon=True,
        )
        self._writer.start()
        if not self._writer_ready.wait(CLOSE_TIMEOUT_MS / 1000.0):
            with self._condition:
                self._abandoned = True
                self._condition.notify_all()
            raise TimeoutError("trace writer initialization timed out")
        if self._init_error is not None:
            raise self._init_error

        self._atexit_registered = True
        atexit.register(self.close)
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self.detach_after_fork_child)

    def new_trace_id(self) -> str | None:
        if not self._usable_in_current_process():
            return None
        return new_trace_id()

    def new_span_id(self) -> str | None:
        if not self._usable_in_current_process():
            return None
        with self._condition:
            if self._closing or self._closed:
                return None
            local_span_seq = self._next_span_seq
            self._next_span_seq += 1
            return f"{self.process_uuid}:s:{local_span_seq}"

    def write_event(self, draft: EventDraft) -> RecordRef | None:
        if not self._usable_in_current_process():
            return None
        with self._condition:
            if self._closing or self._closed:
                self._count_diagnostic_locked("schema_incompatible")
                return None
            record_seq = self._allocate_record_seq_locked()
            observed_ns = self._producer_clock_or_drop_locked(record_seq, "event")
            if observed_ns is None:
                return None
            if self._writer_failed:
                self._note_drop_locked(
                    record_seq,
                    "event",
                    "writer_failure",
                    observed_ns,
                )
                return None
            try:
                record, reference = build_event_record(
                    draft,
                    process_uuid=self.process_uuid,
                    clock_domain_id=self.clock_domain_id,
                    record_seq=record_seq,
                    default_timestamp_ns=observed_ns,
                    communication_mode=self.communication_mode,
                )
                raw = canonical_json_line(record)
            except Exception:  # noqa: BLE001 - serving must remain fail-open.
                self._note_drop_locked(
                    record_seq,
                    "event",
                    "serialization_failure",
                    observed_ns,
                )
                return None
            reserved = draft.event_name in TERMINAL_EVENTS
            if not self._can_enqueue_locked(raw, reserved=reserved):
                self._note_drop_locked(
                    record_seq,
                    "event",
                    "queue_overflow",
                    observed_ns,
                )
                return None
            self._seal_loss_locked()
            if not self._enqueue_locked(
                _QueuedRecord(raw, "event", record_seq, reserved, observed_ns)
            ):
                self._note_drop_locked(
                    record_seq,
                    "event",
                    "queue_overflow",
                    observed_ns,
                )
                return None
            return reference

    def write_edge(self, draft: EdgeDraft) -> RecordRef | None:
        if not self._usable_in_current_process():
            return None
        with self._condition:
            if self._closing or self._closed:
                self._count_diagnostic_locked("schema_incompatible")
                return None
            record_seq = self._allocate_record_seq_locked()
            observed_ns = self._producer_clock_or_drop_locked(record_seq, "edge")
            if observed_ns is None:
                return None
            if self._writer_failed:
                self._note_drop_locked(
                    record_seq,
                    "edge",
                    "writer_failure",
                    observed_ns,
                )
                return None
            try:
                record, reference = build_edge_record(
                    draft,
                    process_uuid=self.process_uuid,
                    record_seq=record_seq,
                    communication_mode=self.communication_mode,
                )
                raw = canonical_json_line(record)
            except Exception:  # noqa: BLE001 - serving must remain fail-open.
                self._note_drop_locked(
                    record_seq,
                    "edge",
                    "serialization_failure",
                    observed_ns,
                )
                return None
            if not self._can_enqueue_locked(raw, reserved=False):
                self._note_drop_locked(
                    record_seq,
                    "edge",
                    "queue_overflow",
                    observed_ns,
                )
                return None
            self._seal_loss_locked()
            if not self._enqueue_locked(
                _QueuedRecord(raw, "edge", record_seq, False, observed_ns)
            ):
                self._note_drop_locked(
                    record_seq,
                    "edge",
                    "queue_overflow",
                    observed_ns,
                )
                return None
            return reference

    def write_kv_recovery_profile(
        self,
        record_type: ProfileRecordType,
        timestamp_ns: int,
        **fields: object,
    ) -> ProfileRecordRef | None:
        """Serialize and enqueue one profile record on the shared writer."""

        if not self._usable_in_current_process():
            return None
        with self._condition:
            profile = self._profile
            if profile is None or self._closing or self._closed:
                self._count_diagnostic_locked("schema_incompatible")
                return None
            record_seq = self._allocate_profile_record_seq_locked(profile)
            if not isinstance(timestamp_ns, int) or isinstance(timestamp_ns, bool):
                observed_ns = self._profile_fallback_timestamp_locked()
                self._note_profile_drop_locked(
                    profile,
                    record_seq,
                    record_type,
                    "serialization_failure",
                    observed_ns,
                )
                return None
            observed_ns = timestamp_ns
            if observed_ns < 0 or observed_ns > 2**64 - 1:
                fallback_ns = self._profile_fallback_timestamp_locked()
                self._note_profile_drop_locked(
                    profile,
                    record_seq,
                    record_type,
                    "serialization_failure",
                    fallback_ns,
                )
                return None
            if self._writer_failed:
                self._note_profile_drop_locked(
                    profile,
                    record_seq,
                    record_type,
                    "writer_failure",
                    observed_ns,
                )
                return None
            try:
                record, reference = build_profile_data_record(
                    record_type=record_type,
                    process_uuid=self.process_uuid,
                    record_seq=record_seq,
                    timestamp_ns=observed_ns,
                    clock_domain_id=self.clock_domain_id,
                    config=profile.config,
                    fields=fields,
                )
                raw = profile_record_line(record)
            except Exception:  # noqa: BLE001 - serving must remain fail-open.
                self._note_profile_drop_locked(
                    profile,
                    record_seq,
                    record_type,
                    "serialization_failure",
                    observed_ns,
                )
                return None
            if not self._can_enqueue_locked(raw, reserved=False, stream="profile"):
                self._note_profile_drop_locked(
                    profile,
                    record_seq,
                    record_type,
                    "queue_overflow",
                    observed_ns,
                )
                return None
            self._seal_profile_loss_locked(profile)
            queued = _QueuedRecord(
                raw,
                record_type,
                record_seq,
                False,
                observed_ns,
                "profile",
            )
            if not self._enqueue_locked(queued):
                self._note_profile_drop_locked(
                    profile,
                    record_seq,
                    record_type,
                    "queue_overflow",
                    observed_ns,
                )
                return None
            common_keys = {
                "schema",
                "record_type",
                "process_uuid",
                "record_seq",
                "record_id",
                "run_id",
                "timestamp_ns",
                "clock_domain_id",
                "profile_id",
            }
            assert profile.records is not None
            profile.records.append(
                ProfileRecord(
                    record_type=record_type,
                    record_seq=record_seq,
                    record_id=reference.record_id,
                    timestamp_ns=observed_ns,
                    fields={
                        key: value
                        for key, value in record.items()
                        if key not in common_keys
                    },
                )
            )
            return reference

    def drop_kv_recovery_profile(
        self,
        record_type: ProfileRecordType,
        timestamp_ns: int | None,
        reason: ProfileLossReason = "serialization_failure",
    ) -> int | None:
        """Consume one profile sequence and account the exact failed category."""

        if not self._usable_in_current_process():
            return None
        with self._condition:
            profile = self._profile
            if profile is None or self._closing or self._closed:
                return None
            record_seq = self._allocate_profile_record_seq_locked(profile)
            observed_ns = (
                timestamp_ns
                if type(timestamp_ns) is int and 0 <= timestamp_ns <= 2**64 - 1
                else self._profile_fallback_timestamp_locked()
            )
            self._note_profile_drop_locked(
                profile, record_seq, record_type, reason, observed_ns
            )
            return record_seq

    @property
    def kv_recovery_profile_enabled(self) -> bool:
        return self._profile is not None and self._usable_in_current_process()

    @property
    def kv_recovery_profile_evidence_complete(self) -> bool:
        with self._condition:
            profile = self._profile
            return bool(
                profile is not None
                and profile.dropped_data_count == 0
                and profile.dropped_control_count == 0
                and profile.writer_failure_count == 0
            )

    @property
    def kv_recovery_profile_attempted_data_count(self) -> int:
        with self._condition:
            return self._profile.attempted_data_count if self._profile else 0

    def kv_recovery_profile_snapshot(
        self,
    ) -> tuple[tuple[ProfileRecord, ...], tuple[ProfileLossInterval, ...]]:
        with self._condition:
            profile = self._profile
            if profile is None:
                return (), ()
            assert profile.records is not None and profile.losses is not None
            return tuple(profile.records), tuple(profile.losses)

    def close(self) -> CloseResult:
        requested_deadline_ns = time.monotonic_ns() + CLOSE_TIMEOUT_MS * 1_000_000
        if os.getpid() != self._owner_pid:
            self.detach_after_fork_child()
            return self._result("writer_failure", summary_written=False)
        claimed = self._claimed_close_result()
        if claimed is not None:
            self._unregister_atexit()
            return claimed
        if not self._close_lock.acquire(
            timeout=self._remaining_close_seconds(requested_deadline_ns)
        ):
            result = self._bounded_timeout_without_lock()
            self._unregister_atexit()
            return result
        try:
            if not self._condition.acquire(
                timeout=self._remaining_close_seconds(requested_deadline_ns)
            ):
                return self._bounded_timeout_without_lock()
            try:
                claimed = self._claimed_close_result()
                if claimed is not None:
                    return claimed
                if self._closed:
                    result, _ = self._claim_close_result(
                        "writer_failure", summary_written=False
                    )
                    return result
                self._close_deadline_ns = requested_deadline_ns
                self._seal_loss_locked()
                if self._profile is not None:
                    self._seal_profile_loss_locked(self._profile)
                self._closing = True
                self._condition.notify_all()
            finally:
                self._condition.release()

            self._writer.join(self._remaining_close_seconds(requested_deadline_ns))
            if not self._condition.acquire(
                timeout=self._remaining_close_seconds(requested_deadline_ns)
            ):
                return self._bounded_timeout_without_lock()
            try:
                claimed = self._claimed_close_result()
                if self._writer.is_alive():
                    if claimed is None:
                        self._force_timeout_accounting_locked()
                        self._abandoned = True
                        self._closed = True
                        claimed, _ = self._claim_close_result(
                            "timeout", summary_written=False
                        )
                        self._condition.notify_all()
                elif claimed is None:
                    outcome = self._writer_outcome or "writer_failure"
                    claimed, _ = self._claim_close_result(
                        outcome, self._summary_written
                    )
                assert claimed is not None
                return claimed
            finally:
                self._condition.release()
        finally:
            self._unregister_atexit()
            self._close_lock.release()

    @staticmethod
    def _remaining_close_seconds(deadline_ns: int) -> float:
        return max(0.0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000)

    def _bounded_timeout_without_lock(self) -> CloseResult:
        """Publish a lock-free timeout when a vanished thread owns a close lock."""

        # Exact counters are not evidence-bearing if this timeout claim wins,
        # because no shard admitted by this CloseResult can then publish. A
        # writer that already won the atomic drained claim is returned as-is.
        result, won = self._claim_close_result("timeout", summary_written=False)
        if won:
            self._abandoned = True
            self._closed = True
            self._writer_outcome = "timeout"
        return result

    def _claimed_close_result(self) -> CloseResult | None:
        return self._completion_claim.get("result")

    def _claim_close_result(
        self, close_outcome: str, summary_written: bool
    ) -> tuple[CloseResult, bool]:
        candidate = self._result(close_outcome, summary_written)
        winner = self._completion_claim.setdefault("result", candidate)
        self._close_result = winner
        return winner, winner is candidate

    @property
    def diagnostic_counts(self) -> dict[str, int]:
        with self._condition:
            return dict(self._diagnostic_counts)

    @property
    def committed_shard_path(self) -> Path | None:
        """Return the only shard path eligible for a run manifest.

        The raw ``shard_path`` is also used for an empty UUID reservation and
        failure quarantine. Callers must use this receipt-gated property when
        constructing the manifest's explicit expected-shard list.
        """

        result = self._claimed_close_result()
        if (
            result is not None
            and result.close_outcome == "drained"
            and result.summary_written
        ):
            return self.shard_path
        return None

    @property
    def committed_kv_recovery_profile_shard_path(self) -> Path | None:
        """Return the paired profile path only after one immutable close win."""

        result = self._claimed_close_result()
        profile = self._profile
        if (
            profile is not None
            and result is not None
            and result.close_outcome == "drained"
            and result.summary_written
            and result.profile_summary_written
        ):
            return profile.shard_path
        return None

    def defer_diagnostic(self, reason: str) -> None:
        """Schedule one bounded diagnostic without running a producer handler."""

        if not self._usable_in_current_process():
            return
        with self._condition:
            if self._closing or self._closed:
                return
            self._count_diagnostic_locked(reason)

    def __enter__(self) -> JsonlTraceSink:  # noqa: PYI034 - Python 3.10 API.
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def _open_shard(self) -> tuple[str, Path, int]:
        self.base_path.parent.mkdir(parents=True, exist_ok=True)
        last_error: OSError | None = None
        for _ in range(3):
            process_uuid = self._process_uuid_factory()
            shard_path = Path(f"{self.base_path}.rlp.{process_uuid}.jsonl")
            profile_path = Path(
                f"{self.base_path}.rlp-kv-recovery.{process_uuid}.jsonl"
            )
            fd = -1
            profile_fd = -1
            profile_created = False
            try:
                flags = os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_WRONLY
                flags |= getattr(os, "O_CLOEXEC", 0)
                fd = os.open(
                    shard_path,
                    flags,
                    0o600,
                )
                try:
                    os.fchmod(fd, 0o600)
                    if self._profile is not None:
                        profile_fd = os.open(profile_path, flags, 0o600)
                        profile_created = True
                        os.fchmod(profile_fd, 0o600)
                except Exception:
                    try:
                        os.close(fd)
                    except Exception:  # noqa: BLE001, S110 - preserve init cause.
                        pass
                    try:
                        shard_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                    if profile_fd >= 0:
                        try:
                            os.close(profile_fd)
                        except OSError:
                            pass
                    if profile_created:
                        try:
                            profile_path.unlink(missing_ok=True)
                        except OSError:
                            pass
                    raise
                if self._profile is not None:
                    self._profile.shard_path = profile_path
                    self._profile.fd = profile_fd
                return process_uuid, shard_path, fd
            except FileExistsError as exc:
                last_error = exc
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    try:
                        shard_path.unlink(missing_ok=True)
                    except OSError:
                        pass
        raise FileExistsError(
            "could not allocate a unique process shard"
        ) from last_error

    def _allocate_record_seq_locked(self) -> int:
        record_seq = self._next_record_seq
        self._next_record_seq += 1
        self._attempted_data_count += 1
        return record_seq

    @staticmethod
    def _allocate_profile_record_seq_locked(profile: _ProfileWriterState) -> int:
        if profile.next_record_seq > 2**64 - 1:
            raise OverflowError("profile record sequence exhausted")
        record_seq = profile.next_record_seq
        profile.next_record_seq += 1
        profile.attempted_data_count += 1
        return record_seq

    def _profile_fallback_timestamp_locked(self) -> int:
        try:
            value = self._clock_ns()
            if type(value) is int and 0 <= value <= 2**64 - 1:
                return value
        except Exception:  # noqa: BLE001, S110 - evidence-only fallback.
            pass
        return time.monotonic_ns()

    def _producer_clock_or_drop_locked(
        self, record_seq: int, record_type: str
    ) -> int | None:
        try:
            observed_ns = self._clock_ns()
            if (
                isinstance(observed_ns, bool)
                or not isinstance(observed_ns, int)
                or observed_ns < 0
                or observed_ns > 2**64 - 1
            ):
                raise ValueError("CLOCK_MONOTONIC value is outside uint64")
            return observed_ns
        except Exception:  # noqa: BLE001 - producer remains serving fail-open.
            fallback_ns = time.monotonic_ns()
            self._count_diagnostic_locked("clock_domain_unavailable")
            self._note_drop_locked(
                record_seq,
                record_type,
                "serialization_failure",
                fallback_ns,
            )
            return None

    def _can_enqueue_locked(
        self, raw: bytes, *, reserved: bool, stream: str = "base"
    ) -> bool:
        if self._writer_failed or self._closing or self._closed:
            return False
        if stream == "profile":
            profile = self._profile
            if profile is None or profile.queued_bytes + len(raw) > MAX_QUEUED_BYTES:
                return False
            if reserved:
                return profile.reserved_queued < RESERVED_CAPACITY_RECORDS
            return profile.ordinary_queued < DATA_CAPACITY_RECORDS
        if stream != "base":
            return False
        if self._queued_bytes + len(raw) > MAX_QUEUED_BYTES:
            return False
        if reserved:
            return self._reserved_queued < RESERVED_CAPACITY_RECORDS
        return self._ordinary_queued < DATA_CAPACITY_RECORDS

    def _enqueue_locked(self, queued: _QueuedRecord) -> bool:
        if not self._can_enqueue_locked(
            queued.raw, reserved=queued.reserved, stream=queued.stream
        ):
            return False
        self._queue.append(queued)
        if queued.stream == "profile":
            assert self._profile is not None
            self._profile.queued_bytes += len(queued.raw)
            if queued.reserved:
                self._profile.reserved_queued += 1
            else:
                self._profile.ordinary_queued += 1
        else:
            self._queued_bytes += len(queued.raw)
            if queued.reserved:
                self._reserved_queued += 1
            else:
                self._ordinary_queued += 1
        self._condition.notify()
        return True

    def _note_drop_locked(
        self,
        record_seq: int,
        record_type: str,
        reason: str,
        observed_ns: int,
    ) -> None:
        self._dropped_data_count += 1
        self._count_diagnostic_locked(reason)
        event_increment = int(record_type == "event")
        edge_increment = int(record_type == "edge")
        current = self._open_loss
        if (
            current is not None
            and current.reason == reason
            and record_seq == current.last_record_seq + 1
        ):
            current.last_record_seq = record_seq
            current.event_count += event_increment
            current.edge_count += edge_increment
            current.last_timestamp_ns = observed_ns
            return
        self._seal_loss_locked()
        self._open_loss = _OpenLoss(
            reason=reason,
            first_record_seq=record_seq,
            last_record_seq=record_seq,
            event_count=event_increment,
            edge_count=edge_increment,
            first_timestamp_ns=observed_ns,
            last_timestamp_ns=observed_ns,
        )

    def _seal_loss_locked(self) -> None:
        current = self._open_loss
        if current is None:
            return
        loss_seq = self._next_loss_interval_seq
        self._next_loss_interval_seq += 1
        self._open_loss = None
        try:
            record = build_loss_interval_record(
                process_uuid=self.process_uuid,
                loss_interval_seq=loss_seq,
                reason=current.reason,
                first_dropped_record_seq=current.first_record_seq,
                last_dropped_record_seq=current.last_record_seq,
                event_count=current.event_count,
                edge_count=current.edge_count,
                first_observed_timestamp_ns=current.first_timestamp_ns,
                last_observed_timestamp_ns=current.last_timestamp_ns,
            )
            raw = canonical_json_line(record)
        except Exception:  # noqa: BLE001 - control loss invalidates, not serving.
            self._dropped_control_count += 1
            return
        if not self._enqueue_locked(
            _QueuedRecord(raw, "loss_interval", None, True, None)
        ):
            self._dropped_control_count += 1

    def _note_profile_drop_locked(
        self,
        profile: _ProfileWriterState,
        record_seq: int,
        record_type: ProfileRecordType,
        reason: ProfileLossReason,
        observed_ns: int,
    ) -> None:
        profile.dropped_data_count += 1
        self._count_diagnostic_locked(reason)
        counts: dict[ProfileRecordType, int] = {
            "block_set_chunk": 0,
            "wait_set_chunk": 0,
            "transfer_event": 0,
            "recovery_event": 0,
        }
        counts[record_type] = 1
        current = profile.open_loss
        if (
            current is not None
            and current.reason == reason
            and record_seq == current.last_record_seq + 1
        ):
            current.last_record_seq = record_seq
            current.counts[record_type] += 1
            current.last_timestamp_ns = observed_ns
            assert profile.losses is not None
            profile.losses[-1] = ProfileLossInterval(
                reason=current.reason,
                first_record_seq=current.first_record_seq,
                last_record_seq=current.last_record_seq,
                counts=dict(current.counts),
                first_timestamp_ns=current.first_timestamp_ns,
                last_timestamp_ns=current.last_timestamp_ns,
            )
            return
        self._seal_profile_loss_locked(profile)
        profile.open_loss = _OpenProfileLoss(
            reason=reason,
            first_record_seq=record_seq,
            last_record_seq=record_seq,
            counts=counts,
            first_timestamp_ns=observed_ns,
            last_timestamp_ns=observed_ns,
        )
        assert profile.losses is not None
        profile.losses.append(
            ProfileLossInterval(
                reason=reason,
                first_record_seq=record_seq,
                last_record_seq=record_seq,
                counts=dict(counts),
                first_timestamp_ns=observed_ns,
                last_timestamp_ns=observed_ns,
            )
        )

    def _seal_profile_loss_locked(self, profile: _ProfileWriterState) -> None:
        current = profile.open_loss
        if current is None:
            return
        loss_seq = profile.next_loss_interval_seq
        profile.next_loss_interval_seq += 1
        profile.open_loss = None
        try:
            record = build_profile_loss_interval_record(
                process_uuid=self.process_uuid,
                config=profile.config,
                loss_interval_seq=loss_seq,
                reason=current.reason,
                first_dropped_record_seq=current.first_record_seq,
                last_dropped_record_seq=current.last_record_seq,
                counts=current.counts,
                first_observed_timestamp_ns=current.first_timestamp_ns,
                last_observed_timestamp_ns=current.last_timestamp_ns,
            )
            raw = profile_record_line(record)
        except Exception:  # noqa: BLE001 - control loss invalidates evidence.
            profile.dropped_control_count += 1
            return
        if not self._enqueue_locked(
            _QueuedRecord(
                raw,
                "loss_interval",
                None,
                True,
                None,
                "profile",
            )
        ):
            profile.dropped_control_count += 1

    def _writer_main(self) -> None:
        initialized = False
        try:
            self._initialize_writer()
            initialized = True
            self._writer_ready.set()
            with self._condition:
                initialization_abandoned = self._abandoned
            if initialization_abandoned:
                self._remove_failed_initialization_shard()
                return
            if not self._wait_for_writer_gate():
                with self._condition:
                    if self._abandoned:
                        return
                self._finish_timeout_in_writer()
                return
            while True:
                with self._condition:
                    if self._abandoned:
                        return
                    while (
                        not self._queue
                        and not self._closing
                        and not self._pending_diagnostics
                        and not self._abandoned
                    ):
                        self._condition.wait(WRITE_INTERVAL_MS / 1000.0)
                    if self._abandoned:
                        return
                    diagnostics = self._take_pending_diagnostics_locked()
                    if diagnostics:
                        finish_timeout = False
                        finish_drained = False
                        batch = []
                    elif self._close_cutoff_reached_locked():
                        finish_timeout = True
                        finish_drained = False
                        batch: list[_QueuedRecord] = []
                    elif not self._queue and self._closing:
                        finish_timeout = False
                        finish_drained = True
                        batch = []
                    else:
                        finish_timeout = False
                        finish_drained = False
                        batch = self._take_batch_locked()
                        self._inflight_batch = list(batch)
                if diagnostics:
                    self._log_diagnostics_in_writer(diagnostics)
                    continue
                if finish_timeout:
                    self._finish_timeout_in_writer()
                    return
                if finish_drained:
                    self._finish_drained_in_writer()
                    return
                for queued in batch:
                    with self._condition:
                        if self._abandoned:
                            return
                        if self._close_cutoff_reached_locked():
                            finish_timeout = True
                            break
                    try:
                        self._write_queued_all(queued)
                    except Exception:  # noqa: BLE001 - writer is fail-open.
                        self._mark_writer_failure()
                        return
                    self._record_written(queued)
                if finish_timeout:
                    self._finish_timeout_in_writer()
                    return
        except Exception as exc:  # noqa: BLE001 - initialization is fail-open.
            if not initialized:
                self._init_error = exc
                self._remove_failed_initialization_shard()
                self._writer_ready.set()
            else:
                self._mark_writer_failure()
        finally:
            try:
                self._finalize_writer_in_writer()
            except Exception:  # noqa: BLE001 - final state must still publish.
                with self._condition:
                    self._mark_writer_failure_locked()
                    self._summary_written = False
                    self._writer_outcome = "writer_failure"
            finally:
                # No cleanup exception may skip the state observed by close().
                with self._condition:
                    self._closed = True
                    if (
                        initialized
                        and self._claimed_close_result() is None
                        and self._closing
                    ):
                        outcome = self._writer_outcome or (
                            "writer_failure" if self._writer_failed else "drained"
                        )
                        self._claim_close_result(outcome, self._summary_written)
                    self._condition.notify_all()

    def _finalize_writer_in_writer(self) -> None:
        with self._condition:
            invalidate_late_summary = self._abandoned and self._summary_written
        if invalidate_late_summary:
            # The summary is already under an incomplete name. A duplicate
            # timeout summary also makes the retained bytes structurally invalid.
            self._append_timeout_invalidation_in_writer()
            with self._condition:
                self._summary_written = False
                self._writer_outcome = "timeout"

        staging_closed = self._close_staging_fd()
        profile_closed = self._close_profile_fd()
        persistent_closed = self._close_fd()
        if not staging_closed or not profile_closed or not persistent_closed:
            with self._condition:
                self._mark_writer_failure_locked()
                self._summary_written = False
                self._writer_outcome = "writer_failure"

        # Diagnostics may execute arbitrary handlers, so drain them before a
        # complete shard can be published into the formal namespace.
        self._flush_diagnostics_in_writer()
        published = self._publish_completed_shard_in_writer()
        if not published:
            # A publication failure schedules writer_failure after the first
            # flush. A successful publication is the final commit point and
            # must never be followed by an arbitrary handler or filesystem op.
            self._flush_diagnostics_in_writer()

    def _initialize_writer(self) -> None:
        process_uuid, shard_path, fd = self._open_shard()
        self.process_uuid = process_uuid
        self.shard_path = shard_path
        self._fd = fd
        started_timestamp_ns = self._clock_ns()
        start_record = build_process_start_record(
            process_uuid=self.process_uuid,
            pid=self._owner_pid,
            started_timestamp_ns=started_timestamp_ns,
            clock_domain_id=self.clock_domain_id,
            provenance=self.provenance,
        )
        start_raw = canonical_json_line(start_record)
        if not self._write_reserved_control_in_writer(start_raw, count_drop=False):
            raise OSError("process_start reserved capacity is unavailable")
        self._content_hash.update(start_raw)
        profile = self._profile
        if profile is not None:
            profile_start = build_profile_start_record(
                process_uuid=self.process_uuid,
                pid=self._owner_pid,
                started_timestamp_ns=started_timestamp_ns,
                clock_domain_id=self.clock_domain_id,
                provenance=self.provenance,
                config=profile.config,
            )
            profile_raw = profile_record_line(profile_start)
            if not self._write_profile_reserved_control_in_writer(
                profile_raw, count_drop=False
            ):
                raise OSError("profile_start reserved capacity is unavailable")
            assert profile.content_hash is not None
            profile.content_hash.update(profile_raw)

    def _wait_for_writer_gate(self) -> bool:
        gate = self._writer_start_gate
        if gate is None:
            return True
        while not gate.wait(0.01):
            with self._condition:
                if self._abandoned:
                    return False
                if self._close_cutoff_reached_locked():
                    return False
        return True

    def _finish_drained_in_writer(self) -> None:
        if not self._counts_reconcile():
            self._mark_writer_failure()
            return
        try:
            self._write_summary_in_writer("drained")
        except Exception:  # noqa: BLE001 - close remains serving fail-open.
            self._mark_writer_failure()

    def _finish_timeout_in_writer(self) -> None:
        with self._condition:
            controls = self._prepare_timeout_controls_locked()
        for queued in controls:
            if self._close_deadline_reached():
                with self._condition:
                    for pending_control in self._inflight_batch:
                        if (
                            pending_control.stream == "profile"
                            and self._profile is not None
                        ):
                            self._profile.dropped_control_count += 1
                        else:
                            self._dropped_control_count += 1
                    self._inflight_batch.clear()
                    self._queued_bytes = 0
                    self._reserved_queued = 0
                    if self._profile is not None:
                        self._profile.queued_bytes = 0
                        self._profile.reserved_queued = 0
                self._writer_outcome = "timeout"
                return
            try:
                self._write_queued_all(queued)
            except Exception:  # noqa: BLE001 - evidence fails closed.
                self._mark_writer_failure()
                return
            self._record_written(queued)
        if self._close_deadline_reached() or not self._counts_reconcile():
            self._writer_outcome = "timeout"
            return
        try:
            self._write_summary_in_writer("timeout")
        except Exception:  # noqa: BLE001 - evidence fails closed.
            self._mark_writer_failure()

    def _write_summary_in_writer(self, close_outcome: str) -> None:
        if self._close_deadline_reached():
            self._writer_outcome = "timeout"
            return
        self._move_formal_shard_to_incomplete_in_writer()
        if self._profile is not None:
            self._move_profile_shard_to_incomplete_in_writer()
        if self._close_deadline_reached():
            self._writer_outcome = "timeout"
            return
        summary = build_process_summary_record(
            process_uuid=self.process_uuid,
            ended_timestamp_ns=self._clock_ns(),
            attempted_data_count=self._attempted_data_count,
            written_event_count=self._written_event_count,
            written_edge_count=self._written_edge_count,
            written_loss_interval_count=self._written_loss_interval_count,
            dropped_data_count=self._dropped_data_count,
            dropped_control_count=self._dropped_control_count,
            writer_failure_count=self._writer_failure_count,
            close_outcome=close_outcome,
            content_sha256=self._content_hash.hexdigest(),
        )
        if not self._write_reserved_control_in_writer(canonical_json_line(summary)):
            self._writer_outcome = close_outcome
            return
        if self._close_deadline_reached():
            self._writer_outcome = "timeout"
            self._append_timeout_invalidation_in_writer()
            return
        profile = self._profile
        if profile is not None:
            assert profile.content_hash is not None
            profile_summary = build_profile_summary_record(
                process_uuid=self.process_uuid,
                config=profile.config,
                ended_timestamp_ns=self._clock_ns(),
                attempted_data_count=profile.attempted_data_count,
                written_counts={
                    "block_set_chunk": profile.written_block_set_chunk_count,
                    "wait_set_chunk": profile.written_wait_set_chunk_count,
                    "transfer_event": profile.written_transfer_event_count,
                    "recovery_event": profile.written_recovery_event_count,
                },
                written_loss_interval_count=profile.written_loss_interval_count,
                dropped_data_count=profile.dropped_data_count,
                dropped_control_count=profile.dropped_control_count,
                writer_failure_count=profile.writer_failure_count,
                close_outcome=close_outcome,
                content_sha256=profile.content_hash.hexdigest(),
            )
            if not self._write_profile_reserved_control_in_writer(
                profile_record_line(profile_summary)
            ):
                self._writer_outcome = close_outcome
                return
            if self._close_deadline_reached():
                self._writer_outcome = "timeout"
                self._append_timeout_invalidation_in_writer()
                return
            profile.summary_written = True
        self._summary_written = True
        self._writer_outcome = close_outcome

    def _move_formal_shard_to_incomplete_in_writer(self) -> None:
        """Hide summary bytes while retaining the process UUID reservation."""

        with self._quarantine_lock:
            if self.incomplete_shard_path is not None:
                return
            if not self.process_uuid or not self.shard_path.exists():
                raise OSError("formal shard is unavailable before summary")
            target = Path(f"{self.shard_path}.incomplete.{time.monotonic_ns()}")
            reservation = Path(f"{self.shard_path}.reservation.{time.monotonic_ns()}")
            reservation_fd = -1
            linked = False
            try:
                # Hard-link first, then atomically replace the formal name with
                # an empty private sentinel. The formal UUID path is therefore
                # never absent and a second O_EXCL sink cannot claim it.
                os.link(self.shard_path, target)
                linked = True
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
                flags |= getattr(os, "O_CLOEXEC", 0)
                reservation_fd = os.open(reservation, flags, 0o600)
                os.fchmod(reservation_fd, 0o600)
                reservation_stat = os.fstat(reservation_fd)
                os.close(reservation_fd)
                reservation_fd = -1
                os.replace(reservation, self.shard_path)
                formal_stat = os.stat(self.shard_path, follow_symlinks=False)
                identity = (reservation_stat.st_dev, reservation_stat.st_ino)
                if (formal_stat.st_dev, formal_stat.st_ino) != identity:
                    raise OSError("formal shard reservation identity changed")
                self._reservation_identity = identity
                self.incomplete_shard_path = target
            except Exception:
                if reservation_fd >= 0:
                    try:
                        os.close(reservation_fd)
                    except OSError:
                        pass
                try:
                    reservation.unlink(missing_ok=True)
                except OSError:
                    pass
                if linked and self.incomplete_shard_path is None:
                    try:
                        target.unlink(missing_ok=True)
                    except OSError:
                        pass
                raise

    def _move_profile_shard_to_incomplete_in_writer(self) -> None:
        """Hide profile summary bytes under the same writer/quarantine owner."""

        profile = self._profile
        if profile is None:
            return
        with self._quarantine_lock:
            if profile.incomplete_shard_path is not None:
                return
            if not self.process_uuid or not profile.shard_path.exists():
                raise OSError("formal profile shard is unavailable before summary")
            target = Path(f"{profile.shard_path}.incomplete.{time.monotonic_ns()}")
            reservation = Path(
                f"{profile.shard_path}.reservation.{time.monotonic_ns()}"
            )
            reservation_fd = -1
            linked = False
            try:
                os.link(profile.shard_path, target)
                linked = True
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
                flags |= getattr(os, "O_CLOEXEC", 0)
                reservation_fd = os.open(reservation, flags, 0o600)
                os.fchmod(reservation_fd, 0o600)
                reservation_stat = os.fstat(reservation_fd)
                os.close(reservation_fd)
                reservation_fd = -1
                os.replace(reservation, profile.shard_path)
                formal_stat = os.stat(profile.shard_path, follow_symlinks=False)
                identity = (reservation_stat.st_dev, reservation_stat.st_ino)
                if (formal_stat.st_dev, formal_stat.st_ino) != identity:
                    raise OSError("formal profile reservation identity changed")
                profile.reservation_identity = identity
                profile.incomplete_shard_path = target
            except Exception:
                if reservation_fd >= 0:
                    try:
                        os.close(reservation_fd)
                    except OSError:
                        pass
                try:
                    reservation.unlink(missing_ok=True)
                except OSError:
                    pass
                if linked and profile.incomplete_shard_path is None:
                    try:
                        target.unlink(missing_ok=True)
                    except OSError:
                        pass
                raise

    def _publish_completed_shard_in_writer(self) -> bool:
        """Publish the base/profile pair before one immutable close claim."""

        with self._condition:
            eligible = (
                self._summary_written
                and self._writer_outcome == "drained"
                and not self._writer_failed
                and not self._abandoned
                and not self._close_deadline_reached()
                and (self._profile is None or self._profile.summary_written)
            )
        if not eligible:
            return False
        with self._quarantine_lock:
            targets: list[tuple[str, Path, Path, tuple[int, int]]] = []
            base_source = self.incomplete_shard_path
            base_identity = self._reservation_identity
            if base_source is None or base_identity is None:
                self._mark_publication_failure()
                return False
            targets.append(("base", base_source, self.shard_path, base_identity))
            profile = self._profile
            if profile is not None:
                if (
                    profile.incomplete_shard_path is None
                    or profile.reservation_identity is None
                ):
                    self._mark_publication_failure()
                    return False
                targets.append(
                    (
                        "profile",
                        profile.incomplete_shard_path,
                        profile.shard_path,
                        profile.reservation_identity,
                    )
                )
            for _stream, source, formal, identity in targets:
                try:
                    formal_stat = os.stat(formal, follow_symlinks=False)
                except OSError:
                    formal_stat = None
                if (
                    not source.exists()
                    or formal_stat is None
                    or (formal_stat.st_dev, formal_stat.st_ino) != identity
                ):
                    self._mark_publication_failure()
                    return False

            published: list[tuple[str, Path, Path, tuple[int, int]]] = []
            try:
                for target in targets:
                    _stream, source, formal, _identity = target
                    os.replace(source, formal)
                    published.append(target)
            except OSError:
                for stream, source, formal, _identity in reversed(published):
                    self._retract_published_shard_in_writer(stream, formal, source)
                self._mark_publication_failure()
                return False

            with self._condition:
                if self._abandoned or self._close_deadline_reached():
                    publication_expired = True
                else:
                    result, won = self._claim_close_result(
                        "drained", summary_written=True
                    )
                    publication_expired = not won
                    if won:
                        self.incomplete_shard_path = None
                        self._reservation_identity = None
                        if profile is not None:
                            profile.incomplete_shard_path = None
                            profile.reservation_identity = None
                        self._closed = True
                        self._close_result = result
                        self._condition.notify_all()
            if publication_expired:
                for stream, source, formal, _identity in reversed(published):
                    self._retract_published_shard_in_writer(stream, formal, source)
                with self._condition:
                    self._summary_written = False
                    if profile is not None:
                        profile.summary_written = False
                    self._writer_outcome = "timeout"
                    self._count_diagnostic_locked("close_timeout")
                return False
            return True

    def _retract_published_shard_in_writer(
        self, stream: str, formal: Path, target: Path
    ) -> None:
        if stream == "profile":
            profile = self._profile
            if profile is not None:
                profile.reservation_identity = None
        else:
            self._reservation_identity = None
        try:
            os.replace(formal, target)
            if stream == "profile" and self._profile is not None:
                self._profile.incomplete_shard_path = target
            else:
                self.incomplete_shard_path = target
            return
        except OSError:
            pass
        try:
            formal.unlink(missing_ok=True)
            if stream == "profile" and self._profile is not None:
                self._profile.incomplete_shard_path = None
            else:
                self.incomplete_shard_path = None
            return
        except OSError:
            pass
        if stream == "profile":
            self._append_profile_invalidation_to_path_in_writer(formal)
        else:
            self._append_invalidation_to_path_in_writer(formal)

    def _mark_publication_failure(self) -> None:
        with self._condition:
            self._mark_writer_failure_locked()
            self._summary_written = False
            self._writer_outcome = "writer_failure"

    def _retract_late_publication_in_writer(self, target: Path) -> None:
        """Best-effort structural invalidation after a publication crosses cutoff."""

        # The sentinel was consumed by the completed-shard publication, so
        # its inode can no longer reserve or authenticate the formal name.
        self._reservation_identity = None
        try:
            os.replace(self.shard_path, target)
            self.incomplete_shard_path = target
            return
        except OSError:
            pass
        try:
            self.shard_path.unlink(missing_ok=True)
            self.incomplete_shard_path = None
            return
        except OSError:
            pass
        # If namespace operations both fail, a duplicate summary makes the
        # formal bytes ineligible. This remains writer-thread-only failure I/O.
        self._append_invalidation_to_path_in_writer(self.shard_path)

    def _append_timeout_invalidation_in_writer(self) -> None:
        """Make a late-written summary structurally ineligible as evidence."""

        try:
            raw = self._invalidation_summary_raw()
            self._write_reserved_control_via_in_writer(raw, self._write_persistent_all)
        except Exception:  # noqa: BLE001, S110 - quarantine already fails closed.
            pass
        profile = self._profile
        if profile is not None:
            try:
                raw = self._profile_invalidation_summary_raw()
                self._write_profile_reserved_control_via_in_writer(
                    raw, self._write_profile_persistent_all
                )
            except Exception:  # noqa: BLE001, S110 - pair already fails closed.
                pass

    def _append_invalidation_to_path_in_writer(self, path: Path) -> None:
        try:
            raw = self._invalidation_summary_raw()

            def write_path(accepted_raw: bytes) -> None:
                fd = -1
                try:
                    flags = os.O_APPEND | os.O_WRONLY
                    flags |= getattr(os, "O_CLOEXEC", 0)
                    fd = os.open(path, flags)
                    view = memoryview(accepted_raw)
                    while view:
                        written = os.write(fd, view)
                        if (
                            isinstance(written, bool)
                            or not isinstance(written, int)
                            or written <= 0
                            or written > len(view)
                        ):
                            raise OSError("invalidation writer made invalid progress")
                        view = view[written:]
                finally:
                    if fd >= 0:
                        try:
                            os.close(fd)
                        except OSError:
                            pass

            self._write_reserved_control_via_in_writer(raw, write_path)
        except Exception:  # noqa: BLE001, S110 - last-resort invalidation.
            pass

    def _append_profile_invalidation_to_path_in_writer(self, path: Path) -> None:
        try:
            raw = self._profile_invalidation_summary_raw()

            def write_path(accepted_raw: bytes) -> None:
                fd = -1
                try:
                    flags = os.O_APPEND | os.O_WRONLY
                    flags |= getattr(os, "O_CLOEXEC", 0)
                    fd = os.open(path, flags)
                    view = memoryview(accepted_raw)
                    while view:
                        written = os.write(fd, view)
                        if (
                            isinstance(written, bool)
                            or not isinstance(written, int)
                            or written <= 0
                            or written > len(view)
                        ):
                            raise OSError("profile invalidation made invalid progress")
                        view = view[written:]
                finally:
                    if fd >= 0:
                        try:
                            os.close(fd)
                        except OSError:
                            pass

            self._write_profile_reserved_control_via_in_writer(raw, write_path)
        except Exception:  # noqa: BLE001, S110 - last-resort invalidation.
            pass

    def _invalidation_summary_raw(self) -> bytes:
        invalidating_summary = build_process_summary_record(
            process_uuid=self.process_uuid,
            ended_timestamp_ns=self._clock_ns(),
            attempted_data_count=self._attempted_data_count,
            written_event_count=self._written_event_count,
            written_edge_count=self._written_edge_count,
            written_loss_interval_count=self._written_loss_interval_count,
            dropped_data_count=self._dropped_data_count,
            dropped_control_count=self._dropped_control_count,
            writer_failure_count=self._writer_failure_count,
            close_outcome="timeout",
            content_sha256=self._content_hash.hexdigest(),
        )
        return canonical_json_line(invalidating_summary)

    def _profile_invalidation_summary_raw(self) -> bytes:
        profile = self._profile
        if profile is None or profile.content_hash is None:
            raise OSError("profile state is unavailable")
        summary = build_profile_summary_record(
            process_uuid=self.process_uuid,
            config=profile.config,
            ended_timestamp_ns=self._clock_ns(),
            attempted_data_count=profile.attempted_data_count,
            written_counts={
                "block_set_chunk": profile.written_block_set_chunk_count,
                "wait_set_chunk": profile.written_wait_set_chunk_count,
                "transfer_event": profile.written_transfer_event_count,
                "recovery_event": profile.written_recovery_event_count,
            },
            written_loss_interval_count=profile.written_loss_interval_count,
            dropped_data_count=profile.dropped_data_count,
            dropped_control_count=profile.dropped_control_count,
            writer_failure_count=profile.writer_failure_count,
            close_outcome="timeout",
            content_sha256=profile.content_hash.hexdigest(),
        )
        return profile_record_line(summary)

    def _write_reserved_control_in_writer(
        self, raw: bytes, *, count_drop: bool = True
    ) -> bool:
        return self._write_reserved_control_via_in_writer(
            raw, self._write_all, count_drop=count_drop
        )

    def _write_reserved_control_via_in_writer(
        self,
        raw: bytes,
        write_raw: Callable[[bytes], None],
        *,
        count_drop: bool = True,
    ) -> bool:
        with self._condition:
            if (
                self._reserved_queued >= RESERVED_CAPACITY_RECORDS
                or self._queued_bytes + len(raw) > MAX_QUEUED_BYTES
            ):
                if count_drop:
                    self._dropped_control_count += 1
                return False
            self._reserved_queued += 1
            self._queued_bytes += len(raw)
        try:
            write_raw(raw)
        except Exception:
            if count_drop:
                with self._condition:
                    self._dropped_control_count += 1
            raise
        finally:
            with self._condition:
                if self._reserved_queued > 0:
                    self._reserved_queued -= 1
                self._queued_bytes = max(0, self._queued_bytes - len(raw))
        return True

    def _write_profile_reserved_control_in_writer(
        self, raw: bytes, *, count_drop: bool = True
    ) -> bool:
        return self._write_profile_reserved_control_via_in_writer(
            raw, self._write_profile_all, count_drop=count_drop
        )

    def _write_profile_reserved_control_via_in_writer(
        self,
        raw: bytes,
        write_raw: Callable[[bytes], None],
        *,
        count_drop: bool = True,
    ) -> bool:
        profile = self._profile
        if profile is None:
            return False
        with self._condition:
            if (
                profile.reserved_queued >= RESERVED_CAPACITY_RECORDS
                or profile.queued_bytes + len(raw) > MAX_QUEUED_BYTES
            ):
                if count_drop:
                    profile.dropped_control_count += 1
                return False
            profile.reserved_queued += 1
            profile.queued_bytes += len(raw)
        try:
            write_raw(raw)
        except Exception:
            if count_drop:
                with self._condition:
                    profile.dropped_control_count += 1
            raise
        finally:
            with self._condition:
                if profile.reserved_queued > 0:
                    profile.reserved_queued -= 1
                profile.queued_bytes = max(0, profile.queued_bytes - len(raw))
        return True

    def _prepare_timeout_controls_locked(self) -> list[_QueuedRecord]:
        timeout_observed_ns = time.monotonic_ns()
        pending = [*self._inflight_batch, *self._queue]
        existing_controls = [
            queued for queued in pending if queued.record_type == "loss_interval"
        ]
        base_data = [
            queued
            for queued in pending
            if queued.stream == "base" and queued.record_type in {"event", "edge"}
        ]
        profile_types = {
            "block_set_chunk",
            "wait_set_chunk",
            "transfer_event",
            "recovery_event",
        }
        profile_data = [
            queued
            for queued in pending
            if queued.stream == "profile" and queued.record_type in profile_types
        ]
        recognized = {
            *map(id, existing_controls),
            *map(id, base_data),
            *map(id, profile_data),
        }
        for queued in pending:
            if id(queued) not in recognized:
                if queued.stream == "profile" and self._profile is not None:
                    self._profile.dropped_control_count += 1
                else:
                    self._dropped_control_count += 1
        self._inflight_batch.clear()
        self._queue.clear()
        self._queued_bytes = 0
        self._ordinary_queued = 0
        self._reserved_queued = 0
        if self._profile is not None:
            self._profile.queued_bytes = 0
            self._profile.ordinary_queued = 0
            self._profile.reserved_queued = 0

        controls: list[_QueuedRecord] = []
        control_bytes = {"base": 0, "profile": 0}
        control_counts = {"base": 0, "profile": 0}

        def admit_control(queued: _QueuedRecord) -> None:
            stream = queued.stream
            if (
                control_counts[stream] >= RESERVED_CAPACITY_RECORDS
                or control_bytes[stream] + len(queued.raw) > MAX_QUEUED_BYTES
            ):
                if stream == "profile" and self._profile is not None:
                    self._profile.dropped_control_count += 1
                else:
                    self._dropped_control_count += 1
                return
            controls.append(queued)
            control_counts[stream] += 1
            control_bytes[stream] += len(queued.raw)

        for queued in existing_controls:
            admit_control(queued)
        for stream, pending_data in (("base", base_data), ("profile", profile_data)):
            group: list[_QueuedRecord] = []
            for queued in pending_data:
                if (
                    group
                    and queued.record_seq is not None
                    and group[-1].record_seq is not None
                    and queued.record_seq != group[-1].record_seq + 1
                ):
                    control = (
                        self._timeout_profile_loss_control_locked(
                            group, timeout_observed_ns
                        )
                        if stream == "profile"
                        else self._timeout_loss_control_locked(
                            group, timeout_observed_ns
                        )
                    )
                    if control is not None:
                        admit_control(control)
                    group = []
                group.append(queued)
            if group:
                control = (
                    self._timeout_profile_loss_control_locked(
                        group, timeout_observed_ns
                    )
                    if stream == "profile"
                    else self._timeout_loss_control_locked(group, timeout_observed_ns)
                )
                if control is not None:
                    admit_control(control)
        self._count_diagnostic_locked("close_timeout")
        self._writer_outcome = "timeout"
        self._inflight_batch = list(controls)
        self._reserved_queued = control_counts["base"]
        self._queued_bytes = control_bytes["base"]
        if self._profile is not None:
            self._profile.reserved_queued = control_counts["profile"]
            self._profile.queued_bytes = control_bytes["profile"]
        return controls

    def _timeout_loss_control_locked(
        self, group: list[_QueuedRecord], timeout_observed_ns: int
    ) -> _QueuedRecord | None:
        first = group[0]
        last = group[-1]
        assert first.record_seq is not None
        assert last.record_seq is not None
        event_count = sum(item.record_type == "event" for item in group)
        edge_count = len(group) - event_count
        self._dropped_data_count += len(group)
        loss_seq = self._next_loss_interval_seq
        self._next_loss_interval_seq += 1
        try:
            record = build_loss_interval_record(
                process_uuid=self.process_uuid,
                loss_interval_seq=loss_seq,
                reason="close_timeout",
                first_dropped_record_seq=first.record_seq,
                last_dropped_record_seq=last.record_seq,
                event_count=event_count,
                edge_count=edge_count,
                first_observed_timestamp_ns=timeout_observed_ns,
                last_observed_timestamp_ns=timeout_observed_ns,
            )
            return _QueuedRecord(
                canonical_json_line(record), "loss_interval", None, True, None
            )
        except Exception:  # noqa: BLE001 - control loss invalidates evidence.
            self._dropped_control_count += 1
            return None

    def _timeout_profile_loss_control_locked(
        self, group: list[_QueuedRecord], timeout_observed_ns: int
    ) -> _QueuedRecord | None:
        profile = self._profile
        if profile is None:
            return None
        first = group[0]
        last = group[-1]
        assert first.record_seq is not None and last.record_seq is not None
        counts: dict[ProfileRecordType, int] = {
            "block_set_chunk": 0,
            "wait_set_chunk": 0,
            "transfer_event": 0,
            "recovery_event": 0,
        }
        for queued in group:
            if queued.record_type not in counts:
                profile.dropped_control_count += 1
                return None
            counts[queued.record_type] += 1  # type: ignore[literal-required]
        profile.dropped_data_count += len(group)
        loss_seq = profile.next_loss_interval_seq
        profile.next_loss_interval_seq += 1
        try:
            record = build_profile_loss_interval_record(
                process_uuid=self.process_uuid,
                config=profile.config,
                loss_interval_seq=loss_seq,
                reason="close_timeout",
                first_dropped_record_seq=first.record_seq,
                last_dropped_record_seq=last.record_seq,
                counts=counts,
                first_observed_timestamp_ns=timeout_observed_ns,
                last_observed_timestamp_ns=timeout_observed_ns,
            )
            return _QueuedRecord(
                profile_record_line(record),
                "loss_interval",
                None,
                True,
                None,
                "profile",
            )
        except Exception:  # noqa: BLE001 - control loss invalidates evidence.
            profile.dropped_control_count += 1
            return None

    def _close_cutoff_reached_locked(self) -> bool:
        return (
            self._closing
            and self._close_deadline_ns is not None
            and time.monotonic_ns() >= self._close_deadline_ns
            and bool(self._queue or self._inflight_batch)
        )

    def _close_deadline_reached(self) -> bool:
        return (
            self._close_deadline_ns is not None
            and time.monotonic_ns() >= self._close_deadline_ns
        )

    def _force_timeout_accounting_locked(self) -> None:
        if self._writer_outcome == "timeout":
            for queued in [*self._inflight_batch, *self._queue]:
                self._account_unwritten_queued_locked(queued)
            self._inflight_batch.clear()
            self._queue.clear()
            self._queued_bytes = 0
            self._ordinary_queued = 0
            self._reserved_queued = 0
            if self._profile is not None:
                self._profile.queued_bytes = 0
                self._profile.ordinary_queued = 0
                self._profile.reserved_queued = 0
            return
        for queued in [*self._inflight_batch, *self._queue]:
            self._account_unwritten_queued_locked(queued)
        self._inflight_batch.clear()
        self._queue.clear()
        self._queued_bytes = 0
        self._ordinary_queued = 0
        self._reserved_queued = 0
        if self._profile is not None:
            self._profile.queued_bytes = 0
            self._profile.ordinary_queued = 0
            self._profile.reserved_queued = 0
        self._writer_failed = True
        self._writer_outcome = "timeout"
        self._count_diagnostic_locked("close_timeout")

    def _account_unwritten_queued_locked(self, queued: _QueuedRecord) -> None:
        profile_types = {
            "block_set_chunk",
            "wait_set_chunk",
            "transfer_event",
            "recovery_event",
        }
        if queued.stream == "profile" and self._profile is not None:
            if queued.record_type in profile_types:
                self._profile.dropped_data_count += 1
            else:
                self._profile.dropped_control_count += 1
        elif queued.record_type in {"event", "edge"}:
            self._dropped_data_count += 1
        else:
            self._dropped_control_count += 1

    def _remove_failed_initialization_shard(self) -> None:
        self._close_profile_fd()
        self._close_fd()
        if self.process_uuid and self.shard_path != self.base_path:
            try:
                self.shard_path.unlink(missing_ok=True)
            except OSError:
                pass
        profile = self._profile
        if profile is not None and profile.shard_path != self.base_path:
            try:
                profile.shard_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _take_batch_locked(self) -> list[_QueuedRecord]:
        batch: list[_QueuedRecord] = []
        batch_bytes = 0
        while self._queue and len(batch) < MAX_BATCH_RECORDS:
            candidate = self._queue[0]
            if batch and batch_bytes + len(candidate.raw) > MAX_BATCH_BYTES:
                break
            queued = self._queue.popleft()
            batch.append(queued)
            batch_bytes += len(queued.raw)
        return batch

    def _record_written(self, queued: _QueuedRecord) -> None:
        with self._condition:
            if self._abandoned:
                return
            if not self._inflight_batch or self._inflight_batch[0] != queued:
                self._mark_writer_failure_locked()
                return
            self._inflight_batch.pop(0)
            if queued.stream == "profile":
                profile = self._profile
                if profile is None or profile.content_hash is None:
                    self._mark_writer_failure_locked()
                    return
                profile.queued_bytes -= len(queued.raw)
                if queued.reserved:
                    profile.reserved_queued -= 1
                else:
                    profile.ordinary_queued -= 1
                profile.content_hash.update(queued.raw)
                if queued.record_type == "block_set_chunk":
                    profile.written_block_set_chunk_count += 1
                elif queued.record_type == "wait_set_chunk":
                    profile.written_wait_set_chunk_count += 1
                elif queued.record_type == "transfer_event":
                    profile.written_transfer_event_count += 1
                elif queued.record_type == "recovery_event":
                    profile.written_recovery_event_count += 1
                elif queued.record_type == "loss_interval":
                    profile.written_loss_interval_count += 1
            else:
                self._queued_bytes -= len(queued.raw)
                if queued.reserved:
                    self._reserved_queued -= 1
                else:
                    self._ordinary_queued -= 1
                self._content_hash.update(queued.raw)
                if queued.record_type == "event":
                    self._written_event_count += 1
                elif queued.record_type == "edge":
                    self._written_edge_count += 1
                elif queued.record_type == "loss_interval":
                    self._written_loss_interval_count += 1

    def _mark_writer_failure(self) -> None:
        with self._condition:
            self._mark_writer_failure_locked()

    def _mark_writer_failure_locked(self) -> None:
        self._writer_failure_count += 1
        if self._profile is not None:
            self._profile.writer_failure_count += 1
        self._writer_failed = True
        self._count_diagnostic_locked("writer_failure")
        for queued in [*self._inflight_batch, *self._queue]:
            self._account_unwritten_queued_locked(queued)
        self._inflight_batch.clear()
        self._queue.clear()
        self._queued_bytes = 0
        self._ordinary_queued = 0
        self._reserved_queued = 0
        if self._profile is not None:
            self._profile.queued_bytes = 0
            self._profile.ordinary_queued = 0
            self._profile.reserved_queued = 0
        self._condition.notify_all()

    def _write_queued_all(self, queued: _QueuedRecord) -> None:
        if queued.stream == "profile":
            self._write_profile_all(queued.raw)
        else:
            self._write_all(queued.raw)

    def _write_all(self, raw: bytes) -> None:
        with self._condition:
            if self._abandoned:
                raise OSError("trace writer was abandoned at close timeout")
        if not self._uses_native_write:
            self._exercise_injected_write(raw)
            with self._condition:
                if self._abandoned:
                    raise OSError("trace writer was abandoned at close timeout")
        self._write_persistent_all(raw)

    def _exercise_injected_write(self, raw: bytes) -> None:
        # A custom write seam runs against one anonymous writer-owned staging
        # fd. Blocking/fault injection therefore cannot append to the formal
        # shard after close has timed out. The production os.write path avoids
        # this extra copy entirely.
        if self._staging_fd < 0:
            if hasattr(os, "memfd_create"):
                self._staging_fd = os.memfd_create(
                    "rlp-write-stage", getattr(os, "MFD_CLOEXEC", 0)
                )
            else:
                self._staging_fd, staging_path = tempfile.mkstemp(
                    prefix="rlp-write-stage-"
                )
                Path(staging_path).unlink(missing_ok=True)
        os.ftruncate(self._staging_fd, 0)
        os.lseek(self._staging_fd, 0, os.SEEK_SET)
        view = memoryview(raw)
        while view:
            written = self._write_function(self._staging_fd, view)
            if (
                isinstance(written, bool)
                or not isinstance(written, int)
                or written <= 0
                or written > len(view)
            ):
                raise OSError("writer made invalid progress")
            view = view[written:]
        os.lseek(self._staging_fd, 0, os.SEEK_SET)
        staged = bytearray()
        while len(staged) < len(raw):
            chunk = os.read(self._staging_fd, len(raw) - len(staged))
            if not chunk:
                break
            staged.extend(chunk)
        if bytes(staged) != raw:
            raise OSError("staged writer bytes do not match the record")

    def _write_persistent_all(self, raw: bytes) -> None:
        view = memoryview(raw)
        while view:
            written = os.write(self._fd, view)
            if (
                isinstance(written, bool)
                or not isinstance(written, int)
                or written <= 0
                or written > len(view)
            ):
                raise OSError("persistent writer made invalid progress")
            view = view[written:]

    def _write_profile_all(self, raw: bytes) -> None:
        with self._condition:
            if self._abandoned:
                raise OSError("trace writer was abandoned at close timeout")
        if not self._uses_native_write:
            self._exercise_injected_write(raw)
            with self._condition:
                if self._abandoned:
                    raise OSError("trace writer was abandoned at close timeout")
        self._write_profile_persistent_all(raw)

    def _write_profile_persistent_all(self, raw: bytes) -> None:
        profile = self._profile
        if profile is None or profile.fd < 0:
            raise OSError("profile writer descriptor is unavailable")
        view = memoryview(raw)
        while view:
            written = os.write(profile.fd, view)
            if (
                isinstance(written, bool)
                or not isinstance(written, int)
                or written <= 0
                or written > len(view)
            ):
                raise OSError("persistent profile writer made invalid progress")
            view = view[written:]

    def _counts_reconcile(self) -> bool:
        base_reconciles = self._attempted_data_count == (
            self._written_event_count
            + self._written_edge_count
            + self._dropped_data_count
        )
        profile = self._profile
        if profile is None:
            return base_reconciles
        profile_reconciles = profile.attempted_data_count == (
            profile.written_block_set_chunk_count
            + profile.written_wait_set_chunk_count
            + profile.written_transfer_event_count
            + profile.written_recovery_event_count
            + profile.dropped_data_count
        )
        return base_reconciles and profile_reconciles

    def _result(self, close_outcome: str, summary_written: bool) -> CloseResult:
        profile = self._profile
        return CloseResult(
            close_outcome=close_outcome,
            summary_written=summary_written,
            attempted_data_count=self._attempted_data_count,
            written_event_count=self._written_event_count,
            written_edge_count=self._written_edge_count,
            dropped_data_count=self._dropped_data_count,
            dropped_control_count=self._dropped_control_count,
            profile_summary_written=(
                bool(profile.summary_written) if profile is not None else False
            ),
            profile_attempted_data_count=(
                profile.attempted_data_count if profile is not None else 0
            ),
            profile_dropped_data_count=(
                profile.dropped_data_count if profile is not None else 0
            ),
            profile_dropped_control_count=(
                profile.dropped_control_count if profile is not None else 0
            ),
        )

    def _count_diagnostic_locked(self, reason: str) -> None:
        if reason not in _DIAGNOSTIC_REASONS:
            reason = "schema_incompatible"
        self._diagnostic_counts[reason] = self._diagnostic_counts.get(reason, 0) + 1
        if (
            reason not in self._logged_diagnostics
            and reason not in self._pending_diagnostics
        ):
            # This set is bounded by the frozen ten-value diagnostic enum.
            # Producer threads only mark state and wake the exporter; arbitrary
            # logging handlers must never execute on the serving hot path.
            self._pending_diagnostics.add(reason)
            self._condition.notify()

    def _take_pending_diagnostics_locked(self) -> tuple[str, ...]:
        reasons = tuple(
            reason
            for reason in _DIAGNOSTIC_REASON_ORDER
            if reason in self._pending_diagnostics
        )
        self._pending_diagnostics.difference_update(reasons)
        self._logged_diagnostics.update(reasons)
        return reasons

    def _flush_diagnostics_in_writer(self) -> None:
        with self._condition:
            reasons = self._take_pending_diagnostics_locked()
        self._log_diagnostics_in_writer(reasons)

    @staticmethod
    def _log_diagnostics_in_writer(reasons: tuple[str, ...]) -> None:
        for reason in reasons:
            try:
                logger.warning("Request lifecycle tracing diagnostic: %s", reason)
            except Exception:  # noqa: BLE001, S110 - logging cannot break serving.
                pass

    def _usable_in_current_process(self) -> bool:
        if os.getpid() == self._owner_pid:
            return not self._closed
        self.detach_after_fork_child()
        return False

    def detach_after_fork_child(self) -> None:
        """Detach an inherited parent sink without touching inherited locks."""

        if self._forked:
            return
        self._forked = True
        self._abandoned = True
        self._closed = True
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1
        if self._staging_fd >= 0:
            try:
                os.close(self._staging_fd)
            except OSError:
                pass
            self._staging_fd = -1
        profile = self._profile
        if profile is not None and profile.fd >= 0:
            try:
                os.close(profile.fd)
            except OSError:
                pass
            profile.fd = -1
        self._queue = deque()
        self._inflight_batch = []
        self._pending_diagnostics = set()
        self._logged_diagnostics = set()
        self._queued_bytes = 0
        self._ordinary_queued = 0
        self._reserved_queued = 0
        if profile is not None:
            profile.queued_bytes = 0
            profile.ordinary_queued = 0
            profile.reserved_queued = 0
        # A lock may have been held by a vanished parent thread at fork.
        self._condition = threading.Condition()
        self._close_lock = threading.Lock()
        self._quarantine_lock = threading.Lock()
        self._writer_ready = threading.Event()
        child_result = self._result("writer_failure", summary_written=False)
        self._completion_claim = {"result": child_result}
        self._close_result = child_result
        self._atexit_registered = False

    def _close_fd(self) -> bool:
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except Exception:  # noqa: BLE001 - shutdown is fail-open.
                return False
            finally:
                self._fd = -1
        return True

    def _close_profile_fd(self) -> bool:
        profile = self._profile
        if profile is not None and profile.fd >= 0:
            try:
                os.close(profile.fd)
            except Exception:  # noqa: BLE001 - shutdown is fail-open.
                return False
            finally:
                profile.fd = -1
        return True

    def _close_staging_fd(self) -> bool:
        if self._staging_fd >= 0:
            try:
                os.close(self._staging_fd)
            except Exception:  # noqa: BLE001 - shutdown is fail-open.
                return False
            finally:
                self._staging_fd = -1
        return True

    def _unregister_atexit(self) -> None:
        if self._atexit_registered:
            try:
                atexit.unregister(self.close)
            finally:
                self._atexit_registered = False


class NullTraceSink:
    def __init__(self, reason_code: str | None = None) -> None:
        self.reason_code = reason_code
        self.shard_path: Path | None = None

    @property
    def committed_shard_path(self) -> None:
        return None

    @property
    def committed_kv_recovery_profile_shard_path(self) -> None:
        return None

    def new_trace_id(self) -> None:
        return None

    def new_span_id(self) -> None:
        return None

    def write_event(self, draft: EventDraft) -> None:
        del draft

    def write_edge(self, draft: EdgeDraft) -> None:
        del draft

    def write_kv_recovery_profile(
        self, record_type: ProfileRecordType, timestamp_ns: int, **fields: object
    ) -> None:
        del record_type, timestamp_ns, fields

    def drop_kv_recovery_profile(
        self,
        record_type: ProfileRecordType,
        timestamp_ns: int | None,
        reason: ProfileLossReason = "serialization_failure",
    ) -> None:
        del record_type, timestamp_ns, reason

    def close(self) -> None:
        return None


class RuntimeLifecycleHooks:
    """Fail-open v1 facade used by thin runtime call sites."""

    def __init__(
        self,
        config: RuntimeTraceConfig,
        sink: JsonlTraceSink | NullTraceSink | None = None,
    ) -> None:
        self.config = config
        self._owner_pid = os.getpid()
        self._state_lock = threading.Lock()
        self._diagnostic_lock = threading.Lock()
        self._pending_reasons: set[str] = set()
        self._logged_reasons: set[str] = set()
        self._needs_reinitialize_after_fork = False
        if sink is not None:
            self._sink = sink
        elif not config.requested:
            self._sink = NullTraceSink()
        elif not config.enabled:
            self._log_disabled_once(config.invalid_reason or "schema_incompatible")
            self._sink = NullTraceSink(config.invalid_reason or "schema_incompatible")
        else:
            try:
                assert config.export_path is not None
                assert config.provenance is not None
                self._sink = JsonlTraceSink(
                    config.export_path,
                    config.provenance,
                    communication_mode=config.communication_mode,
                    kv_recovery_profile_config=config.kv_recovery_profile_config,
                )
            except Exception:  # noqa: BLE001 - initialization is fail-open.
                self._log_disabled_once("init_failure")
                self._sink = NullTraceSink("init_failure")
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._after_fork_child)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> RuntimeLifecycleHooks:
        return cls(RuntimeTraceConfig.from_env(env))

    @property
    def enabled(self) -> bool:
        return isinstance(self._current_sink(), JsonlTraceSink)

    @property
    def shard_path(self) -> Path | None:
        return self._current_sink().shard_path

    @property
    def committed_shard_path(self) -> Path | None:
        """Receipt-gated path for the explicit run manifest."""

        return self._current_sink().committed_shard_path

    @property
    def committed_kv_recovery_profile_shard_path(self) -> Path | None:
        """Receipt-gated paired profile path for the run manifest."""

        return self._current_sink().committed_kv_recovery_profile_shard_path

    @property
    def kv_recovery_profile_enabled(self) -> bool:
        sink = self._current_sink()
        return isinstance(sink, JsonlTraceSink) and sink.kv_recovery_profile_enabled

    @property
    def kv_recovery_profile_evidence_complete(self) -> bool:
        sink = self._current_sink()
        return (
            isinstance(sink, JsonlTraceSink)
            and sink.kv_recovery_profile_evidence_complete
        )

    @property
    def kv_recovery_profile_attempted_data_count(self) -> int:
        sink = self._current_sink()
        return (
            sink.kv_recovery_profile_attempted_data_count
            if isinstance(sink, JsonlTraceSink)
            else 0
        )

    def kv_recovery_profile_snapshot(
        self,
    ) -> tuple[tuple[ProfileRecord, ...], tuple[ProfileLossInterval, ...]]:
        sink = self._current_sink()
        return (
            sink.kv_recovery_profile_snapshot()
            if isinstance(sink, JsonlTraceSink)
            else ((), ())
        )

    @property
    def process_uuid(self) -> str | None:
        """Return the current exporter process identity when enabled."""

        sink = self._current_sink()
        return sink.process_uuid if isinstance(sink, JsonlTraceSink) else None

    @property
    def clock_domain_id(self) -> str | None:
        """Return the current exporter clock identity when enabled."""

        sink = self._current_sink()
        return sink.clock_domain_id if isinstance(sink, JsonlTraceSink) else None

    def new_trace_id(self) -> str | None:
        try:
            return self._current_sink().new_trace_id()
        except Exception:  # noqa: BLE001 - identity allocation is fail-open.
            self._defer_diagnostic("serialization_failure")
            return None

    def new_span_id(self) -> str | None:
        try:
            return self._current_sink().new_span_id()
        except Exception:  # noqa: BLE001 - identity allocation is fail-open.
            self._defer_diagnostic("serialization_failure")
            return None

    def emit_event(self, draft: EventDraft) -> RecordRef | None:
        try:
            return self._current_sink().write_event(draft)
        except Exception:  # noqa: BLE001 - runtime emission is fail-open.
            self._defer_diagnostic("serialization_failure")
            return None

    def emit_edge(self, draft: EdgeDraft) -> RecordRef | None:
        try:
            return self._current_sink().write_edge(draft)
        except Exception:  # noqa: BLE001 - runtime emission is fail-open.
            self._defer_diagnostic("serialization_failure")
            return None

    def emit_kv_recovery_profile(
        self,
        record_type: ProfileRecordType,
        timestamp_ns: int,
        **fields: object,
    ) -> ProfileRecordRef | None:
        try:
            return self._current_sink().write_kv_recovery_profile(
                record_type, timestamp_ns, **fields
            )
        except Exception:  # noqa: BLE001 - runtime emission is fail-open.
            self._defer_diagnostic("serialization_failure")
            return None

    def drop_kv_recovery_profile(
        self,
        record_type: ProfileRecordType,
        timestamp_ns: int | None,
        reason: ProfileLossReason = "serialization_failure",
    ) -> int | None:
        try:
            return self._current_sink().drop_kv_recovery_profile(
                record_type, timestamp_ns, reason
            )
        except Exception:  # noqa: BLE001 - runtime emission is fail-open.
            self._defer_diagnostic("serialization_failure")
            return None

    def close(self) -> CloseResult | None:
        try:
            result = self._current_sink().close()
        except Exception:  # noqa: BLE001 - runtime close is fail-open.
            # A public close boundary must not run an arbitrary logging handler
            # after its bounded drain wait. Initialization/bootstrap diagnostics
            # remain synchronous; active exporter failures are logged by writer.
            self._mark_disabled_once("writer_failure")
            return None
        if not isinstance(result, CloseResult):
            return None
        return result

    def reinitialize_after_fork(self) -> bool:
        """Create the child process's independent shard at worker bootstrap.

        This method is intentionally explicit: opening a shard from the first
        event-emission hot path would violate the frozen no-I/O producer rule.
        """

        self._ensure_process_state()
        if not self._needs_reinitialize_after_fork:
            return isinstance(self._sink, JsonlTraceSink)
        with self._state_lock:
            if not self._needs_reinitialize_after_fork:
                return isinstance(self._sink, JsonlTraceSink)
            if not self.config.enabled:
                self._needs_reinitialize_after_fork = False
                return False
            try:
                assert self.config.export_path is not None
                assert self.config.provenance is not None
                self._sink = JsonlTraceSink(
                    self.config.export_path,
                    self.config.provenance,
                    communication_mode=self.config.communication_mode,
                    kv_recovery_profile_config=(self.config.kv_recovery_profile_config),
                )
            except Exception:  # noqa: BLE001 - worker bootstrap is fail-open.
                self._sink = NullTraceSink("init_failure")
                self._log_disabled_once("init_failure")
                self._needs_reinitialize_after_fork = False
                return False
            self._needs_reinitialize_after_fork = False
            return True

    def __enter__(self) -> RuntimeLifecycleHooks:  # noqa: PYI034 - Python 3.10.
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def _current_sink(self) -> JsonlTraceSink | NullTraceSink:
        self._ensure_process_state()
        return self._sink

    def _ensure_process_state(self) -> None:
        if os.getpid() != self._owner_pid:
            self._after_fork_child()

    def _after_fork_child(self) -> None:
        sink = self._sink
        if isinstance(sink, JsonlTraceSink):
            sink.detach_after_fork_child()
        self._sink = NullTraceSink()
        self._owner_pid = os.getpid()
        self._needs_reinitialize_after_fork = self.config.enabled
        # Never acquire inherited locks: a vanished parent thread may own one.
        self._state_lock = threading.Lock()
        self._diagnostic_lock = threading.Lock()
        self._pending_reasons = set()
        self._logged_reasons = set()

    def _mark_disabled_once(self, reason_code: str) -> None:
        if reason_code not in _DIAGNOSTIC_REASONS:
            reason_code = "schema_incompatible"
        with self._diagnostic_lock:
            if (
                reason_code in self._logged_reasons
                or reason_code in self._pending_reasons
            ):
                return
            # Bounded by the same frozen ten-value enum as exporter diagnostics.
            self._pending_reasons.add(reason_code)

    def _defer_diagnostic(self, reason_code: str) -> None:
        sink = self._sink
        if isinstance(sink, JsonlTraceSink):
            sink.defer_diagnostic(reason_code)
        else:
            self._mark_disabled_once(reason_code)

    def _log_disabled_once(self, reason_code: str) -> None:
        self._mark_disabled_once(reason_code)
        self._flush_disabled_logs()

    def _flush_disabled_logs(self) -> None:
        with self._diagnostic_lock:
            reasons = tuple(
                reason
                for reason in _DIAGNOSTIC_REASON_ORDER
                if reason in self._pending_reasons
            )
            self._pending_reasons.difference_update(reasons)
            self._logged_reasons.update(reasons)
        for reason_code in reasons:
            try:
                logger.warning("Request lifecycle tracing disabled: %s", reason_code)
            except Exception:  # noqa: BLE001, S110 - logging cannot break serving.
                pass
