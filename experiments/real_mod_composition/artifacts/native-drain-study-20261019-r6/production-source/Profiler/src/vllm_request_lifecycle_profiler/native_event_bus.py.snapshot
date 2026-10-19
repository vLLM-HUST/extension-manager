"""Adapter for the native vLLM-HUST request-lifecycle event bus."""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from dataclasses import dataclass

from vllm_request_lifecycle_profiler.runtime_hooks import (
    CloseResult,
    RuntimeLifecycleHooks,
)
from vllm_request_lifecycle_profiler.runtime_protocol import EventDraft

EvidenceEmitter = Callable[[str, str], bool]


@dataclass(frozen=True)
class NativeEventSnapshot:
    event_count: int
    finished_count: int
    preempted_count: int
    reclaimed_count: int


class NativeLifecycleEventSink:
    """Observe typed host events without taking scheduler ownership."""

    def __init__(
        self,
        hooks: RuntimeLifecycleHooks,
        run_id: str,
        *,
        finished_type: type,
        preempted_type: type,
        reclaimed_type: type,
        evidence_emitter: EvidenceEmitter | None = None,
    ) -> None:
        self._hooks = hooks
        self._run_id = run_id
        self._finished_type = finished_type
        self._preempted_type = preempted_type
        self._reclaimed_type = reclaimed_type
        self._evidence_emitter = evidence_emitter
        self._lock = threading.Lock()
        self._event_count = 0
        self._finished_count = 0
        self._preempted_count = 0
        self._reclaimed_count = 0

    def close(self) -> CloseResult | None:
        """Return the original process-local exporter's bounded drain result.

        No hook is registered or initialized here. RuntimeLifecycleHooks.close
        retains its existing two-second bound, concurrency and loss accounting.
        None/timeout/failure is not a successful drain.
        """
        return self._hooks.close()

    def emit(self, event: object) -> None:
        """Consume one host-owned event; all observation failures fail open."""

        try:
            event_name, request_id, draft = self._translate(event)
        except Exception:  # noqa: BLE001 - an observer cannot break scheduling.
            return
        if event_name is None or request_id is None:
            return

        try:
            if self._hooks.enabled and draft is not None:
                self._hooks.emit_event(draft)
            with self._lock:
                self._event_count += 1
                if event_name == "request_finished":
                    self._finished_count += 1
                elif event_name == "request_preempted":
                    self._preempted_count += 1
                else:
                    self._reclaimed_count += 1
            if self._evidence_emitter is not None:
                self._evidence_emitter(event_name, request_id)
        except Exception:  # noqa: BLE001 - evidence remains observational.
            return

    def snapshot(self) -> NativeEventSnapshot:
        with self._lock:
            return NativeEventSnapshot(
                event_count=self._event_count,
                finished_count=self._finished_count,
                preempted_count=self._preempted_count,
                reclaimed_count=self._reclaimed_count,
            )

    def _translate(
        self, event: object
    ) -> tuple[str | None, str | None, EventDraft | None]:
        if isinstance(event, self._finished_type):
            event_name = "request_finished"
            metadata = {
                "runtime_request_id": event.request_id,
                "session_present": event.session_id is not None,
                "prompt_tokens": event.prompt_tokens,
                "output_tokens": event.output_tokens,
                "sequence_tokens": event.sequence_tokens,
                "kv_blocks": event.kv_blocks,
                "kv_reclaim_deferred": event.kv_reclaim_deferred,
                "finished_reason": event.finished_reason,
            }
            observed_name = "request_finished_observed"
        elif isinstance(event, self._preempted_type):
            event_name = "request_preempted"
            metadata = {
                "runtime_request_id": event.request_id,
                "session_present": event.session_id is not None,
                "num_preemptions": event.num_preemptions,
                "kv_blocks": event.kv_blocks,
                "kv_reclaim_deferred": event.kv_reclaim_deferred,
            }
            observed_name = "request_preempted_observed"
        elif isinstance(event, self._reclaimed_type):
            if event.path not in {"immediate", "deferred"}:
                return None, None, None
            event_name = "request_kv_reclaimed"
            metadata = {
                "runtime_request_id": event.request_id,
                "session_present": event.session_id is not None,
                "kv_blocks": event.kv_blocks,
                "reclaim_path": event.path,
            }
            observed_name = "request_kv_reclaimed_observed"
        else:
            return None, None, None

        request_id = event.request_id
        if not isinstance(request_id, str) or not request_id:
            return None, None, None
        trace_id = hashlib.sha256(
            f"{self._run_id}\0{request_id}".encode()
        ).hexdigest()[:32]
        return (
            event_name,
            request_id,
            EventDraft(
                trace_id=trace_id,
                lifecycle_id=f"{trace_id}:e:0",
                parent_lifecycle_id=f"{trace_id}:r",
                scope="engine_sample",
                component="external_evidence",
                event_name=observed_name,
                timestamp_ns=event.ts_monotonic_ns,
                preemption_epoch=0,
                sample_index=0,
                metadata=metadata,
            ),
        )


def native_evidence_emitter(event_name: str, request_id: str) -> bool:
    """Emit a launch-bound receipt only after a real EventBus callback."""

    from vllm.plugins import DEFAULT_PLUGINS_GROUP
    from vllm.plugins.evidence import _emit_host_event

    occurrence_id = hashlib.sha256(
        f"{event_name}\0{request_id}".encode()
    ).hexdigest()
    return _emit_host_event(
        "effective",
        DEFAULT_PLUGINS_GROUP,
        "request_lifecycle_profiler",
        "vllm_request_lifecycle_profiler.plugin:register_plugin",
        detail=f"request-lifecycle-eventbus:{event_name}",
        occurrence_id=occurrence_id,
        observation_kind="runtime_effective",
    )


__all__ = [
    "NativeEventSnapshot",
    "NativeLifecycleEventSink",
    "native_evidence_emitter",
]
