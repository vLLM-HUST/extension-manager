from __future__ import annotations

import logging
import os
import secrets

from vllm_request_lifecycle_profiler.runtime_hooks import RuntimeLifecycleHooks
from vllm_request_lifecycle_profiler.runtime_protocol import (
    KV_RECOVERY_COMMUNICATION_MODE,
)

logger = logging.getLogger(__name__)

_REGISTERED_PID: int | None = None
_RUNTIME_HOOKS: RuntimeLifecycleHooks | None = None
_RUNTIME_BRIDGE: object | None = None
_OBSERVER_FACTORY: object | None = None
_LIFECYCLE_OBSERVER: object | None = None
_NATIVE_EVENT_BUS: object | None = None
_NATIVE_EVENT_SINK: object | None = None


def register_plugin() -> None:
    """Register the plugin.

    This function must be re-entrant because vLLM can load general plugins in
    multiple processes.
    """

    global _LIFECYCLE_OBSERVER, _NATIVE_EVENT_BUS, _NATIVE_EVENT_SINK
    global _OBSERVER_FACTORY, _REGISTERED_PID, _RUNTIME_BRIDGE, _RUNTIME_HOOKS
    process_id = os.getpid()
    if _REGISTERED_PID == process_id:
        return

    try:
        from vllm.v1.events import (
            REQUEST_LIFECYCLE_EVENTS_API_VERSION,
            EventBus,
            RequestFinished,
            RequestKvReclaimed,
            RequestPreempted,
        )
    except Exception as error:
        raise RuntimeError(
            "request lifecycle profiler requires vLLM-HUST "
            "request-lifecycle-events v1"
        ) from error
    if REQUEST_LIFECYCLE_EVENTS_API_VERSION != "1.0":
        raise RuntimeError(
            "unsupported vLLM-HUST request-lifecycle-events API: "
            f"{REQUEST_LIFECYCLE_EVENTS_API_VERSION!r}; expected '1.0'"
        )

    hooks = RuntimeLifecycleHooks.from_env()
    from vllm_request_lifecycle_profiler.native_event_bus import (
        NativeLifecycleEventSink,
        native_evidence_emitter,
    )

    inherited_sink = _NATIVE_EVENT_SINK
    inherited_bus = _NATIVE_EVENT_BUS
    if inherited_sink is not None and inherited_bus is not None:
        inherited_bus.unregister_sink(inherited_sink)
    run_id = os.getenv("VLLM_ECPA_LAUNCH_ID") or hooks.process_uuid or secrets.token_hex(16)
    native_sink = NativeLifecycleEventSink(
        hooks,
        run_id,
        finished_type=RequestFinished,
        preempted_type=RequestPreempted,
        reclaimed_type=RequestKvReclaimed,
        evidence_emitter=native_evidence_emitter,
    )
    EventBus.register_sink(native_sink)
    _NATIVE_EVENT_BUS = EventBus
    _NATIVE_EVENT_SINK = native_sink
    bridge = None
    if (
        hooks.enabled
        and hooks.config.communication_mode == KV_RECOVERY_COMMUNICATION_MODE
        and hooks.config.kv_recovery_profile_config is not None
    ):
        try:
            from vllm.v1.kv_recovery_profile import (
                register_kv_recovery_observer_factory,
            )

            from vllm_request_lifecycle_profiler.kv_recovery_runtime import (
                KVRecoveryObserverFactoryAdapter,
                KVRecoveryRuntimeABI,
                RuntimeBaseLifecycleBridge,
            )

            profile_config = hooks.config.kv_recovery_profile_config
            bridge = RuntimeBaseLifecycleBridge(hooks)
            factory = KVRecoveryObserverFactoryAdapter(
                profile_config.run_id,
                hooks,
                bridge,
                KVRecoveryRuntimeABI.load(),
            )
            register_kv_recovery_observer_factory(factory)
            _RUNTIME_BRIDGE = bridge
            _OBSERVER_FACTORY = factory
            logger.info("Registered the optional KV-recovery profiler.")
        except Exception:
            logger.exception("Failed to register the optional KV-recovery profiler.")

    if hooks.enabled:
        try:
            from vllm_request_lifecycle_profiler.issue19_lifecycle import (
                Issue19LifecycleObserver,
            )
            from vllm_request_lifecycle_profiler.kv_recovery_runtime import (
                RuntimeBaseLifecycleBridge,
            )

            if bridge is None:
                bridge = RuntimeBaseLifecycleBridge(hooks)
                _RUNTIME_BRIDGE = bridge
            run_id = (
                hooks.config.kv_recovery_profile_config.run_id
                if hooks.config.kv_recovery_profile_config is not None
                else hooks.process_uuid
            )
            if run_id is not None:
                _LIFECYCLE_OBSERVER = Issue19LifecycleObserver(hooks, bridge, run_id)
        except Exception:
            logger.exception("Failed to register the optional lifecycle observer.")

    _RUNTIME_HOOKS = hooks
    _REGISTERED_PID = process_id


def close_native_event_sink() -> None:
    """Unregister the process-local native sink without owning host shutdown."""

    global _NATIVE_EVENT_BUS, _NATIVE_EVENT_SINK
    event_bus = _NATIVE_EVENT_BUS
    sink = _NATIVE_EVENT_SINK
    if event_bus is not None and sink is not None:
        try:
            event_bus.unregister_sink(sink)
        except Exception:
            logger.debug("Failed to unregister native lifecycle sink", exc_info=True)
    _NATIVE_EVENT_BUS = None
    _NATIVE_EVENT_SINK = None


def get_native_event_sink() -> object | None:
    """Return the registered process-local EventBus sink."""

    return _NATIVE_EVENT_SINK


def get_lifecycle_observer() -> object | None:
    """Return the process-local observer created by normal plugin loading."""

    register_plugin()
    return _LIFECYCLE_OBSERVER


def close_engine_failure_observers() -> None:
    """Commit process-local profiler shards before EngineCore death is sent."""

    factory = _OBSERVER_FACTORY
    callback = getattr(factory, "close_for_engine_failure", None)
    if callable(callback):
        callback()
