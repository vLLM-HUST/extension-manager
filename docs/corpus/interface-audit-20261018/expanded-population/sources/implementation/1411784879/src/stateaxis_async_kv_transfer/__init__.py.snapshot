"""Activation contract for bounded asynchronous KV restore in StateAxis."""

from __future__ import annotations

from dataclasses import dataclass

MOD_ID = "org.vllm-hust.stateaxis-async-kv-transfer"


@dataclass(frozen=True, slots=True)
class AsyncKvTransferConfig:
    """The only bounded configuration accepted by the StateAxis host."""

    enabled: bool = True
    max_pending_keys: int = 64
    max_correlations: int = 64
    max_retries: int = 0
    generation_bound: bool = True
    snapshot_sha256_required: bool = True
    transactional_restore: bool = True
    serialized_completion: bool = True
    fail_closed: bool = True

    def __post_init__(self) -> None:
        if self != AsyncKvTransferConfig.__new_default():
            raise ValueError("async KV transfer requires the reviewed bounded contract")

    @classmethod
    def __new_default(cls) -> AsyncKvTransferConfig:
        instance = object.__new__(cls)
        for field, value in (
            ("enabled", True),
            ("max_pending_keys", 64),
            ("max_correlations", 64),
            ("max_retries", 0),
            ("generation_bound", True),
            ("snapshot_sha256_required", True),
            ("transactional_restore", True),
            ("serialized_completion", True),
            ("fail_closed", True),
        ):
            object.__setattr__(instance, field, value)
        return instance


def async_kv_transfer() -> AsyncKvTransferConfig:
    """Return the default-off candidate's admitted ON configuration."""

    return AsyncKvTransferConfig()


__all__ = ["MOD_ID", "AsyncKvTransferConfig", "async_kv_transfer"]
