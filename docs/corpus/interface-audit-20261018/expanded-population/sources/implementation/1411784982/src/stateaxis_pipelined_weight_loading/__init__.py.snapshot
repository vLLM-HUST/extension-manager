"""Pinned contract for artifact-bound StateAxis pipelined weight loading."""

from dataclasses import dataclass

MOD_ID = "org.vllm-hust.stateaxis-pipelined-weight-loading"


@dataclass(frozen=True, slots=True)
class PipelinedWeightLoadingConfig:
    enabled: bool = True
    qwen2_only: bool = True
    candidate_policy: str = "pinned_double_buffer_async_v1"
    serial_default_when_disabled: bool = True
    staging_slots: int = 2
    chunk_bytes: int = 64 * 1024 * 1024
    pack_alignment: int = 4096
    incremental_full_byte_sha256: bool = True
    event_guarded_slot_reuse: bool = True
    execution_artifact_plan_digest_bound: bool = True
    packed_weights_root_bound: bool = True
    transactional_ready: bool = True
    fail_closed: bool = True

    def __post_init__(self) -> None:
        flags = (
            self.enabled,
            self.qwen2_only,
            self.serial_default_when_disabled,
            self.incremental_full_byte_sha256,
            self.event_guarded_slot_reuse,
            self.execution_artifact_plan_digest_bound,
            self.packed_weights_root_bound,
            self.transactional_ready,
            self.fail_closed,
        )
        if (
            not all(flags)
            or self.candidate_policy != "pinned_double_buffer_async_v1"
            or self.staging_slots != 2
            or self.chunk_bytes != 64 * 1024 * 1024
            or self.pack_alignment != 4096
        ):
            raise ValueError(
                "pipelined-weight-loading 0.2.0 requires the complete "
                "artifact-bound two-slot async contract"
            )


def pipelined_weight_loading() -> PipelinedWeightLoadingConfig:
    return PipelinedWeightLoadingConfig()


__all__ = [
    "MOD_ID",
    "PipelinedWeightLoadingConfig",
    "pipelined_weight_loading",
]
