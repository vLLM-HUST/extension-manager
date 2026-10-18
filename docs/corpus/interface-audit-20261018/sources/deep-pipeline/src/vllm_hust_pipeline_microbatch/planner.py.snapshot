# SPDX-License-Identifier: Apache-2.0
"""Pure cost model and microbatch assignment from legacy PR #135."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MicroBatchCostModel:
    p0: float
    p1: float
    p2: float
    p3: float
    p4: float
    p5: float
    pp_rank: int
    layer_num: int

    def __post_init__(self) -> None:
        if self.pp_rank < 0 or self.layer_num <= 0:
            raise ValueError("invalid pipeline rank/layer count")

    def predict(self, request_num: int, aggregated_ctx_length: int) -> float:
        if request_num < 0 or aggregated_ctx_length < 0:
            raise ValueError("microbatch dimensions cannot be negative")
        return (
            self.p0 * request_num * self.layer_num
            + self.p1 * request_num
            + self.p2 * aggregated_ctx_length * self.layer_num
            + self.p3 * aggregated_ctx_length
            + self.p4 * self.layer_num
            + self.p5
        )


@dataclass(frozen=True)
class RequestWork:
    request_id: str
    context_length: int

    def __post_init__(self) -> None:
        if not self.request_id or self.context_length <= 0:
            raise ValueError("invalid request work")


@dataclass(frozen=True)
class MicroBatchSnapshot:
    microbatch_id: int
    requests: tuple[RequestWork, ...] = ()

    @property
    def request_num(self) -> int:
        return len(self.requests)

    @property
    def aggregated_ctx_length(self) -> int:
        return sum(request.context_length for request in self.requests)


def worst_rank_cost(
    microbatch: MicroBatchSnapshot, models: tuple[MicroBatchCostModel, ...]
) -> float:
    if not models:
        raise ValueError("at least one rank-local cost model is required")
    return max(
        model.predict(microbatch.request_num, microbatch.aggregated_ctx_length)
        for model in models
    )


def assign_lowest_cost(
    request: RequestWork,
    microbatches: tuple[MicroBatchSnapshot, ...],
    models: tuple[MicroBatchCostModel, ...],
) -> tuple[MicroBatchSnapshot, ...]:
    if not microbatches:
        raise ValueError("at least one microbatch is required")
    target = min(
        microbatches,
        key=lambda batch: (worst_rank_cost(batch, models), batch.microbatch_id),
    )
    return tuple(
        MicroBatchSnapshot(batch.microbatch_id, (*batch.requests, request))
        if batch.microbatch_id == target.microbatch_id
        else batch
        for batch in microbatches
    )


def balanced_assignment(
    requests: tuple[RequestWork, ...], microbatch_count: int
) -> tuple[MicroBatchSnapshot, ...]:
    if microbatch_count <= 0:
        raise ValueError("microbatch_count must be positive")
    base, remainder = divmod(len(requests), microbatch_count)
    batches: list[MicroBatchSnapshot] = []
    cursor = 0
    for microbatch_id in range(microbatch_count):
        size = base + (1 if microbatch_id < remainder else 0)
        batches.append(
            MicroBatchSnapshot(microbatch_id, requests[cursor : cursor + size])
        )
        cursor += size
    return tuple(batches)


__all__ = [
    "MicroBatchCostModel",
    "MicroBatchSnapshot",
    "RequestWork",
    "assign_lowest_cost",
    "balanced_assignment",
    "worst_rank_cost",
]
