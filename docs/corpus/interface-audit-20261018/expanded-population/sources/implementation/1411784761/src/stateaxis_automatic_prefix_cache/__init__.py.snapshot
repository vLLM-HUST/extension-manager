"""Activation contract for bounded automatic prefix reuse in StateAxis."""

from __future__ import annotations

from dataclasses import dataclass

MOD_ID = "org.vllm-hust.stateaxis-automatic-prefix-cache"


@dataclass(frozen=True, slots=True)
class AutomaticPrefixCacheConfig:
    """Only configuration accepted by the hash-bound StateAxis host."""

    enabled: bool = True
    max_entries: int = 2
    block_tokens: int = 128
    lease_safe: bool = True
    verify_tokens_after_hash: bool = True
    fail_closed: bool = True

    def __post_init__(self) -> None:
        if (
            self.enabled is not True
            or self.max_entries != 2
            or self.block_tokens != 128
            or self.lease_safe is not True
            or self.verify_tokens_after_hash is not True
            or self.fail_closed is not True
        ):
            raise ValueError(
                "automatic prefix cache requires the bounded two-entry, "
                "128-token-block, lease-safe, collision-verified contract"
            )


def automatic_prefix_cache() -> AutomaticPrefixCacheConfig:
    """Return the default-off candidate's admitted ON configuration."""

    return AutomaticPrefixCacheConfig()


__all__ = ["MOD_ID", "AutomaticPrefixCacheConfig", "automatic_prefix_cache"]
