"""Host-provider contracts for non-mutating extension orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from vllm_hust_ext.manifest import BundleManifest


@dataclass(frozen=True, slots=True)
class PlanAction:
    operation: str
    target: str
    lifecycle_owner: str
    mutating: bool = False
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ProviderPlan:
    extension_id: str
    provider: str
    actions: tuple[PlanAction, ...]
    generated_config: dict[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RenderArtifact:
    name: str
    media_type: str
    content: str


@dataclass(frozen=True, slots=True)
class ProviderCheck:
    compatible: bool
    configured: bool
    reachable: bool | None = None
    healthy: bool | None = None
    degraded: bool = False
    evidence: tuple[str, ...] = ()


class HostProvider(Protocol):
    """A host-owned adapter. No apply/delete operation is part of this API."""

    name: str

    def supports(self, manifest: BundleManifest) -> bool: ...

    def plan(
        self,
        manifest: BundleManifest,
        configuration: dict[str, Any],
        *,
        enabled: bool,
    ) -> ProviderPlan: ...

    def render(self, plan: ProviderPlan) -> tuple[RenderArtifact, ...]: ...

    def check(
        self, manifest: BundleManifest, configuration: dict[str, Any]
    ) -> ProviderCheck: ...
