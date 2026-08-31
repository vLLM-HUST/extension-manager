"""Provider-neutral state evaluation and planning."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from vllm_hust_ext.config import ExtensionConfig
from vllm_hust_ext.discovery import InstalledBundle
from vllm_hust_ext.providers import provider_for
from vllm_hust_ext.providers.base import ProviderPlan, RenderArtifact


class LifecycleState(str, Enum):
    INSTALLED = "installed"
    DISCOVERED = "discovered"
    COMPATIBLE = "compatible"
    CONFIGURED = "configured"
    ENABLED = "enabled"
    REACHABLE = "reachable"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    INCOMPATIBLE = "incompatible"


@dataclass(frozen=True, slots=True)
class ExtensionStatus:
    extension_id: str
    provider: str
    states: tuple[LifecycleState, ...]
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "extension_id": self.extension_id,
            "provider": self.provider,
            "states": [state.value for state in self.states],
            "evidence": list(self.evidence),
        }


def status_for(
    bundle: InstalledBundle,
    extension: ExtensionConfig,
    *,
    include_external_providers: bool = True,
) -> ExtensionStatus:
    states = [LifecycleState.INSTALLED, LifecycleState.DISCOVERED]
    try:
        provider = provider_for(
            bundle.manifest.host.provider,
            include_external=include_external_providers,
        )
        if not provider.supports(bundle.manifest):
            raise ValueError("selected provider does not support this manifest")
        check = provider.check(bundle.manifest, extension.configuration)
    except ValueError as error:
        return ExtensionStatus(
            bundle.bundle_id,
            bundle.manifest.host.provider,
            tuple(states + [LifecycleState.INCOMPATIBLE]),
            (str(error),),
        )
    if check.compatible is True:
        states.append(LifecycleState.COMPATIBLE)
    elif check.compatible is False:
        states.append(LifecycleState.INCOMPATIBLE)
    if check.configured:
        states.append(LifecycleState.CONFIGURED)
    if extension.enabled:
        states.append(LifecycleState.ENABLED)
    if check.reachable is True:
        states.append(LifecycleState.REACHABLE)
    if check.healthy is True:
        states.append(LifecycleState.HEALTHY)
    if check.degraded or check.reachable is False or check.healthy is False:
        states.append(LifecycleState.DEGRADED)
    return ExtensionStatus(
        bundle.bundle_id,
        provider.name,
        tuple(states),
        check.evidence,
    )


def plan_for(
    bundle: InstalledBundle,
    extension: ExtensionConfig,
    *,
    include_external_providers: bool = True,
) -> ProviderPlan:
    provider = provider_for(
        bundle.manifest.host.provider,
        include_external=include_external_providers,
    )
    if not provider.supports(bundle.manifest):
        raise ValueError("selected provider does not support this manifest")
    plan = provider.plan(
        bundle.manifest,
        extension.configuration,
        enabled=extension.enabled,
    )
    if any(action.mutating for action in plan.actions):
        raise ValueError("provider plan contains a forbidden implicit mutation")
    return plan


def render_plan(
    plan: ProviderPlan, *, include_external_providers: bool = True
) -> tuple[RenderArtifact, ...]:
    provider = provider_for(plan.provider, include_external=include_external_providers)
    return provider.render(plan)


def reject_conflicting_plans(plans: tuple[ProviderPlan, ...]) -> None:
    claims: dict[tuple[str, str], tuple[str, Any]] = {}
    for plan in plans:
        for key, value in plan.generated_config.items():
            claim = (plan.provider, key)
            previous = claims.get(claim)
            if previous is not None and previous[1] != value:
                raise ValueError(
                    f"extensions {previous[0]!r} and {plan.extension_id!r} "
                    f"conflict on {plan.provider}.{key}"
                )
            claims[claim] = (plan.extension_id, value)


def plan_dict(plan: ProviderPlan) -> dict[str, Any]:
    return asdict(plan)
