"""Narrow static replica-writer analysis; never a cluster/runtime attestation.

Pure target analysis receives registered desired objects, not an oracle verdict.
The pinned configuration adapter additionally reads and hashes its small source files.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class WriterAnalysis:
    decision: str
    reason: str
    target: tuple[str, str, str, str] | None = None
    owners: tuple[str, ...] = ()


def _unknown(reason: str) -> WriterAnalysis:
    return WriterAnalysis("unknown", reason)


def _target(
    value: Mapping[str, Any], namespace: str, *, keda: bool = False
) -> tuple[str, str, str, str] | None:
    # Only pinned KEDA defaults may fill absent GVK fields; explicit other kinds
    # must never alias a same-name Deployment.
    if any(
        key in value and not isinstance(value[key], str)
        for key in ("apiVersion", "kind")
    ):
        return None
    api = value.get("apiVersion") or ("apps/v1" if keda else None)
    kind = value.get("kind") or ("Deployment" if keda else None)
    if api != "apps/v1" or kind != "Deployment":
        return None
    name = value.get("name")
    if not isinstance(name, str) or not name:
        return None
    return ("apps/v1", "Deployment", namespace, name)


def _analyze_registered_objects(
    deployment: Mapping[str, Any],
    autoscalers: Sequence[Mapping[str, Any]],
    *,
    release_namespace: str,
    release_name: str,
) -> WriterAnalysis:
    """Analyze one exact Helm release target and its registered desired objects.

    Caller must independently authenticate the inventory and actual Helm renderer
    source/argv/values/output before invoking. No caller verdict, writer flags,
    ownership_conflicts, inferred cluster presence, or global compatibility claim.
    """
    if not release_namespace or not release_name:
        return _unknown("release identity missing")
    metadata = deployment.get("metadata", {})
    annotations = metadata.get("annotations", {})
    namespace = metadata.get("namespace", release_namespace)
    if (
        namespace != release_namespace
        or annotations.get("meta.helm.sh/release-name") != release_name
        or annotations.get("meta.helm.sh/release-namespace") != release_namespace
    ):
        return _unknown("rendered Deployment is not bound to this Helm release")
    target = _target(
        {
            "apiVersion": deployment.get("apiVersion"),
            "kind": deployment.get("kind"),
            "name": metadata.get("name"),
        },
        namespace,
    )
    if target is None or not isinstance(deployment.get("spec"), dict):
        return _unknown("unsupported or incomplete rendered target")
    replicas = deployment["spec"].get("replicas")
    has_chart_writer = "replicas" in deployment["spec"]
    if has_chart_writer and (type(replicas) is not int or replicas < 0):
        return _unknown("replicas is not a nonnegative exact integer")
    writers: set[str] = set()
    if has_chart_writer:
        writers.add(f"helm:{release_namespace}/{release_name}")
    seen_objects: dict[tuple[str, str, str], Mapping[str, Any]] = {}
    scaled_objects: dict[str, tuple[str, str, str]] = {}
    relevant_hpas = []
    for obj in autoscalers:
        api, kind = obj.get("apiVersion"), obj.get("kind")
        if (api, kind) not in {
            ("keda.sh/v1alpha1", "ScaledObject"),
            ("autoscaling/v2", "HorizontalPodAutoscaler"),
        }:
            return _unknown("inventory contains an unsupported scaler kind/version")
        meta, spec = obj.get("metadata", {}), obj.get("spec", {})
        ns, name = meta.get("namespace", release_namespace), meta.get("name")
        if not isinstance(ns, str) or not ns or not isinstance(name, str) or not name:
            return _unknown("autoscaler identity incomplete")
        if not isinstance(kind, str):
            return _unknown("scaler kind is not a string")
        identity = (kind, ns, name)
        if identity in seen_objects:
            if seen_objects[identity] != obj:
                return _unknown("two observations disagree for one autoscaler")
            continue
        seen_objects[identity] = obj
        ref = spec.get("scaleTargetRef")
        if not isinstance(ref, dict):
            return _unknown("autoscaler target missing")
        # Exact KEDA59815 gvkr.go26-29,37-51,70-72: apps/v1 Deployment defaults;
        # defaultKind resolves directly, without RESTMapper/API discovery.
        other = _target(ref, ns, keda=kind == "ScaledObject")
        if other is None:
            return _unknown("target outside this pinned Deployment adapter")
        if other != target:
            continue
        if kind == "ScaledObject":
            paused = meta.get("annotations", {})
            if any(key.startswith("autoscaling.keda.sh/paused") for key in paused):
                return _unknown("paused KEDA behavior outside this bounded adapter")
            if not isinstance(spec.get("triggers"), list) or not spec["triggers"]:
                return _unknown("ScaledObject activation configuration incomplete")
            uid = meta.get("uid")
            if uid:
                if uid in scaled_objects and scaled_objects[uid] != identity:
                    return _unknown("ScaledObject UID reused by another identity")
                scaled_objects[uid] = identity
            writers.add(f"keda:{ns}/{name}")
        else:
            relevant_hpas.append(obj)
    for obj in relevant_hpas:
        meta = obj["metadata"]
        owners = [
            r for r in meta.get("ownerReferences", []) if r.get("controller") is True
        ]
        if owners:
            if len(owners) != 1:
                return _unknown("ambiguous HPA controller owner")
            owner = owners[0]
            owner_identity = scaled_objects.get(owner.get("uid"))
            if (
                owner.get("apiVersion") != "keda.sh/v1alpha1"
                or owner.get("kind") != "ScaledObject"
                or owner_identity
                != (
                    "ScaledObject",
                    meta.get("namespace", release_namespace),
                    owner.get("name"),
                )
            ):
                return _unknown("HPA owner not joined to its actual ScaledObject")
            # This HPA and its parent are one delegated writer, not two owners.
            continue
        writers.add(f"hpa:{meta.get('namespace', release_namespace)}/{meta['name']}")
    if len(writers) > 1:
        return WriterAnalysis(
            "conflict",
            "independent desired writers share spec.replicas",
            target,
            tuple(sorted(writers)),
        )
    return WriterAnalysis(
        "no-conflict-in-declared-inventory",
        "at most one replica writer in this exact registered inventory; "
        "not global admission",
        target,
        tuple(sorted(writers)),
    )


def analyze_registered_objects(
    deployment: object,
    autoscalers: object,
    *,
    release_namespace: str,
    release_name: str,
) -> WriterAnalysis:
    try:
        if not isinstance(deployment, Mapping) or not isinstance(
            autoscalers, (list, tuple)
        ):
            return _unknown("desired objects are not mappings/a sequence")
        if any(not isinstance(obj, Mapping) for obj in autoscalers):
            return _unknown("autoscaler is not a mapping")
        return _analyze_registered_objects(
            deployment,
            autoscalers,
            release_namespace=release_namespace,
            release_name=release_name,
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        return _unknown("malformed metadata/spec/owner references")


PINNED_SOURCE_SHA256 = {
    "keda-hpa.excerpt.txt": (
        "b90b1d12d05cb1c0a4f2bf4c36233e6ac5690abdc60d05edbb1f2ddf3774dcaf"
    ),
    "vllm-keda-scaled-object.yaml": (
        "a202c270c8db091504d6d1e8915d2e592b7ec7b01a7789d5171b1b66fe2ae9d1"
    ),
    "keda-scale-executor.excerpt.txt": (
        "6fd3c4d9a67ef6d9d585dc01356c6fb6d5bc282ab523a77303d0132670682808"
    ),
    "production-deployment.yaml": (
        "9fb95e350573cb199eedbfb5b4ef6c26c84a45602ce30bdc6ac45f041e16f3da"
    ),
    "production-values.yaml": (
        "ed8148b272694c1f7f32ab5198eb7e78ba8fe378b18a956acc32c3441de44f3f"
    ),
    "production-stack-provider-manifest.json": (
        "0a751df04ebc8c5a6e52e4eb0ef07e26980d2efdb4e8757c20f3aa26a3e614f0"
    ),
    "keda-gvkr.go": (
        "7da6cf3b9eee67e027de3c549b83dd24a099e47845660a4b6b4194d25bd4025b"
    ),
    "keda-scaledobject-controller.go": (
        "0963215f007bcedae545c8764c7a846b4ae16480c37fda106b5ac730b92b7c0e"
    ),
    "keda-scaledobject-types.go": (
        "a14853c680934a806ab6da7e8ce43cc098fa975c780f5f055ab8637eb4b937f3"
    ),
}


def inspect_pinned_configuration(
    configuration: Mapping[str, Any],
    autoscalers: Sequence[Mapping[str, Any]],
    *,
    source_root: Path | str | None,
) -> tuple[WriterAnalysis, ...]:
    """Recompute bounded chart rules from registered config, never oracle verdict.

    source_root is trusted application wiring, not configuration-controlled.
    autoscalers are registered desired raw objects (or a lossless parse of them),
    not claims that those controllers currently run. Pinned sources are checked
    on each call. No cluster health or runtime authority is inferred.
    """
    import hashlib
    from pathlib import Path

    if source_root is None:
        return (_unknown("pinned adapter source root missing"),)
    for name, expected in PINNED_SOURCE_SHA256.items():
        path = Path(source_root) / name
        if path.is_symlink() or not path.is_file():
            return (_unknown("pinned adapter source absent"),)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            return (_unknown("pinned adapter source bytes changed"),)
    try:
        if configuration.get("chart", "vllm/vllm-stack") != "vllm/vllm-stack":
            return (_unknown("chart is outside pinned source adapter"),)
        release = configuration.get("release", "vllm")
        ns = configuration.get("namespace", "default")
        if not isinstance(release, str) or not isinstance(ns, str):
            return (_unknown("release identity malformed"),)
        values = configuration.get("values")
        if not isinstance(values, dict):
            return (_unknown("values are missing"),)
        engine = values.get("servingEngineSpec", {})
        enabled = engine.get("enableEngine", True)  # pinned values.yaml7
        if type(enabled) is not bool:
            return (_unknown("engine enabled flag malformed"),)
        if not enabled:
            return (
                WriterAnalysis(
                    "no-conflict-in-declared-inventory",
                    "chart creates no engine Deployment",
                ),
            )
        models = engine.get("modelSpec")
        if not isinstance(models, list) or not models:
            return (_unknown("explicit modelSpec list missing"),)
        results = []
        seen = set()
        for model in models:
            name = model.get("name")
            if not isinstance(name, str) or not name or name in seen:
                return (_unknown("model names missing or duplicated"),)
            seen.add(name)
            if "enabled" in model and type(model["enabled"]) is not bool:
                return (_unknown("model enabled flag malformed"),)
            if model.get("enabled") is False:
                continue
            ray = model.get("raySpec", {}).get("enabled", False)
            if type(ray) is not bool:
                return (_unknown("ray mode malformed"),)
            if ray:
                return (_unknown("Ray carrier outside Deployment adapter"),)
            delegated = model.get("keda", {}).get("enabled", False)
            if type(delegated) is not bool:
                return (_unknown("KEDA delegation malformed"),)
            # Exact template18-19 and33-35; no guessed rendered resource name.
            spec = {} if delegated else {"replicas": model.get("replicaCount")}
            deployment = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": f"{release}-{name}-deployment-vllm",
                    "namespace": ns,
                    "annotations": {
                        "meta.helm.sh/release-name": release,
                        "meta.helm.sh/release-namespace": ns,
                    },
                },
                "spec": spec,
            }
            # Internal release annotations express the deterministic provenance
            # of this derived projection; they are not asserted live metadata.
            results.append(
                analyze_registered_objects(
                    deployment, autoscalers, release_namespace=ns, release_name=release
                )
            )
        return tuple(results) or (
            WriterAnalysis(
                "no-conflict-in-declared-inventory",
                "no enabled Deployment in supplied model list",
            ),
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        return (_unknown("malformed desired configuration or object inventory"),)
