"""Process-owned runtime evidence for Manager-supervised vLLM launches."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import time
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from vllm_hust_ext.config import config_path
from vllm_hust_ext.discovery import InstalledBundle

_HOST_SCHEMA = "vllm-hust-plugin-evidence/0.1"
_SINK = "vllm_hust_ext.runtime_evidence:record_event"
_PATH_ENV = "VLLM_HUST_EXT_EVIDENCE_PATH"
_MODULE_BINDING_ENV = "VLLM_HUST_EXT_MODULE_BINDING"
_MODULE_SCHEMA = "vllm-hust-module-evidence/0.1"
_LAUNCH_SCHEMA = "vllm-hust-module-launch/0.1"
_MODULE_ROLES = {
    "vllm.scheduler-class.v1": "scheduler",
    "vllm.worker-class.v1": "worker",
    "vllm.batch-admission-policy.v1": "admission",
}
_EVIDENCE_ENVIRONMENT = (
    "VLLM_ECPA_EVIDENCE_SINK",
    "VLLM_ECPA_EVIDENCE_STRICT",
    "VLLM_ECPA_PLAN_ID",
    "VLLM_ECPA_LAUNCH_ID",
    _PATH_ENV,
)
# The formal phase-handoff protocol owns the original five-field entry-point
# binding. Module launches additionally bind a journal that handoff cannot move.
_OWNED_EVIDENCE_ENVIRONMENT = (*_EVIDENCE_ENVIRONMENT, _MODULE_BINDING_ENV)
_MAX_READ_BYTES = 1024 * 1024


def evidence_path() -> Path:
    override = os.environ.get(_PATH_ENV)
    return (
        Path(override)
        if override
        else config_path().with_name("runtime-evidence.jsonl")
    )


def _require_bound_event(event: dict[str, Any]) -> None:
    if event.get("schema") != _HOST_SCHEMA:
        raise ValueError("unsupported host evidence schema")
    if event.get("binding_status") != "bound":
        raise ValueError("unbound host evidence is not accepted")
    if not isinstance(event.get("plan_id"), str) or not event["plan_id"]:
        raise ValueError("host evidence requires plan_id")
    if not isinstance(event.get("launch_id"), str) or not event["launch_id"]:
        raise ValueError("host evidence requires launch_id")
    process = event.get("process")
    if not isinstance(process, dict):
        raise ValueError("host evidence requires process identity")
    if not isinstance(process.get("host"), str) or not process["host"]:
        raise ValueError("host evidence process requires host")
    if not isinstance(process.get("pid"), int) or isinstance(process["pid"], bool):
        raise ValueError("host evidence process requires pid")
    if (
        not isinstance(process.get("start_identity"), str)
        or not process["start_identity"]
    ):
        raise ValueError("host evidence process requires start_identity")


def record_event(event: dict[str, Any]) -> None:
    """Append one validated event; called inside the supervised host process."""

    if not isinstance(event, dict):
        raise TypeError("host evidence must be an object")
    _require_bound_event(event)
    _append(event)


def _append(event: dict[str, Any]) -> None:
    target = evidence_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n").encode()
    descriptor = os.open(target, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        if os.write(descriptor, encoded) != len(encoded):
            raise OSError("incomplete runtime evidence write")
    finally:
        os.close(descriptor)


def launch_environment(
    bundles: Sequence[InstalledBundle],
    *,
    semantic_launch_spec: str | Path | None = None,
) -> dict[str, str]:
    """Create a fresh binding for one actual Manager-supervised launch."""

    conflicts = [name for name in _OWNED_EVIDENCE_ENVIRONMENT if name in os.environ]
    if conflicts:
        raise ValueError(
            "vllm-hust-ext owns runtime evidence environment variables: "
            f"{sorted(conflicts)}"
        )
    plan_material = json.dumps(
        [
            [
                bundle.bundle_id,
                getattr(bundle.manifest, "bundle_version", "unknown"),
                str(getattr(bundle, "manifest_path", "unknown")),
            ]
            for bundle in sorted(bundles, key=lambda item: item.bundle_id)
        ],
        separators=(",", ":"),
    ).encode()
    native_plan_id = hashlib.sha256(plan_material).hexdigest()
    if semantic_launch_spec is not None:
        from .semantic_runtime_binding import validate_semantic_launch_spec

        spec = validate_semantic_launch_spec(semantic_launch_spec, bundles)
        native_plan_id = spec["native_plan_id"]
    environment = {
        "VLLM_ECPA_EVIDENCE_SINK": _SINK,
        "VLLM_ECPA_EVIDENCE_STRICT": "1",
        "VLLM_ECPA_PLAN_ID": native_plan_id,
        "VLLM_ECPA_LAUNCH_ID": str(uuid.uuid4()),
        _PATH_ENV: str(evidence_path()),
    }
    components = [item for bundle in bundles for item in _module_components(bundle)]
    if components:
        binding: dict[str, Any] = {
            "schema": _LAUNCH_SCHEMA,
            "plan_id": native_plan_id,
            "launch_id": environment["VLLM_ECPA_LAUNCH_ID"],
            "manager_process": _own_process(),
            "components": sorted(
                components,
                key=lambda item: (item["extension_id"], item["component_id"]),
            ),
        }
        binding["binding_digest"] = _digest(binding)
        _append(binding)
        environment[_MODULE_BINDING_ENV] = binding["binding_digest"]
    return environment


def _start_identity(pid: int) -> str | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        close = raw.rfind(")")
        fields_after_comm = raw[close + 1 :].split()
        if fields_after_comm[0] in {"Z", "X"}:
            return None
        start_ticks = fields_after_comm[19]
        int(start_ticks)
    except (OSError, IndexError, ValueError):
        return None
    return f"pid:{pid}:start_ticks:{start_ticks}"


def _process_is_current(process: object) -> bool:
    if not isinstance(process, dict):
        return False
    pid = process.get("pid")
    return bool(
        isinstance(pid, int)
        and not isinstance(pid, bool)
        and pid > 0
        and process.get("host") == socket.gethostname()
        and isinstance(process.get("start_identity"), str)
        and bool(process["start_identity"])
        and process.get("start_identity") == _start_identity(pid)
    )


def _events() -> tuple[dict[str, Any], ...]:
    target = evidence_path()
    try:
        with target.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - _MAX_READ_BYTES))
            if size > _MAX_READ_BYTES:
                stream.readline()
            lines = stream.readlines()
    except OSError:
        return ()
    events: list[dict[str, Any]] = []
    for line in lines:
        try:
            event = json.loads(line)
            _require_bound_event(event)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            continue
        events.append(event)
    return tuple(events)


def runtime_effective_evidence(bundle: InstalledBundle) -> str | None:
    """Return evidence only for a live process that observed real runtime work."""

    if _module_components(bundle):
        return _module_effective_evidence(bundle)

    entry_points = {
        (
            dict(carrier.attributes).get("group"),
            dict(carrier.attributes).get("name"),
        )
        for carrier in bundle.manifest.implementation
        if carrier.type == "python_entry_point"
    }
    entry_points.update(
        (entry_point.group, entry_point.name)
        for entry_point in bundle.manifest.activation.entry_points
    )
    for event in reversed(_events()):
        entry_point = event.get("entry_point")
        if (
            event.get("event") != "effective"
            or event.get("observation_kind") != "runtime_effective"
            or not isinstance(entry_point, dict)
            or (entry_point.get("group"), entry_point.get("name")) not in entry_points
            or not _process_is_current(event.get("process"))
        ):
            continue
        process = event["process"]
        return (
            "live host runtime observer evidence "
            f"launch_id={event['launch_id']} pid={process['pid']} "
            f"event_id={event.get('event_id', 'unknown')}"
        )
    return None


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _own_process() -> dict[str, Any]:
    pid = os.getpid()
    identity = _start_identity(pid)
    if identity is None:
        raise ValueError("runtime process identity is unavailable")
    return {"host": socket.gethostname(), "pid": pid, "start_identity": identity}


def _module_components(bundle: InstalledBundle) -> list[dict[str, Any]]:
    components = getattr(bundle.manifest, "components", ())
    # Direct class carriers require their complete paired module contract.
    # Existing entry-point-only policy bundles retain their established path.
    if not any(
        set(component.contracts) & {"vllm.scheduler-class.v1", "vllm.worker-class.v1"}
        for component in components
    ):
        return []
    active = {
        f"{dict(carrier.attributes).get('module')}:{dict(carrier.attributes).get('object')}"
        for carrier in bundle.manifest.implementation
        if carrier.type == "python_module"
        and dict(carrier.attributes).get("status") == "active"
    }
    manifest_sha = hashlib.sha256(bundle.manifest_path.read_bytes()).hexdigest()
    result = []
    for component in components:
        selected = set(component.contracts) & _MODULE_ROLES.keys()
        if not selected:
            continue
        if len(selected) != 1 or component.implementation_ref not in active:
            raise ValueError(
                "module evidence requires one active declared carrier per component"
            )
        contract = next(iter(selected))
        result.append(
            {
                "extension_id": bundle.bundle_id,
                "extension_version": bundle.manifest.bundle_version,
                "manifest_sha256": manifest_sha,
                "component_id": component.component_id,
                "contract": contract,
                "implementation_ref": component.implementation_ref,
                "role": _MODULE_ROLES[contract],
            }
        )
    return result


def _module_records() -> list[dict[str, Any]]:
    try:
        with evidence_path().open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - _MAX_READ_BYTES))
            if size > _MAX_READ_BYTES:
                stream.readline()
            lines = stream.readlines()
    except OSError:
        return []
    result = []
    for line in lines:
        try:
            item = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(item, dict) and item.get("schema") in {
            _MODULE_SCHEMA,
            _LAUNCH_SCHEMA,
        }:
            result.append(item)
    return result


def _valid_binding(binding: dict[str, Any]) -> bool:
    return (
        set(binding)
        == {
            "schema",
            "plan_id",
            "launch_id",
            "manager_process",
            "components",
            "binding_digest",
        }
        and binding["schema"] == _LAUNCH_SCHEMA
        and all(
            isinstance(binding[key], str) and binding[key]
            for key in ("plan_id", "launch_id", "binding_digest")
        )
        and isinstance(binding["components"], list)
        and bool(binding["components"])
        and all(
            isinstance(item, dict)
            and set(item)
            == {
                "extension_id",
                "extension_version",
                "manifest_sha256",
                "component_id",
                "contract",
                "implementation_ref",
                "role",
            }
            and all(isinstance(value, str) and value for value in item.values())
            and item["contract"] in _MODULE_ROLES
            and item["role"] == _MODULE_ROLES[item["contract"]]
            for item in binding["components"]
        )
        and binding["binding_digest"]
        == _digest({k: v for k, v in binding.items() if k != "binding_digest"})
        and _process_is_current(binding["manager_process"])
    )


def _bound_launch() -> dict[str, Any]:
    if any(not os.environ.get(name) for name in _OWNED_EVIDENCE_ENVIRONMENT):
        raise ValueError("incomplete Manager module evidence environment")
    if (
        os.environ["VLLM_ECPA_EVIDENCE_SINK"] != _SINK
        or os.environ["VLLM_ECPA_EVIDENCE_STRICT"] != "1"
    ):
        raise ValueError("unsupported Manager module evidence sink or strictness")
    digest = os.environ[_MODULE_BINDING_ENV]
    for binding in reversed(_module_records()):
        if (
            binding.get("binding_digest") != digest
            or binding.get("schema") != _LAUNCH_SCHEMA
        ):
            continue
        if not _valid_binding(binding) or any(
            binding[key] != os.environ[env]
            for key, env in (
                ("plan_id", "VLLM_ECPA_PLAN_ID"),
                ("launch_id", "VLLM_ECPA_LAUNCH_ID"),
            )
        ):
            raise ValueError("Manager module launch binding differs or owner exited")
        return cast(dict[str, Any], binding)
    raise ValueError("Manager-issued module launch binding is missing")


def emit_module_effective(
    implementation: type,
    *,
    role: str,
    request_count: int,
    output_token_count: int,
) -> bool:
    """Record successful step outputs, never import/init or mere submission.

    The trusted carrier must call only after its real completion/commit boundary.
    This records process-local work, not independent accelerator completion proof.
    """
    if not isinstance(implementation, type) or role not in _MODULE_ROLES.values():
        raise ValueError("invalid module implementation or role")
    if any(
        type(value) is not int or value <= 0
        for value in (request_count, output_token_count)
    ):
        raise ValueError("module evidence requires positive successful output counts")
    binding = _bound_launch()
    reference = f"{implementation.__module__}:{implementation.__qualname__}"
    loaded: Any = sys.modules.get(implementation.__module__)
    for name in implementation.__qualname__.split("."):
        loaded = getattr(loaded, name, None)
    if loaded is not implementation:
        raise ValueError("module evidence requires the actual loaded class symbol")
    candidates = [
        item
        for item in binding["components"]
        if item["implementation_ref"] == reference and item["role"] == role
    ]
    if len(candidates) != 1:
        raise ValueError(
            "runtime class/role does not match a unique selected module carrier"
        )
    _append(
        {
            "schema": _MODULE_SCHEMA,
            "event": "effective",
            "observation_kind": "runtime_effective",
            "plan_id": binding["plan_id"],
            "launch_id": binding["launch_id"],
            "binding_digest": binding["binding_digest"],
            "component": candidates[0],
            "process": _own_process(),
            "observed_at_ns": time.time_ns(),
            "request_count": request_count,
            "output_token_count": output_token_count,
        }
    )
    return True


def _module_effective_evidence(bundle: InstalledBundle) -> str | None:
    expected = _module_components(bundle)
    records = _module_records()
    binding = next(
        (
            item
            for item in reversed(records)
            if item.get("schema") == _LAUNCH_SCHEMA
            and isinstance(item.get("components"), list)
            and any(
                isinstance(c, dict) and c.get("extension_id") == bundle.bundle_id
                for c in item.get("components", [])
            )
        ),
        None,
    )
    if binding is None or not _valid_binding(binding):
        return None
    selected = [
        item
        for item in binding["components"]
        if item["extension_id"] == bundle.bundle_id
    ]
    if sorted(selected, key=lambda item: item["component_id"]) != sorted(
        expected, key=lambda item: item["component_id"]
    ):
        return None
    observed = set()
    pids = set()
    for event in records:
        if (
            event.get("schema") != _MODULE_SCHEMA
            or event.get("binding_digest") != binding["binding_digest"]
        ):
            continue
        component = event.get("component")
        if (
            not isinstance(component, dict)
            or component.get("extension_id") != bundle.bundle_id
        ):
            continue
        valid = (
            set(event)
            == {
                "schema",
                "event",
                "observation_kind",
                "plan_id",
                "launch_id",
                "binding_digest",
                "component",
                "process",
                "observed_at_ns",
                "request_count",
                "output_token_count",
            }
            and event.get("event") == "effective"
            and event.get("observation_kind") == "runtime_effective"
            and event.get("plan_id") == binding["plan_id"]
            and event.get("launch_id") == binding["launch_id"]
            and component in selected
            and all(
                type(event.get(key)) is int and event[key] > 0
                for key in ("observed_at_ns", "request_count", "output_token_count")
            )
            and _process_is_current(event.get("process"))
        )
        # An exited observed participant revokes the launch's evidence; never
        # borrow an older launch or hide a failed rank behind another live one.
        if not valid:
            return None
        observed.add(component["component_id"])
        pids.add(event["process"]["pid"])
    if observed != {item["component_id"] for item in expected}:
        return None
    return (
        "live module runtime evidence "
        f"launch_id={binding['launch_id']} components={len(observed)} "
        f"pids={sorted(pids)}; "
        "all declared modules observed, not an all-rank device qualification"
    )
