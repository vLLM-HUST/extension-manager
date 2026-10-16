"""Observer-minted raw correlation only; never a Manager execution Plan.

The unchanged native transport calls these opaque aliases plan_id/launch_id.
This adapter authenticates their baseline origin before writing the existing
bootstrap contexts. Activation alone never supplies semantic-effect evidence.
"""

from __future__ import annotations

import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path

from experiments.exposure_gate import native_semantic_bootstrap as native_bootstrap
from experiments.native_attention_candidate import (
    semantic_producer_registry as registry,
)
from experiments.native_kv_tensor_candidate import artifact_bootstrap

SCHEMA = "ecpa-baseline-native-scope/v1"
ORIGIN = "baseline-host-observer"
MEANING = "observer-minted-opaque-native-correlation-only"
PATH_ENV = "ECPA_BASELINE_NATIVE_SCOPE_PATH"
SHA_ENV = "ECPA_BASELINE_NATIVE_SCOPE_SHA256"
ARMS = {"entry-points-unmanaged", "explicit-manual-hooks"}
HEX = re.compile(r"[0-9a-f]{64}\Z")


def _path(value):
    path = Path(value)
    registry.require(
        path.is_absolute() and path.resolve() == path and not path.is_symlink(),
        "baseline scope path is not canonical",
    )
    return path


def _unique(pairs):
    value = {}
    for key, item in pairs:
        registry.require(key not in value, "baseline artifact repeats a JSON field")
        value[key] = item
    return value


def _reference(reference):
    registry.require(set(reference) == {"path", "sha256"}, "baseline reference differs")
    path = _path(reference["path"])
    raw, _ = native_bootstrap.read_private(path, 0o600)
    registry.require(
        registry.sha(raw) == reference["sha256"], "baseline reference bytes differ"
    )
    return raw


def _object(reference):
    return json.loads(_reference(reference), object_pairs_hook=_unique)


def _fresh_context_paths(native_path, tensor_path):
    paths = (_path(native_path), _path(tensor_path))
    registry.require(paths[0] != paths[1], "baseline context targets must be distinct")
    for path in paths:
        parent = path.parent.stat()
        registry.require(
            stat.S_ISDIR(parent.st_mode)
            and parent.st_uid == os.geteuid()
            and not stat.S_IMODE(parent.st_mode) & 0o077,
            "baseline context directory is not private and owned",
        )
        registry.require(
            not os.path.lexists(path), "baseline context target is not fresh"
        )
    return paths


def _receipt_sources_and_prefix(receipt):
    registry.require(
        set(receipt)
        == {
            "schema",
            "origin",
            "arm",
            "observer_trial_id",
            "owner",
            "host",
            "peers",
            "activation_profile_sha256",
            "host_sources",
            "observer_source",
            "socket",
            "journal",
            "activation_only",
            "effect_qualification",
            "formal_result",
        },
        "baseline observer receipt fields differ",
    )
    registry._files(receipt["host_sources"])
    registry._files(
        {receipt["observer_source"]["path"]: receipt["observer_source"]["sha256"]}
    )
    journal = receipt["journal"]
    raw = _path(journal["path"]).read_bytes()
    registry.require(
        len(raw) == journal["prefix_bytes"] and registry.sha(raw) == journal["sha256"],
        "baseline observer journal prefix changed",
    )
    rows = [json.loads(line, object_pairs_hook=_unique) for line in raw.splitlines()]
    registry.require(
        len(rows) == journal["records"] and rows, "baseline observer prefix incomplete"
    )
    previous = "0" * 64
    for sequence, row in enumerate(rows):
        registry.require(
            row["sequence"] == sequence
            and row["previous_sha256"] == previous
            and row["sha256"]
            == registry.sha(
                registry.canonical({k: v for k, v in row.items() if k != "sha256"})
            ),
            "baseline observer journal hashchain differs",
        )
        previous = row["sha256"]
    registry.require(
        previous == journal["last_sha256"], "baseline observer prefix end differs"
    )
    for peer in receipt["peers"]:
        for field, event in (
            ("activation_resolved_sequence", "resolved"),
            ("activation_invoked_sequence", "invoked"),
        ):
            row = rows[peer[field]]
            registry.require(
                row["kernel"] == peer["kernel"]
                and row["envelope"]["payload"]["event"] == event,
                "baseline activation journal join differs",
            )


@dataclass(frozen=True)
class BaselineNativeScope:
    raw: bytes

    def value(self):
        value = json.loads(self.raw, object_pairs_hook=_unique)
        registry.require(
            set(value)
            == {
                "schema",
                "origin",
                "observer_trial_id",
                "arm",
                "activation_profile_sha256",
                "common_query_sha256",
                "native_correlation",
                "activation_only",
                "effect_qualification",
                "formal_result",
            }
            and value["schema"] == SCHEMA
            and value["origin"] == ORIGIN
            and value["arm"] in ARMS
            and value["activation_only"] is True
            and value["effect_qualification"] is None
            and value["formal_result"] is False,
            "baseline scope schema or classification differs",
        )
        registry.require(
            isinstance(value["observer_trial_id"], str)
            and re.fullmatch(
                r"baseline-trial:[0-9a-f]{64}", value["observer_trial_id"]
            ),
            "baseline observer trial differs",
        )
        for key in ("activation_profile_sha256", "common_query_sha256"):
            registry.require(
                isinstance(value[key], str) and HEX.fullmatch(value[key]),
                "baseline scope digest differs",
            )
        aliases = value["native_correlation"]
        registry.require(
            set(aliases) == {"plan_id", "launch_id", "meaning"}
            and aliases["meaning"] == MEANING,
            "baseline correlation meaning differs",
        )
        launch = uuid.UUID(aliases["launch_id"])
        registry.require(
            str(launch) == aliases["launch_id"] and launch.version == 4,
            "baseline launch correlation differs",
        )
        material = {k: v for k, v in value.items() if k != "native_correlation"}
        registry.require(
            aliases["plan_id"]
            == registry.sha(registry.canonical({**material, "launch_id": str(launch)})),
            "baseline correlation digest differs",
        )
        return value

    def write(self, path):
        self.value()
        path = _path(path)
        parent = path.parent.stat()
        registry.require(
            parent.st_uid == os.geteuid() and not stat.S_IMODE(parent.st_mode) & 0o077,
            "baseline scope directory is not private",
        )
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(self.raw)
            stream.flush()
            os.fsync(stream.fileno())
        return {"path": str(path), "sha256": registry.sha(self.raw)}

    def environment(self, inherited, *, scope_reference):
        """Combine actual observer environment; reject even identical owned keys."""
        value = self.value()
        registry.require(
            _reference(scope_reference) == self.raw, "baseline scope artifact differs"
        )
        owned = {"VLLM_ECPA_PLAN_ID", "VLLM_ECPA_LAUNCH_ID", PATH_ENV, SHA_ENV}
        registry.require(
            not owned.intersection(inherited),
            "baseline correlation environment conflict",
        )
        registry.require(
            not any(key.startswith("ECPA_SEMANTIC_") for key in inherited)
            and "VLLM_HUST_EXT_EVIDENCE_PATH" not in inherited
            and inherited.get("VLLMHUST_EXT_ENABLED_BUNDLES") in (None, ""),
            "baseline cannot inherit Manager semantic bindings",
        )
        for key, expected in {
            "ECPA_BASELINE_HOST_OBSERVER_TRIAL": value["observer_trial_id"],
            "ECPA_ACTIVATION_CONTRACT": value["arm"],
            "ECPA_ACTIVATION_PROFILE_SHA256": value["activation_profile_sha256"],
        }.items():
            registry.require(
                key not in inherited or inherited[key] == expected,
                "baseline observer environment binding differs",
            )
        return {
            **inherited,
            "VLLM_ECPA_PLAN_ID": value["native_correlation"]["plan_id"],
            "VLLM_ECPA_LAUNCH_ID": value["native_correlation"]["launch_id"],
            PATH_ENV: scope_reference["path"],
            SHA_ENV: scope_reference["sha256"],
        }


def create(observer_trial, arm, activation_profile_sha256, common_query_sha256):
    value = {
        "schema": SCHEMA,
        "origin": ORIGIN,
        "observer_trial_id": observer_trial,
        "arm": arm,
        "activation_profile_sha256": activation_profile_sha256,
        "common_query_sha256": common_query_sha256,
        "activation_only": True,
        "effect_qualification": None,
        "formal_result": False,
    }
    launch = str(uuid.uuid4())
    value["native_correlation"] = {
        "plan_id": registry.sha(registry.canonical({**value, "launch_id": launch})),
        "launch_id": launch,
        "meaning": MEANING,
    }
    scope = BaselineNativeScope(registry.canonical(value))
    scope.value()
    return scope


def _authenticate_collector(
    ready, *, spec_reference, collector_source_path, drain_policy_reference=None
):
    """Pin the real optional drain extension before and after Unix authentication."""
    from experiments.native_challenge_candidate import collector_client

    _reference(spec_reference)
    if drain_policy_reference is not None:
        _reference(drain_policy_reference)
    result = collector_client.authenticate(
        Path(ready["socket_path"]),
        ready,
        Path(spec_reference["path"]),
        Path(collector_source_path),
        drain_policy_path=(
            Path(drain_policy_reference["path"]) if drain_policy_reference else None
        ),
    )
    _reference(spec_reference)
    if drain_policy_reference is not None:
        _reference(drain_policy_reference)
    return result


def write_contexts(
    scope,
    *,
    scope_reference,
    observer,
    receipt_reference,
    common_query_reference,
    peers,
    spec_reference,
    policy_reference,
    ready,
    source_files,
    collector_source_path,
    native_context_path,
    tensor_context_path,
    drain_policy_path=None,
):
    """Publish unchanged bootstraps only after a fresh real observer finalization.

    The owner freezes receipt after all API/worker activation callbacks arrive.
    Any later callback changes its captured prefix and safely rejects this call.
    The returned receipt remains activation-only, never an effect qualification.
    """
    native_context_path, tensor_context_path = _fresh_context_paths(
        native_context_path, tensor_context_path
    )
    from experiments.native_attention_candidate.baseline_host_binding import (
        SCHEMA as HOST_SCHEMA,
    )
    from experiments.native_attention_candidate.baseline_host_binding import (
        HostObserver,
    )

    value = scope.value()
    registry.require(
        _reference(scope_reference) == scope.raw, "baseline scope artifact differs"
    )
    registry.require(
        common_query_reference["sha256"] == value["common_query_sha256"],
        "baseline common query differs",
    )
    _reference(common_query_reference)
    registry.require(
        isinstance(observer, HostObserver), "actual baseline observer required"
    )
    receipt = _object(receipt_reference)
    registry.require(
        receipt["schema"] == HOST_SCHEMA
        and receipt["origin"] == ORIGIN
        and receipt["activation_only"] is True
        and receipt["effect_qualification"] is None
        and receipt["formal_result"] is False
        and receipt["observer_trial_id"] == value["observer_trial_id"]
        and receipt["arm"] == value["arm"]
        and receipt["activation_profile_sha256"] == value["activation_profile_sha256"]
        and registry.canonical(observer.finalize(peers)) == registry.canonical(receipt),
        "baseline actual observer receipt differs",
    )
    _receipt_sources_and_prefix(receipt)
    spec, policy = _object(spec_reference), _object(policy_reference)
    drain_reference = None
    if drain_policy_path is not None:
        drain_path = _path(drain_policy_path)
        drain_reference = {
            "path": str(drain_path),
            "sha256": registry.sha(drain_path.read_bytes()),
        }
        drain_policy = _object(drain_reference)
        registry.require(
            drain_policy["native_spec_sha256"] == spec_reference["sha256"]
            and drain_policy["tensor_policy_sha256"] == policy_reference["sha256"],
            "baseline drain policy belongs to another spec/tensor policy",
        )
    registry.require(
        spec["native_plan_id"] == value["native_correlation"]["plan_id"]
        and spec["native_launch_id"] == value["native_correlation"]["launch_id"]
        and ready["spec_sha256"] == spec_reference["sha256"]
        and policy["native_spec_sha256"] == spec_reference["sha256"],
        "baseline native transport correlation differs",
    )
    registry.require(
        len(spec["senders"]) == len(receipt["peers"]) == 3,
        "baseline native membership incomplete",
    )
    sources = {row["path"]: row["sha256"] for row in source_files}
    registry.require(
        len(sources) == len(source_files), "baseline native sources repeated"
    )
    registry._files(sources)
    expected_env = scope.environment(
        observer.environment(), scope_reference=scope_reference
    )
    own_env = {
        key: expected_env[key]
        for key in ("VLLM_ECPA_PLAN_ID", "VLLM_ECPA_LAUNCH_ID", PATH_ENV, SHA_ENV)
    }
    expected = {row["process"]["pid"]: row["process"] for row in receipt["peers"]}
    registry.require(
        len(expected) == 3
        and {row["process"]["pid"] for row in spec["senders"]} == set(expected),
        "baseline native peer identity differs",
    )
    for sender in spec["senders"]:
        process = sender["process"]
        registry.require(
            process == expected[process["pid"]]
            and process["assignment_source"] == "host",
            "baseline native role differs",
        )
        registry._kernel({key: process[key] for key in registry.KERNEL})
        registry.require(
            {r["path"]: r["sha256"] for r in sender["source_files"]} == sources,
            "baseline sender source tuple differs",
        )
    for process in [receipt["host"], *[row["kernel"] for row in receipt["peers"]]]:
        registry._kernel(process)
        actual = registry._environment(process["pid"])
        registry.require(
            all(actual.get(k.encode()) == v.encode() for k, v in own_env.items()),
            "actual baseline native environment differs",
        )
    _authenticate_collector(
        ready,
        spec_reference=spec_reference,
        collector_source_path=collector_source_path,
        drain_policy_reference=drain_reference,
    )
    registry._files(sources)
    registry.require(
        _reference(scope_reference) == scope.raw
        and _object(receipt_reference) == receipt
        and _object(spec_reference) == spec
        and _object(policy_reference) == policy
        and registry.canonical(observer.finalize(peers)) == registry.canonical(receipt),
        "baseline inputs changed during collector authentication",
    )
    _reference(common_query_reference)
    if drain_reference is not None:
        _reference(drain_reference)
    _receipt_sources_and_prefix(receipt)
    for process in [receipt["host"], *[row["kernel"] for row in receipt["peers"]]]:
        registry._kernel(process)
        actual = registry._environment(process["pid"])
        registry.require(
            all(actual.get(k.encode()) == v.encode() for k, v in own_env.items()),
            "actual baseline native environment differs",
        )
    # No IDs are injected into native facts. Source callbacks read the actual
    # inherited aliases; both existing writers retain their original schemas.
    _fresh_context_paths(native_context_path, tensor_context_path)
    native_bootstrap.write_context(
        Path(native_context_path),
        spec_path=Path(spec_reference["path"]),
        ready=ready,
        source_files=source_files,
    )
    artifact_bootstrap.write_context(
        Path(tensor_context_path),
        spec_path=Path(spec_reference["path"]),
        policy_path=Path(policy_reference["path"]),
        ready=ready,
        source_files=source_files,
    )
    return {
        "schema": "ecpa-baseline-native-bootstrap-binding/v1",
        "origin": ORIGIN,
        "baseline_scope_sha256": scope_reference["sha256"],
        "host_observer_receipt_sha256": receipt_reference["sha256"],
        "activation_only": True,
        "effect_qualification": None,
        "formal_result": False,
    }
