"""Independent runner observes actual owned successor after source route-open.

The publication is only a wakeup. Current kernel, ancestry, immutable inputs,
real collector socket authentication and original healthy Host are reobserved.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path

from experiments.formal_campaign import h3_native_client, h3_native_collector
from experiments.formal_campaign.h3_dynamic_authority import require
from experiments.formal_campaign.h3_observer_loss import observe_host_kernels
from experiments.formal_campaign.h3_owned_worker_carrier import reference
from experiments.formal_campaign.h3_worker_relaunch import identity, owned_sessions


def observe(scope, output, authority_kernel, authority):
    from experiments.formal_campaign.h3_observer_live_launcher import write_private

    path = output / "live-route-publication.json"
    raw = path.read_bytes()
    value = json.loads(raw)
    transport = value["transport"]
    require(
        value["schema"] == "ecpa-h3-observer-live-route-publication/v2"
        and transport["live_receipt"] == scope.receipt_ref()
        and identity(authority_kernel["pid"]) == authority_kernel,
        "route publication authority/start receipt differs",
    )
    expected = [
        {k: m["identity"][k] for k in ("pid", "start_ticks", "session", "boot_id")}
        for m in transport["semantic_enrollment"]["members"]
    ]
    actual_hosts = observe_host_kernels(expected)
    native = h3_native_collector.native
    descriptor = transport["successor_descriptor"]
    collector = descriptor["collector"]
    actual = native.identity(collector["pid"])
    _, owned = owned_sessions(authority_kernel)
    kernel = {k: collector[k] for k in ("pid", "start_ticks", "session", "boot_id")}
    require(
        actual == collector and owned.get(collector["pid"]) == kernel,
        "successor is not independently observed actual authority-owned kernel",
    )
    root = Path(scope.value()["declaration"]["successor"]["output"])
    authentication = h3_native_client.authenticate(
        root / "native.sock",
        descriptor,
        root / "native-spec.json",
        Path(h3_native_collector.__file__).resolve(),
        drain_policy_path=root / "drain-policy.json",
    )
    query = authority.call("query")
    require(
        query["route"]["generation"] == transport["generation"]
        and query["route"]["snapshot"]
        == {"transport_enrollment_sha256": transport["sha256"]},
        "actual independently queried route is not source-issued successor transport",
    )
    observed = time.monotonic_ns()
    require(
        path.read_bytes() == raw
        and transport["commit"]["committed_ns"] <= value["published_ns"] <= observed,
        "route publication changed or independent ordering differs",
    )
    return write_private(
        output / "runner-live-route-observation.json",
        {
            "schema": "ecpa-h3-observer-independent-live-route/v2",
            "start_id": scope.value()["start"]["start_id"],
            "live_receipt": scope.receipt_ref(),
            "publication": reference(path),
            "authority": authority_kernel,
            "route_query": query,
            "authority_socket_fence": list(authority.socket_fence),
            "successor": actual,
            "successor_kernel": kernel,
            "authentication": authentication,
            "observer": native.identity(os.getpid()),
            "host_kernels": actual_hosts,
            "host_preserved": actual_hosts == expected,
            "observed_ns": observed,
            "inputs": {
                name: reference(root / name)
                for name in (
                    "native-spec.json",
                    "tensor-policy.json",
                    "drain-policy.json",
                )
            },
            "formal_result": False,
        },
    )


def verify(witness, publication, scope, *, authority_kernel, host_kernels, terminal_ns):
    """Offline join only to independently recorded kernel/socket authentication."""
    from experiments.formal_campaign.h3_owned_worker_carrier import checked_reference

    value = json.loads(checked_reference(witness["publication"]).read_bytes())
    require(
        value == publication
        and witness["schema"] == "ecpa-h3-observer-independent-live-route/v2"
        and witness["start_id"] == scope.value()["start"]["start_id"]
        and witness["live_receipt"] == scope.receipt_ref()
        and witness["authority"] == authority_kernel
        and witness["successor"]
        == value["transport"]["successor_descriptor"]["collector"]
        and witness["successor_kernel"]
        == {
            k: witness["successor"][k]
            for k in ("pid", "start_ticks", "session", "boot_id")
        }
        and value["transport"]["commit"]["committed_ns"]
        <= value["published_ns"]
        <= witness["observed_ns"]
        <= terminal_ns,
        "independent actual route observation belongs to another receipt/epoch/clock",
    )
    root = Path(scope.value()["declaration"]["successor"]["output"])
    require(
        set(witness["inputs"])
        == {"native-spec.json", "tensor-policy.json", "drain-policy.json"},
        "complete actual successor immutable inputs absent",
    )
    for name, ref in witness["inputs"].items():
        require(ref["path"] == str(root / name), "successor raw input path differs")
        checked_reference(ref)
    # Authenticate's full independent before snapshot includes challenge-bound
    # live peer and descriptor/archive clock receipts; re-use original offline
    # consumers per request rather than treating this observation as completion.
    authentication = witness["authentication"]
    raw = base64.b64decode(authentication["status_raw_base64"], validate=True)
    status = json.loads(raw)
    native = h3_native_collector.native
    descriptor = value["transport"]["successor_descriptor"]
    clock = authentication["authentication_clock"]
    require(
        authentication["status"] == status
        and native.sha(raw) == authentication["status_raw_sha256"]
        and authentication["kernel_peer"]["pid"] == witness["successor"]["pid"]
        and clock["client"] == witness["observer"]
        and clock["client_source_sha256"]
        == native.sha(Path(h3_native_client.__file__).read_bytes())
        and value["published_ns"]
        <= clock["dispatch_monotonic_ns"]
        <= clock["completed_monotonic_ns"]
        <= witness["observed_ns"]
        and status["collector"] == descriptor["collector"]
        and status["spec_sha256"] == descriptor["spec_sha256"]
        and status["collector_source_sha256"] == descriptor["collector_source_sha256"]
        and status["socket_identity"] == descriptor["socket_identity"]
        and status["archive_identity"] == descriptor["archive_identity"]
        and status["failed"] is False,
        "independent successor real peer/raw status/source/clock differs",
    )
    spec = json.loads((root / "native-spec.json").read_bytes())
    drain_policy = json.loads((root / "drain-policy.json").read_bytes())
    require(
        authentication["kernel_peer"]["uid"] == spec["senders"][0]["peer_uid"]
        and clock["schema"] == "ecpa-native-status-authentication-clock/v1",
        "independent root collector peer credentials/authentication clock differs",
    )
    core = {
        k: v
        for k, v in status.items()
        if k not in {"acknowledged_prefix", "issued_monotonic_ns", "source_drain"}
    }
    require(
        core
        == {
            "schema": "ecpa-h3-concurrent-native-collector-status/v1",
            "spec_sha256": descriptor["spec_sha256"],
            "collector_source_sha256": descriptor["collector_source_sha256"],
            "collector": descriptor["collector"],
            "socket_identity": descriptor["socket_identity"],
            "socket_path": str(root / "native.sock"),
            "archive_identity": descriptor["archive_identity"],
            "classification": "REAL_RUNTIME_UNQUALIFIED",
            "formal_producer_registration": False,
            "failed": False,
        },
        'independent root receiver full status diff'
        'ers from frozen source-owned descriptor',
    )
    h3_native_client.validate_request_status(status, spec, drain_policy)
    require(
        witness["route_query"]["route"]["generation"]
        == value["transport"]["generation"]
        and witness["route_query"]["route"]["snapshot"]
        == {"transport_enrollment_sha256": value["transport"]["sha256"]},
        "independent actual route query differs from published transport",
    )
    preserved = witness["host_kernels"] == host_kernels
    return {
        "host_preserved": preserved,
        "summary_consistent": witness["host_preserved"] is preserved,
        "successor_kernel": witness["successor_kernel"],
        "observed_ns": witness["observed_ns"],
    }
