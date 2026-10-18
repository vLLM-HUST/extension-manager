"""Source candidate for original observer-loss; never accepts worker raw evidence.

Only an authority-created H3 native collector is an eligible observer. Registration
and the original runner must explicitly adopt this domain before formal execution.
No module-level launch, signal, import-time observation, or cleanup occurs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import select
import signal
import time
from pathlib import Path

from experiments.formal_campaign.h3_dynamic_authority import canonical, require
from experiments.formal_campaign.h3_worker_relaunch import identity, owned_sessions

RAW = "ecpa-h3-observer-loss-raw/v1"
BINDING = "ecpa-h3-authority-owned-native-observer/v1"
ARMS = ("vanilla-vllm-entry-points", "manual-integration", "ecpa")


def validate_original(original, client, start, protocol):
    require(original["cell_id"] == "observer-loss", "distinct original cell required")
    require(
        original["campaign_id"] == protocol["h3"]["campaign_id"], "campaign differs"
    )
    require(original["fault"]["target_role"] == "observer", "worker target forbidden")
    require(original["fault"]["signal"] == "SIGKILL", "freeze actual observer kill")
    require(original["fault"]["target_exit_timeout_s"] > 0, "exit bound missing")
    require(start["arm"] in ARMS and start["repetition"] in (1, 2, 3), "arm differs")
    require(
        start["start_id"] == f"observer-loss-r{start['repetition']}-{start['arm']}",
        "start differs",
    )
    require(
        start["arm_order"]
        == protocol["schedule"][start["repetition"] - 1].index(start["arm"]) + 1,
        "Latin order differs",
    )
    expected = {
        "request_count": 60,
        "concurrency": 8,
        "interval_s": 0.2,
        "timeout_s": 10,
        "dispatch_slack_s": 0.5,
        "retry_policy": "single-attempt-no-retry",
    }
    require(
        all(client.get(k) == v for k, v in expected.items()),
        "original workload differs",
    )
    require(
        client["payload"] == original["probe"]["request_payload"], "payload differs"
    )
    require(original["probe"]["request_count"] == 60, "original request count differs")


def binding(
    process,
    descriptor,
    *,
    authority,
    start_id,
    enrollment,
    phase_index,
    collector_source,
    collector_argv,
):
    """Authority-only hook immediately after authenticated start_native_epoch.

    Popen identity, original descriptor, owned ancestry, and exact source argv are
    checked together; a PID supplied in an arbitrary marker cannot select a target.
    """
    require(phase_index in (0, 1), "original and recovery observer epochs only")
    require(process.poll() is None, "observer exited before binding")
    kernel = identity(process.pid)
    original_identity = {
        **kernel,
        "start_identity": f"pid:{kernel['pid']}:start_ticks:{kernel['start_ticks']}",
    }
    require(
        descriptor["collector"] == original_identity
        and descriptor["launcher_observed_identity"] == original_identity,
        "authenticated original collector descriptor epoch differs",
    )
    _, descendants = owned_sessions(authority)
    require(descendants.get(process.pid) == kernel, "observer is not authority-owned")
    source = Path(collector_source).resolve()
    argv = [
        s.decode()
        for s in Path(f"/proc/{process.pid}/cmdline").read_bytes().split(b"\0")
        if s
    ]
    require(argv == collector_argv and str(source) in argv, "collector argv differs")
    return {
        "schema": BINDING,
        "start_id": start_id,
        "phase_index": phase_index,
        "enrollment_sha256": enrollment,
        "authority": authority,
        "observer": kernel,
        "original_collector_identity": original_identity,
        "source": {
            "path": str(source),
            "sha256": "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest(),
        },
        "argv": argv,
        "descriptor_sha256": "sha256:"
        + hashlib.sha256(canonical(descriptor)).hexdigest(),
        "observed_ns": time.monotonic_ns(),
    }


def observe_original_client_barrier(*, output, client_kernel, start_id, enrollment):
    """Join the actual original client kernel, source argv and chained trace.

    Matches the existing carrier's first-request-start rule; no positive response
    precondition, schedule reanchoring, extra probe, retry, or new timing policy.
    """
    from experiments.formal_campaign.h3_client_trace import read_client_trace
    from experiments.formal_campaign.h3_native_http import BoundOriginalClient

    output = Path(output)
    actual = BoundOriginalClient(
        client_kernel,
        output / "runtime-client-spec.json",
        output / "client.jsonl",
        output / "client-ready.json",
    )
    spec = actual.spec
    require(
        spec["start_id"] == start_id
        and spec["initial_enrollment_sha256"] == enrollment,
        "client start/enrollment differs",
    )
    ready = json.loads((output / "client-ready.json").read_bytes())
    require(
        ready["client"]
        == {k: client_kernel[k] for k in ("pid", "start_ticks", "boot_id")},
        "actual client-ready kernel differs",
    )
    events = read_client_trace(output / "client.jsonl")
    require(
        events
        and events[0]["kind"] == "client.start"
        and all(e["client"] == ready["client"] for e in events),
        "original client trace owner/start differs",
    )
    require(
        events[0]["detail"]["spec_sha256"]
        == "sha256:" + hashlib.sha256(canonical(spec)).hexdigest(),
        "original client spec lineage differs",
    )
    starts = [e for e in events if e["kind"] == "request.start"]
    require(starts, "no actual pre-fault request; no observer fault")
    prefix = b"".join(canonical(event) + b"\n" for event in events)
    require(
        (output / "client.jsonl").read_bytes().startswith(prefix),
        "actual chained client prefix changed before observer injection",
    )
    prefix_path = output / "runner-pre-fault-client-prefix.bin"
    descriptor = os.open(
        prefix_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(prefix)
        stream.flush()
        os.fsync(stream.fileno())
    actual.verify()
    return {
        "start_id": start_id,
        "enrollment_sha256": enrollment,
        "client_spec": {
            "path": str(output / "runtime-client-spec.json"),
            "sha256": "sha256:" + hashlib.sha256(actual.spec_raw).hexdigest(),
        },
        "client_prefix": {
            "path": str(prefix_path),
            "sha256": "sha256:" + hashlib.sha256(prefix).hexdigest(),
        },
        "client_started_ns": events[0]["monotonic_ns"],
        "first_request_started_ns": starts[0]["monotonic_ns"],
        "observed_ns": time.monotonic_ns(),
    }


def observe_and_fault(
    bound,
    *,
    authority,
    source_ref,
    expected_argv,
    start_id,
    enrollment,
    timeout_s,
    before_signal,
):
    """Runner primitive: independent reobservation then exactly one pidfd signal.

    before_signal must validate the registered original client timing barrier and
    retain it before the fault. It cannot choose a PID or alter the target binding.
    The caller owns evidence persistence and all cleanup. This never restarts Host.
    """
    require(
        bound["schema"] == BINDING and bound["start_id"] == start_id,
        "wrong observer binding domain/start",
    )
    require(
        bound["authority"] == authority and identity(authority["pid"]) == authority,
        "authority epoch differs",
    )
    require(bound["enrollment_sha256"] == enrollment, "stale enrollment")
    require(
        bound["source"] == source_ref and bound["argv"] == expected_argv,
        "unregistered observer source/argv",
    )
    require(
        "sha256:" + hashlib.sha256(Path(source_ref["path"]).read_bytes()).hexdigest()
        == source_ref["sha256"],
        "observer source changed",
    )
    target = bound["observer"]
    _, descendants = owned_sessions(authority)
    require(
        descendants.get(target["pid"]) == target and target != authority,
        "target is not the distinct current observer",
    )
    actual_argv = [
        s.decode()
        for s in Path(f"/proc/{target['pid']}/cmdline").read_bytes().split(b"\0")
        if s
    ]
    require(actual_argv == expected_argv, "observer command changed")
    require(timeout_s > 0, "missing frozen death timeout")
    fd = os.pidfd_open(target["pid"])
    try:
        require(
            identity(target["pid"]) == target, "observer epoch changed after pidfd open"
        )
        barrier = before_signal()
        require(
            barrier["start_id"] == start_id
            and barrier["client_started_ns"]
            <= barrier["observed_ns"]
            <= time.monotonic_ns(),
            "original client barrier differs",
        )
        require(
            barrier["enrollment_sha256"] == enrollment, "barrier enrollment differs"
        )
        # Recheck while holding the actual kernel handle; no numeric-PID fallback.
        require(identity(target["pid"]) == target, "observer changed before signal")
        triggered = time.monotonic_ns()
        signal.pidfd_send_signal(fd, signal.SIGKILL)
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        require(bool(poller.poll(int(timeout_s * 1000))), "observer death timeout")
        dead = time.monotonic_ns()
    finally:
        os.close(fd)
    return {
        "schema": RAW,
        "start_id": start_id,
        "binding": bound,
        "client_barrier": barrier,
        "fault": {"target": target, "signal": "SIGKILL", "triggered_ns": triggered},
        "pidfd_observed_dead_ns": dead,
        "formal_result": False,
        "objective_met": None,
    }


def validate_raw(
    raw, bound, *, authority_events, independent_host_kernels, original_host_kernels
):
    """Distinct evidence gate. Workload/recovery/cleanup still need original intake.

    Never turns the observer-death primitive into an admitted complete formal row.
    """
    require(
        raw["schema"] == RAW and raw["binding"] == bound,
        "worker/legacy/replayed raw cannot satisfy observer-loss",
    )
    require(
        raw["start_id"] == bound["start_id"]
        and raw["fault"]["target"] == bound["observer"],
        "actual observer target differs",
    )
    require(raw["fault"]["signal"] == "SIGKILL", "observer signal differs")
    trigger, dead = raw["fault"]["triggered_ns"], raw["pidfd_observed_dead_ns"]
    require(bound["observed_ns"] < trigger <= dead, "observer event ordering differs")
    require(
        len(original_host_kernels) == 3
        and all(k != bound["observer"] for k in original_host_kernels),
        "observer target aliases original Host member",
    )
    host_preserved = independent_host_kernels == original_host_kernels
    closed = [
        e
        for e in authority_events
        if e["kind"] == "observer.loss.observed"
        and e["authority"] == bound["authority"]
        and e["detail"].get("observer") == bound["observer"]
    ]
    require(
        len(closed) == 1
        and closed[0]["monotonic_ns"] >= trigger
        and closed[0]["route"]["generation"] is None,
        "independent exact-observer loss event missing",
    )
    require(
        any(
            e["kind"] == "route.closed"
            and e["authority"] == bound["authority"]
            and e["detail"].get("reason") == "original observer lost"
            and trigger <= e["monotonic_ns"] <= closed[0]["monotonic_ns"]
            and e["route"]["generation"] is None
            for e in authority_events
        ),
        "actual fail-close route event missing",
    )
    require(
        not any(
            e["kind"] == "route.open.applied"
            and e["monotonic_ns"] > closed[0]["monotonic_ns"]
            for e in authority_events
        ),
        "route reopened without fresh observer enrollment",
    )
    return {
        "actual_observer_fault_observed": True,
        "host_preserved_after_fault": host_preserved,
        "formal_result": False,
        "objective_met": None,
        "unverified_obligations": [
            "original-window-source-intake",
            "recovery-and-operator-actions",
            "predecessor-fate",
            "backend-execution-duplication",
            "external-ownership-and-cleanup",
        ],
    }


def intake_observer_artifacts(
    *,
    raw_path,
    journal_path,
    expected_binding,
    expected_policy_sha256,
    original_host_kernels,
):
    """Read unchanged original authority chain; never accept a caller event list.

    Registration/source admission of the expected binding/policy is a separate
    prerequisite. This routine alone deliberately cannot mark formal admission.
    """
    from experiments.formal_campaign.h3_dynamic_authority import read_dynamic_journal
    from experiments.formal_campaign.h3_observer_authority import JOURNAL

    events = read_dynamic_journal(journal_path, domain=JOURNAL)
    require(
        events[0]["authority"] == expected_binding["authority"]
        and events[0]["policy_sha256"] == expected_policy_sha256,
        "original authority journal epoch/policy differs",
    )
    bound_events = [
        e
        for e in events
        if e["kind"] == "observer.actual-bound"
        and e["detail"].get("binding") == expected_binding
    ]
    require(
        len(bound_events) == 1, "exact source-owned observer journal binding missing"
    )
    path = Path(raw_path)
    require(not path.is_symlink() and path.is_file(), "observer raw must be regular")
    raw = json.loads(path.read_bytes())
    require(
        bound_events[0]["monotonic_ns"] < raw["fault"]["triggered_ns"],
        "source observer registration occurred after fault",
    )
    current = [identity(k["pid"]) for k in original_host_kernels]
    return validate_raw(
        raw,
        expected_binding,
        authority_events=events,
        independent_host_kernels=current,
        original_host_kernels=original_host_kernels,
    )


def observe_host_kernels(expected):
    """Retain real downstream Host loss as an outcome, never as another target."""
    observed = []
    for kernel in expected:
        try:
            observed.append(identity(kernel["pid"]))
        except (OSError, ValueError):
            observed.append(None)
    return observed


def verify_terminal_witness(
    accounting,
    witness,
    *,
    original_host_kernels,
    client_trace,
    expected_client,
    start_id,
    launch_ns,
    dead_ns,
):
    """Derive Host preservation from exact epochs; a summary cannot hide loss."""
    require(
        len(original_host_kernels) == 3, "actual original API+TP2 membership required"
    )
    starts = [e for e in client_trace if e["kind"] == "client.start"]
    stops = [e for e in client_trace if e["kind"] == "client.stop"]
    require(
        len(starts) == len(stops) == 1
        and starts[0]["detail"]["start_id"] == start_id
        and all(e["client"] == expected_client for e in client_trace),
        "terminal witness refers to another original client trace",
    )
    stop = stops[0]["monotonic_ns"]
    require(
        launch_ns <= starts[0]["monotonic_ns"] <= dead_ns <= stop
        and witness["client_stop_ns"] == stop
        and stop <= accounting["observed_ns"] <= witness["observed_ns"]
        and witness["replacement_committed"] is False
        and accounting["replacement_committed"] is False,
        "original chained client.stop/carrier/independent terminal clocks differ",
    )
    carrier_preserved = (
        accounting["host_kernels_at_client_stop"] == original_host_kernels
    )
    independently_preserved = witness["host_kernels"] == original_host_kernels
    consistent = (
        accounting["predecessor_alive_through_client_window"] is carrier_preserved
        and witness["host_preserved"] is independently_preserved
    )
    return {
        "host_preserved": carrier_preserved and independently_preserved,
        "summary_consistent": consistent,
        "client_stop_ns": stop,
        "terminal_ns": witness["observed_ns"],
    }


def verify_independent_partial_terminal(
    marker, *, context, epochs, fault, dead_ns, cleanup_started_ns
):
    """Bind a genuine failed start without inventing carrier success/client.stop."""
    require(
        marker["schema"] == "ecpa-h3-observer-independent-runner-terminal/v1"
        and marker["context"] == context
        and marker["run_epochs"] == epochs
        and marker["start_id"] == context["start_id"]
        and marker["fault"] == fault
        and marker["observed_dead_ns"] == dead_ns
        and marker["carrier_complete"] is False
        and dead_ns <= marker["observed_ns"] <= cleanup_started_ns,
        (
            "partial terminal differs from actual independently observed "
            "start/epochs/fault/death"
        ),
    )
    return {
        "kind": "independent-runner-failed-start",
        "client_stop_ns": None,
        "terminal_ns": marker["observed_ns"],
        "host_preserved": None,
        "summary_consistent": None,
    }


def verify_first_request_prefix(
    prefix_path,
    barrier,
    *,
    start_id,
    enrollment,
    client_spec_path,
    expected_client,
    fault_ns,
):
    """Original chained pre-fault source proof survives a later incomplete trace."""
    from experiments.formal_campaign.h3_client_trace import read_client_trace
    from experiments.formal_campaign.h3_dynamic_authority import check_ref

    require(
        barrier["client_prefix"]["path"] == str(prefix_path),
        "first-request proof belongs to another start output",
    )
    checked = check_ref(barrier["client_prefix"])
    events = read_client_trace(checked)
    spec_raw = Path(client_spec_path).read_bytes()
    spec = json.loads(spec_raw)
    if "client_spec" in barrier:
        require(
            barrier["client_spec"]["path"] == str(client_spec_path)
            and check_ref(barrier["client_spec"]).read_bytes() == spec_raw,
            "original client spec raw reference differs",
        )
    starts = [e for e in events if e["kind"] == "request.start"]
    require(
        events
        and events[0]["kind"] == "client.start"
        and starts
        and events[0]["detail"]["start_id"] == start_id
        and spec["start_id"] == start_id
        and spec["initial_enrollment_sha256"]
        == barrier["enrollment_sha256"]
        == enrollment
        and events[0]["detail"]["spec_sha256"]
        == "sha256:" + hashlib.sha256(canonical(spec)).hexdigest()
        and all(e["client"] == expected_client for e in events),
        "original first-request source/spec/client/enrollment proof differs",
    )
    require(
        barrier["client_started_ns"] == events[0]["monotonic_ns"]
        and barrier["first_request_started_ns"] == starts[0]["monotonic_ns"]
        and events[-1]["monotonic_ns"] <= barrier["observed_ns"] < fault_ns,
        "original first-request clock differs from actual observer fault",
    )
    require(
        starts[0]["detail"]["request_id"]
        in {f"{start_id}/request-{i:05d}" for i in range(60)}
        and base64.b64decode(starts[0]["detail"]["body_base64"], validate=True)
        == canonical(spec["payload"]),
        "actual pre-fault request differs from original60 payload/identity",
    )
    return True
