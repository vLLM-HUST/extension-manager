"""After-cleanup H4 sampled intake: original272 traffic and32 full proofs.

This is independent archived verification, not a lifecycle receipt projection.
No dead PID is treated as current: actual role epochs are cross-joined to raw
/proc resource samples and an independent root cleanup witness supplied by root.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from experiments.formal_campaign import h4_owned_resources
from experiments.formal_campaign.analyze import (
    h4_decode_body,
    h4_request_identity_observation,
    h4_request_payload,
    h4_response_summary,
    load_h4_campaign,
)
from experiments.formal_campaign.h3_native_authority import native_host_roster
from experiments.formal_campaign.h3_runtime_source_closure import (
    verify_runtime_source_closure,
)
from experiments.formal_campaign.h4_npu_observation import decode_observation
from experiments.formal_campaign.h4_sampled_native_schedule import (
    bind_selected_phases,
)
from experiments.formal_campaign.h4_sampled_native_source_scope import (
    scope_native_senders,
)
from experiments.pair_semantic_candidate import authority as pair
from experiments.pair_semantic_candidate.binding import PROFILER
from vllm_hust_ext.host_evidence import parse_host_event

from .h4_sampled_native_replay import check_ref, replay_sampled_native_report
from .h4_sampled_registration import (
    build_plan_guard,
    checked,
    read_registered_schedule,
    validate_inputs,
    verify_sampled_protocol_sources,
)
from .h4_sampled_registration import (
    validate_original_receipt as validate_receipt,
)

canonical, require = pair.canonical, pair.require


def same(a, b):
    return canonical(a) == canonical(b)


def read(path):
    path = Path(path)
    require(
        path.is_absolute() and path.resolve() == path and not path.is_symlink(),
        "unsafe archive path",
    )
    return json.loads(path.read_bytes())


def verify_traffic(rows, schedule, payload, *, allow_incomplete=False):
    """Recompute all272 body/status/latency/identity rows, never selected-only."""
    require(
        type(allow_incomplete) is bool
        and len(schedule["requests"]) == 272
        and (len(rows) <= 272 if allow_incomplete else len(rows) == 272),
        "original272 coverage incomplete",
    )
    indexed = {}
    for row in rows:
        index = row["all_index"]
        require(
            type(row["native_verified"]) is bool,
            "typed original native result required",
        )
        require(
            type(index) is int and index not in indexed and 0 <= index < 272,
            "duplicate/invalid original request index",
        )
        declaration = schedule["requests"][index]
        require(
            row["request_id"] == declaration["request_id"]
            and type(row["selected"]) is bool
            and row["selected"] is declaration["selected"]
            and row["kind"] == ("warmup" if index < 16 else "measured")
            and h4_decode_body(row["http_request"]) == payload
            and hashlib.sha256(payload).hexdigest() == declaration["body_sha256"],
            "request identity/body/selection changed",
        )
        require(
            type(row["dispatch_ns"]) is int
            and type(row["complete_ns"]) is int
            and 0 < row["dispatch_ns"] <= row["complete_ns"],
            "original RAW clocks invalid",
        )
        summary = h4_response_summary(row["http_response"])
        require(
            all(same(row[key], value) for key, value in summary.items()),
            "HTTP summary changed",
        )
        if row["http_response"] is not None:
            observed = h4_request_identity_observation(
                row["request_id"], row["request_headers"], row["http_response"]
            )
            require(
                same(observed, row["request_identity"]),
                "HTTP request-ID metadata changed",
            )
            require(
                observed["server_header_matches_sent_request_id"] is not False
                and observed["server_completion_matches_sent_request_id"] is not False,
                "returned actual request ID conflicts",
            )
        clock = row["native_clock"]
        require(
            type(clock["sent_ns"]) is int
            and type(clock["deadline_ns"]) is int
            and clock["deadline_ns"] - clock["sent_ns"] == 120_000_000_000,
            "original120 deadline changed",
        )
        if row["http_response"] is not None:
            require(
                type(clock["backend_sent_ns"]) is int
                and type(clock["received_ns"]) is int
                and clock["sent_ns"] <= clock["backend_sent_ns"] <= clock["received_ns"]
                and clock["http_deadline_met"]
                is (clock["received_ns"] <= clock["deadline_ns"]),
                "all272 actual HTTP send/receive/absolute-deadline evidence differs",
            )
            if clock["received_ns"] > clock["deadline_ns"]:
                require(
                    type(row["error"]) is str
                    and bool(row["error"])
                    and row["native_verified"] is False,
                    "late HTTP response mislabeled as successful request",
                )
        else:
            require(
                clock["received_ns"] is None
                and clock["http_deadline_met"] is None
                and type(row["error"]) is str
                and bool(row["error"])
                and row["native_verified"] is False,
                "missing HTTP outcome cannot supply on-time success",
            )
        if not declaration["selected"]:
            require(
                row["native_verified"] is False and not row.get("native_report"),
                "unselected request carries false semantic qualification",
            )
        indexed[index] = row
    if not allow_incomplete:
        require(set(indexed) == set(range(272)), "missing original requests")
    measured = [r for i, r in indexed.items() if i >= 16]
    if measured:
        require(
            set(range(16)) <= set(indexed),
            "measured traffic lacks completed original warmups",
        )
        require(
            max(indexed[i]["complete_ns"] for i in range(16))
            <= min(r["dispatch_ns"] for r in measured),
            "measured requests started before original warmup HTTP completed",
        )
    boundaries = sorted(
        (r[k], delta)
        for r in rows
        for k, delta in (("dispatch_ns", 1), ("complete_ns", -1))
    )
    active = 0
    for _, delta in boundaries:
        active += delta
        require(0 <= active <= 8, "actual HTTP window exceeds original concurrency8")
    return [indexed[i] for i in sorted(indexed)]


def coherent_roster(archive, owner, roster, kernels):
    """A single independent raw /proc sample must contain all actual roles."""
    require(
        same(archive["root"], owner)
        and set(roster) == set(kernels)
        and set(roster)
        == {"api-server/0", "engine-core-scheduler/0", "worker/0", "worker/1"},
        "actual pair four-role roster differs",
    )
    for slot, process in roster.items():
        k = kernels[slot]
        require(
            set(k) == {"pid", "start_ticks", "session", "boot_id"}
            and process["assignment_source"] == "host"
            and type(process["ordinal"]) is int
            and process["pid"] == k["pid"]
            and process["start_identity"]
            == f"pid:{k['pid']}:start_ticks:{k['start_ticks']}",
            "Host role is not the original exact kernel epoch",
        )
    require(
        len({canonical(k) for k in kernels.values()}) == 4, "Host role epochs alias"
    )
    for sample in archive["samples"]:
        members = {m["pid"]: m for m in sample["members"]}
        if all(
            k["pid"] in members
            and same(
                {
                    name: members[k["pid"]][name]
                    for name in ("pid", "start_ticks", "session")
                },
                {name: k[name] for name in ("pid", "start_ticks", "session")},
            )
            and k["boot_id"] == owner["boot_id"]
            for k in kernels.values()
        ):
            return sample
    raise ValueError("no independent coherent four-role process sample")


def verify_profiler(record, report_ref, epoch, final_host_raw):
    path = Path(record["profiler_snapshot"])
    require(
        path.parent == Path(report_ref["path"]).parent,
        "profiler snapshot escapes request archive",
    )
    raw = path.read_bytes()
    require(
        hashlib.sha256(raw).hexdigest() == record["profiler_snapshot_sha256"]
        and final_host_raw.startswith(raw)
        and raw.endswith(b"\n"),
        "profiler original prefix changed",
    )
    before_count = None
    hasher = hashlib.sha256()
    if hasher.hexdigest() == record["profiler_before_prefix_sha256"]:
        before_count = 0
    lines = raw.splitlines(keepends=True)
    for index, line in enumerate(lines, 1):
        hasher.update(line)
        if hasher.hexdigest() == record["profiler_before_prefix_sha256"]:
            require(before_count is None, "ambiguous original profiler prefix")
            before_count = index
    require(before_count is not None, "original profiler-before prefix missing")
    events = [parse_host_event(line) for line in lines]
    runtime = record["full_archive"]["attention_complete_transactions"]
    selected = [t for t in runtime if t["phase_id"] == record["phase"]["phase_id"]]
    require(len(selected) == 1, "profiler native request join ambiguous")
    occurrence = hashlib.sha256(
        ("request_finished\0" + selected[0]["runtime_request_id"]).encode()
    ).hexdigest()
    require(
        occurrence == record["profiler_occurrence_id"],
        "profiler callback bound to another opaque runtime",
    )
    matched = []
    for event in events:
        require(
            event["plan_id"] == epoch["enrollment"]["native_plan_id"]
            and event["launch_id"] == epoch["enrollment"]["native_launch_id"],
            "profiler mixed epoch",
        )
        process = event["process"]
        slot = f"{process['role']}/{process['ordinal']}"
        if process["assignment_source"] == "host":
            require(
                slot in epoch["roster"] and same(process, epoch["roster"][slot]),
                "profiler kernel changed",
            )
        else:
            # Match the live _profiler_snapshot rule exactly. Environment-only
            # unknown loader events can precede assignment, never substitute an
            # API/scheduler effective callback or an arbitrary process epoch.
            originals = {
                canonical(
                    {
                        k: v
                        for k, v in original.items()
                        if k not in {"role", "ordinal", "assignment_source"}
                    }
                )
                for original in epoch["roster"].values()
            }
            require(
                process["assignment_source"] == "environment"
                and process["role"] == "unknown"
                and event["event"] in {"discovered", "resolved"}
                and event["observation_kind"] == "loader_lifecycle"
                and canonical(
                    {
                        k: v
                        for k, v in process.items()
                        if k not in {"role", "ordinal", "assignment_source"}
                    }
                )
                in originals,
                "unbound profiler journal process has no exact assigned epoch",
            )
    for event in events[before_count:]:
        if (
            event["event"] == "effective"
            and event["observation_kind"] == "runtime_effective"
            and event["detail"] == "request-lifecycle-eventbus:request_finished"
            and event["occurrence_id"] == occurrence
            and tuple(event["entry_point"][k] for k in ("group", "name", "value"))
            == pair.ENTRIES[PROFILER]
            and event["process"]["role"] in {"api-server", "engine-core-scheduler"}
            and event["process"]["ordinal"] == 0
        ):
            require(
                record["profiler_before_wall_ns"]
                <= event["observed_at_ns"]
                <= record["profiler_after_wall_ns"],
                "profiler callback outside original read interval",
            )
            matched.append(event)
    require(
        matched and same(matched, record["profiler_matched_events"]),
        "same-request profiler finished proof missing",
    )


def verify_root_cleanup(root_ref, output, owner, kernels, ports):
    """Explicit independent root witness, not runner's self-reported booleans.

    Root observer must capture this schema/raw terminal NPU observation for this
    new domain. This consumer does not invent or synthesize that missing witness.
    """
    root = json.loads(check_ref(root_ref).read_bytes())
    require(
        root["schema"] == "ecpa-h4-sampled-independent-root-terminal/v1"
        and root["run_directory"] == str(output)
        and same(root["product_root"], owner)
        and root["released"] is True
        and root["remaining_observed_epochs"] == []
        and set(root["open_ports"]) == {str(p) for p in ports}
        and all(type(v) is bool and v is False for v in root["open_ports"].values()),
        "independent root cleanup absent/incomplete",
    )
    observed = root["all_observed_epochs"]
    for expected in (owner, *kernels.values()):
        require(
            any(same({k: item[k] for k in expected}, expected) for item in observed),
            "independent root observer did not retain actual role epoch",
        )
    npu = json.loads(check_ref(root["terminal_npu_observation"]).read_bytes())
    raw, _ = decode_observation(npu)
    require(b"Process id" in raw, "actual terminal process table absent")
    for device in (0, 3):
        require(
            f"No running processes found in NPU {device}".encode() in raw,
            "actual device not process empty",
        )
    return root


def pinned_terminal(root, output):
    """Check all original file-presence decisions against independent root bytes."""
    names = (
        "source-admission.json",
        "phase0.product-popen-timing.json",
        "actual-runtime-closure.json",
        "sampled-source-result.json",
        "sampled-epoch-archive.json",
        "request-results.jsonl",
        "all272-request-results.json",
        "owned-resources.json",
    )
    expected = {str(output / name) for name in names if (output / name).exists()}
    require(set(root["terminal_artifacts"]) == expected, "terminal file set changed")
    for name, digest in root["terminal_artifacts"].items():
        check_ref(dict(path=name, sha256=digest))


def failed_observation(campaign, start, root_ref, *, rows, verified, reason):
    """An admitted actual failure is retained; unknown metrics are never zero."""
    return dict(
        schema="ecpa-h4-sampled-native-independent-start-observation/v1",
        start_id=start["start_id"],
        cell_id=campaign["cell_id"],
        arm=start["arm"],
        repetition=start["repetition"],
        arm_order=start["arm_order"],
        formal_start_validated=True,
        start_validation="source-admitted-actual-sampled-start",
        status="failed",
        observed_failure=reason,
        coverage="complete-observed" if len(rows) == 272 else "incomplete-observed",
        full_native_sample_count=len(verified),
        all_http_request_count=len(rows),
        successful_measured=None,
        source_native_complete=False,
        resources=None,
        performance_eligible=False,
        phase_bins=None,
        phase_bins_status="unavailable",
        independent_root_cleanup=root_ref,
        formal_result=False,
        H4_hypothesis_claim=False,
        limitation=(
            "Authenticated negative start only; "
            "no successful native token or performance claim"
        ),
    )


def verify_present_native_history(boot):
    """Validate every original fact with no ACK/completion invented from a prefix.

    The private oracle retains every source, sender, epoch, tensor, OP and ACK
    predicate. Its typed incomplete drain result is allowed only in this offline
    negative-observation path; it cannot mint a native request proof.
    """
    from experiments.native_attention_candidate.attention_consumer import (
        _verify_attention_archive,
    )

    from . import h4_sampled_native_collector

    root = Path(boot["output"])
    journal = root / "native.jsonl"
    if not journal.exists():
        require(
            not (root / "snapshots").exists()
            or not any((root / "snapshots").iterdir()),
            "native snapshots exist without original journal",
        )
        return None
    return _verify_attention_archive(
        root / "native-spec.json",
        root / "tensor-policy.json",
        journal,
        drain_policy_path=root / "drain-policy.json",
        drain_protocol=h4_sampled_native_collector,
        acknowledged_prefix=None,
        _owner=object(),
        _allow_incomplete=True,
    )


def independent_runner_signal(root, root_ref, expected_argv):
    """Authenticate a real negative Popen wait result against its original epoch."""
    terminal = root.get("runner_terminal")
    if terminal is None:
        return None
    require(
        type(terminal) is dict
        and set(terminal)
        == {
            "schema",
            "kernel",
            "returncode",
            "kind",
            "signal",
            "popen",
            "observed_monotonic_ns",
            "wait_api",
        },
        "malformed independent runner termination",
    )
    require(
        terminal["schema"] == "ecpa-h4-independent-runner-terminal/v1"
        and terminal["wait_api"] == "subprocess.Popen.poll"
        and type(terminal["returncode"]) is int
        and type(root["runner_exit_code"]) is int
        and terminal["returncode"] == root["runner_exit_code"],
        "independent runner exit ABI differs",
    )
    path = check_ref(terminal["popen"])
    require(
        path == Path(root_ref["path"]).parent / "actual-runner-Popen.json",
        "runner Popen witness moved to another observation",
    )
    launch = read(path)
    kernel = {
        k: launch["kernel"][k] for k in ("pid", "start_ticks", "session", "boot_id")
    }
    require(
        same(kernel, terminal["kernel"])
        and launch["argv"] == expected_argv
        and type(launch["observed_monotonic_ns"]) is int
        and type(terminal["observed_monotonic_ns"]) is int
        and 0 < launch["observed_monotonic_ns"] <= terminal["observed_monotonic_ns"]
        and any(
            same({k: epoch[k] for k in kernel}, kernel)
            for epoch in root["all_observed_epochs"]
        ),
        "independent runner signal lacks exact source command/kernel/clock witness",
    )
    if terminal["returncode"] >= 0:
        require(
            terminal["kind"] == "exit" and terminal["signal"] is None,
            "ordinary exit mislabeled as signal termination",
        )
        return None
    require(
        terminal["kind"] == "signal"
        and type(terminal["signal"]) is int
        and terminal["signal"] == -terminal["returncode"],
        "actual negative signal wait result differs",
    )
    return dict(kind="independently-observed-runner-signal", terminal=terminal)


def no_epoch_runtime_cause(outcome, root, root_ref, expected_argv, admission):
    """No generic nonzero or schema/integrity error becomes formal failure."""
    require(root.get("released") is True, "independent cleanup not released")
    require(
        type(root.get("runner_exit_code")) is int, "typed actual runner exit required"
    )
    signal = independent_runner_signal(root, root_ref, expected_argv)
    if outcome is not None:
        require(
            outcome["schema"] == "ecpa-h4-sampled-live-source-observation/v1",
            "wrong source outcome schema",
        )
        if outcome.get("failure_category") == "unqualified-verification-error":
            raise ValueError(
                "explicit source/schema/ABI/integrity failure remains unqualified"
            )
        category = outcome.get("failure_category")
        if category is not None:
            require(
                category == "runtime-interruption", "unknown source failure taxonomy"
            )
            event = outcome.get("runtime_interruption")
            require(
                type(event) is dict
                and set(event)
                == {
                    "schema",
                    "family",
                    "exception_type",
                    "observed_monotonic_ns",
                    "observed_raw_ns",
                }
                and event["schema"] == "ecpa-h4-source-runtime-interruption/v1"
                and event["family"] in {"timeout", "connection", "process-timeout"}
                and event["exception_type"]
                in {
                    "timeout": {"builtins.TimeoutError"},
                    "connection": {
                        "builtins.ConnectionError",
                        "builtins.ConnectionRefusedError",
                        "builtins.ConnectionResetError",
                        "builtins.ConnectionAbortedError",
                        "builtins.BrokenPipeError",
                        "http.client.RemoteDisconnected",
                    },
                    "process-timeout": {"subprocess.TimeoutExpired"},
                }[event["family"]]
                and type(outcome.get("failure_observed_monotonic_ns")) is int
                and type(outcome.get("failure_observed_raw_ns")) is int
                and type(event["observed_monotonic_ns"]) is int
                and type(event["observed_raw_ns"]) is int
                and admission["before_monotonic_ns"]
                <= event["observed_monotonic_ns"]
                <= outcome["failure_observed_monotonic_ns"]
                and admission["after_ns"]
                <= event["observed_raw_ns"]
                <= outcome["failure_observed_raw_ns"]
                and type(outcome.get("failure")) is str
                and bool(outcome["failure"]),
                "runtime interruption lacks source-owned typed cause/clocks",
            )
            return dict(kind="source-observed-runtime-interruption", source=event)
        require(
            outcome.get("failure") is None
            and outcome.get("runtime_interruption") is None,
            "untyped source failure remains unqualified",
        )
    require(
        signal is not None, "generic nonzero exit or missing cause remains unqualified"
    )
    return signal


def intake(campaign_path, launch_path, receipt_path, start_id, root_cleanup_ref):
    campaign, launch, workload, native = validate_inputs(
        campaign_path, launch_path, require_fresh_paths=False
    )
    receipt = read(receipt_path)
    validate_receipt(receipt, load_h4_campaign(Path(campaign_path)), Path(receipt_path))
    verify_sampled_protocol_sources(
        native,
        Path(native["repositories"]["manager"]["path"]),
        campaign["fixed_identity"]["manager_commit"],
    )
    starts = [s for s in native["starts"] if s["start_id"] == start_id]
    require(len(starts) == 1, "unknown/duplicate original start")
    start = starts[0]
    output = Path(start["run_directory"])
    phase = json.loads(checked(start["phase"]))
    guard = build_plan_guard(campaign, native, start, receipt)
    closure = verify_runtime_source_closure(
        phase,
        campaign["fixed_identity"],
        native["repositories"],
        native["runtime_wheels"],
    )
    require(
        same(closure, read(output / "actual-runtime-closure.json")),
        "actual source/wheel closure differs from launch",
    )
    plan, invocations = (
        guard.verify_plan_current()
    )  # full sources + actual2 artifacts, no dead-PID check
    from .run_h4_sampled import source_admission

    admission = read(output / "source-admission.json")
    timing = read(output / "phase0.product-popen-timing.json")
    require(
        same(
            admission,
            source_admission(
                campaign,
                start,
                receipt,
                phase,
                closure,
                guard.launch,
                timing["actual_kernel"],
                timing,
            ),
        ),
        "actual product source admission changed",
    )
    require(
        type(timing["before_ns"]) is int
        and type(timing["after_ns"]) is int
        and 0 < timing["before_ns"] <= timing["after_ns"]
        and timing["argv"] == phase["argv"],
        "actual Popen clocks/argv changed",
    )
    root = json.loads(check_ref(root_cleanup_ref).read_bytes())
    require(
        root["execution_domain"] == "registered-original-start",
        "qualification cannot become formal start",
    )
    # This version's source-owned root producer always writes this raw fact.
    # Validate it for every registered result, including complete positive rows.
    # Old root artifacts cannot borrow the new source qualification.
    require(
        type(root.get("runner_terminal")) is dict,
        "registered start lacks mandatory independent runner terminal",
    )
    registered_runner_argv = [
        phase["argv"][0],
        "-m",
        "experiments.formal_campaign.run_h4_sampled",
        "--campaign",
        str(campaign_path),
        "--launch-spec",
        str(launch_path),
        "--deployment-receipt",
        str(receipt_path),
        "--start-id",
        start_id,
    ]
    independent_runner_signal(root, root_cleanup_ref, registered_runner_argv)
    pinned_terminal(root, output)
    epoch_path = output / "sampled-epoch-archive.json"
    if not epoch_path.exists():
        # Full source admission occurred in the real Popen callback. No native
        # enrollment/proof is fabricated when startup failed before it existed.
        verify_root_cleanup(
            root_cleanup_ref,
            output,
            admission["owner"],
            {},
            native["allocated_tcp_ports"],
        )
        require(
            not (output / "request-results.jsonl").exists()
            and not (output / "all272-request-results.json").exists()
            and not Path(phase["native_bootstrap"]["output"]).exists(),
            "pre-enrollment failure carries unexplained native/request facts",
        )
        result_path = output / "sampled-source-result.json"
        outcome = read(result_path) if result_path.exists() else None
        cause = no_epoch_runtime_cause(
            outcome, root, root_cleanup_ref, registered_runner_argv, admission
        )
        return failed_observation(
            campaign,
            start,
            root_cleanup_ref,
            rows=[],
            verified=[],
            reason=dict(
                kind="post-Popen-startup-failure",
                authenticated_runtime_cause=cause,
                runner_exit_code=root["runner_exit_code"],
                source_failure=outcome["failure"] if outcome else None,
            ),
        )
    epoch = read(epoch_path)
    require(
        epoch["schema"] == "ecpa-h4-sampled-actual-epoch-archive/v1",
        "wrong actual epoch domain",
    )
    result_path = output / "sampled-source-result.json"
    if result_path.exists():
        result = read(result_path)
    else:
        require(
            root["runner_exit_code"] != 0,
            "missing terminal result without actual runner failure",
        )
        # Only observed nonzero exit supplies this negative outcome; no cleanup
        # or request-success flags are manufactured from the absent source file.
        result = dict(failure=None, resources=None)
    timing = read(output / "phase0.product-popen-timing.json")
    require(
        same(timing["actual_kernel"], epoch["owner"])
        and timing["argv"] == phase["argv"],
        "actual product launch changed",
    )
    require(
        epoch["enrollment"]["semantic_context"]
        == {
            k: guard.launch[k]
            for k in (
                "execution_plan_id",
                "controller_instance",
                "candidate_generation",
                "membership_epoch",
            )
        }
        and epoch["enrollment"]["native_plan_id"] == guard.launch["native_plan_id"],
        "full semantic context/Plan differs",
    )
    if result_path.exists():
        require(
            not result["cleanup_errors"]
            and result.get("actual_epochs_gone") is True
            and result.get("actual_ports_closed") is True,
            "original source cleanup incomplete",
        )
    # Missing final resource archive after a real nonzero runner exit is not
    # replaced with zeros. Full independent root role/cleanup joins still apply.
    resource_path = output / "owned-resources.json"
    resources = None
    if resource_path.exists():
        stored_resources = read(resource_path)
        resources = h4_owned_resources.verify_archive(
            resource_path,
            epoch["owner"],
            result.get("resources")
            if result_path.exists()
            else stored_resources["resources"],
        )
        require(
            resources["device_command"] == launch["npu_memory_command"],
            "registered resource observation changed",
        )
        coherent_roster(resources, epoch["owner"], epoch["roster"], epoch["kernels"])
    else:
        require(
            root["runner_exit_code"] != 0,
            "resource archive missing without actual runner failure",
        )
    raw = (output / "final-original-Host.jsonl").read_bytes()
    require(
        hashlib.sha256(raw).hexdigest() == epoch["host_journal_sha256"],
        "original Host bytes changed",
    )
    events = [parse_host_event(line) for line in raw.splitlines()]
    require(
        same(
            native_host_roster(
                events,
                epoch["enrollment"]["native_plan_id"],
                epoch["enrollment"]["native_launch_id"],
            ),
            epoch["roster"],
        ),
        "original Host roster changed",
    )
    for invocation in (
        *invocations,
        {
            "entry_point": dict(
                zip(("group", "name", "value"), pair.ENTRIES[PROFILER], strict=True)
            ),
            "role": "api-server",
            "required_ordinals": [0],
        },
        {
            "entry_point": dict(
                zip(("group", "name", "value"), pair.ENTRIES[PROFILER], strict=True)
            ),
            "role": "engine-core-scheduler",
            "required_ordinals": [0],
        },
    ):
        for ordinal in invocation["required_ordinals"]:
            require(
                any(
                    e["event"] == "invoked"
                    and e["observation_kind"] == "loader_lifecycle"
                    and same(e["entry_point"], invocation["entry_point"])
                    and e["process"]["role"] == invocation["role"]
                    and e["process"]["ordinal"] == ordinal
                    for e in events
                ),
                "full original loader obligation missing",
            )
    source_peers = epoch["enrollment"]["source_peers"]
    require(len(source_peers) == 3, "native peer slots missing")
    peer_slots = set()
    for peer in source_peers:
        process = peer["process"]
        slot = f"{process['role']}/{process['ordinal']}"
        require(
            slot in {"api-server/0", "worker/0", "worker/1"}
            and slot not in peer_slots
            and same(process, {**epoch["roster"][slot], **epoch["kernels"][slot]}),
            (
                "archived native peer is not exact untouched Host"
                "7 plus independently observed kernel4"
            ),
        )
        peer_slots.add(slot)
    membership = read(output / "phase0.actual-membership.json")
    require(len(membership) == 3, "original native membership incomplete")
    for member in membership:
        event = parse_host_event(canonical(member["event"]))
        slot = f"{member['role']}/{member['ordinal']}"
        require(
            slot in peer_slots
            and same(event["process"], epoch["roster"][slot])
            and same(
                member["identity"],
                {
                    **epoch["kernels"][slot],
                    "launch_id": epoch["enrollment"]["native_launch_id"],
                },
            )
            and event in events,
            "original membership event/kernel/launch changed",
        )
    require(
        len({(m["role"], m["ordinal"]) for m in membership}) == 3,
        "original membership slots duplicate",
    )
    handoff = read(output / "phase0.native-source-handoff.json")
    require(
        handoff["host_evidence"]["path"] == epoch["host_journal_original"],
        "original Host path mismatch",
    )
    require(
        same(handoff["record"]["publisher"], epoch["owner"]),
        "actual publisher not observed product root",
    )
    if start["arm"] == "ecpa":
        record = handoff["record"]
        raw_handoff = check_ref(handoff["raw"]).read_bytes()
        original = json.loads(raw_handoff)
        require(
            same({k: v for k, v in record.items() if k != "binding_sha256"}, original)
            and record["binding_sha256"] == hashlib.sha256(raw_handoff).hexdigest()
            and same(record["manager_source_sha256"], phase["manager_source_sha256"]),
            "Manager original handoff changed",
        )
    else:
        require(
            handoff["origin"] == "host-baseline"
            and "manager_source_sha256" not in handoff["record"],
            "baseline falsely attributed to Manager",
        )
    environment = handoff["record"]["environment"]
    require(
        environment["VLLM_ECPA_PLAN_ID"] == epoch["enrollment"]["native_plan_id"]
        and environment["VLLM_ECPA_LAUNCH_ID"]
        == epoch["enrollment"]["native_launch_id"],
        "actual handoff epoch differs",
    )
    boot = phase["native_bootstrap"]
    schedule, schedule_raw = read_registered_schedule(start["schedule"], boot["phases"])
    spec = read(Path(boot["output"]) / "native-spec.json")
    bind_selected_phases(spec, schedule)
    require(
        spec["native_plan_id"] == epoch["enrollment"]["native_plan_id"]
        and spec["native_launch_id"] == epoch["enrollment"]["native_launch_id"],
        "original full native history is for another Plan/launch",
    )
    senders, _ = scope_native_senders(
        epoch["peers"] if "peers" in epoch else epoch["enrollment"]["source_peers"],
        boot["source_files"],
    )
    require(
        same(spec["senders"], senders)
        and same(spec["phases"], boot["phases"])
        and same(spec["kv_requirements"], boot["kv_requirements"]),
        "original native declaration changed",
    )
    policy = read(Path(boot["output"]) / "tensor-policy.json")
    require(
        same(policy["requirements"], boot["tensor_requirements"]),
        "registered28layer tensor inventory changed",
    )
    payload = h4_request_payload(workload, launch["arms"][start["arm"]]["served_model"])
    trace_path = output / "request-results.jsonl"
    trace = trace_path.read_bytes() if trace_path.exists() else b""
    require(not trace or trace.endswith(b"\n"), "truncated original request row")
    rows = [json.loads(line) for line in trace.splitlines()]
    aggregate = output / "all272-request-results.json"
    if aggregate.exists():
        require(
            same(sorted(rows, key=lambda r: r["all_index"]), read(aggregate)),
            "original traffic copies diverge",
        )
    else:
        require(
            result["failure"] is not None or root["runner_exit_code"] != 0,
            "missing traffic aggregate without observed interruption",
        )
    rows = verify_traffic(rows, schedule, payload, allow_incomplete=True)
    from .h4_sampled_calibration import validate_calibration

    tokenization = validate_calibration(
        native["new_tokenizer_and_native_calibration"],
        campaign=campaign,
        launch=launch,
        workload=workload,
        native=native,
    )
    for row in rows:
        if row["http_response"] is not None and row["status_code"] == 200:
            response = json.loads(h4_decode_body(row["http_response"]))
            require(
                type(response["usage"]["prompt_tokens"]) is int
                and response["usage"]["prompt_tokens"]
                == len(tokenization["input_ids"]),
                (
                    "actual272 response tokenization differs from "
                    "independent full input IDs"
                ),
            )
    verified, prefixes = [], []
    for row in rows:
        if not row["selected"]:
            continue
        expected = (
            Path(boot["output"])
            / "snapshots"
            / hashlib.sha256(row["request_id"].encode()).hexdigest()
            / "native-consume-report.json"
        )
        reference = row.get("native_report")
        if reference is None:
            require(
                row["native_verified"] is False, "native success has no original report"
            )
            if not expected.exists():
                continue
            # A proof written before consume/response failure still gets full
            # replay. Missing summary flags cannot hide a corrupt report.
            stored = read(expected)
            reference = dict(
                path=str(expected),
                sha256=hashlib.sha256(expected.read_bytes()).hexdigest(),
                profiler_snapshot_path=stored["profiler_snapshot"],
                profiler_snapshot_sha256=stored["profiler_snapshot_sha256"],
            )
        require(
            Path(reference["path"]) == expected, "native proof moved to another request"
        )
        clock = row["native_clock"]
        if row["native_verified"]:
            require(
                row["native_error"] is None
                and row["error"] is None
                and type(clock.get("consumed_ns")) is int
                and clock["received_ns"]
                <= clock["consumed_ns"]
                <= clock["deadline_ns"],
                "native success was not consumed before original deadline",
            )
        response = h4_decode_body(row["http_response"])
        record = replay_sampled_native_report(
            reference,
            request_id=row["request_id"],
            request_body=payload,
            response_body=response,
            response_expectation={
                "min_completion_tokens": 16,
                "max_completion_tokens": 64,
            },
            enrollment=epoch["enrollment"],
            deadline_ns=clock["deadline_ns"],
        )
        require(
            all(
                Path(record[key]) == Path(boot["output"]) / filename
                for key, filename in (
                    ("native_spec", "native-spec.json"),
                    ("tensor_policy", "tensor-policy.json"),
                    ("drain_policy", "drain-policy.json"),
                )
            )
            and Path(record["journal"]) == expected.parent / "native.jsonl"
            and record["schema"] == "ecpa-h4-sampled-native-consume-report/v1"
            and record["schedule_sha256"] == hashlib.sha256(schedule_raw).hexdigest()
            and record["original_sent_ns"] == clock["sent_ns"]
            and record["backend_sent_ns"] == clock["backend_sent_ns"]
            and record["backend_received_ns"] == clock["received_ns"]
            and (
                not row["native_verified"]
                or record["verified_monotonic_ns"] <= clock["consumed_ns"]
            ),
            "sample original clocks/schedule differ",
        )
        verify_profiler(record, reference, epoch, raw)
        transaction = next(
            t
            for t in record["full_archive"]["attention_complete_transactions"]
            if t["phase_id"] == record["phase"]["phase_id"]
        )
        require(
            reference["profiler_snapshot_path"] == record["profiler_snapshot"]
            and reference["profiler_snapshot_sha256"]
            == record["profiler_snapshot_sha256"],
            "sample profiler summary differs",
        )
        if row.get("native_report") is not None:
            require(
                reference["runtime_request_id"] == transaction["runtime_request_id"]
                and reference["transaction_id"] == transaction["transaction_id"],
                "sample summary opaque request differs",
            )
        verified.append(transaction["runtime_request_id"])
        prefixes.append(Path(record["journal"]).read_bytes())
    require(len(verified) == len(set(verified)), "selected opaque requests alias")
    history = verify_present_native_history(boot)
    journal_path = Path(boot["output"]) / "native.jsonl"
    original_native = journal_path.read_bytes() if journal_path.exists() else b""
    require(
        all(original_native.startswith(prefix) for prefix in prefixes),
        "original global native history forks",
    )
    # Every snapshot report is accounted for, including reports for a request
    # whose completion row was lost. No orphan successful proof is silently skipped.
    snapshots = Path(boot["output"]) / "snapshots"
    existing_reports = (
        set(snapshots.glob("*/native-consume-report.json"))
        if snapshots.exists()
        else set()
    )
    accounted_reports = {
        snapshots
        / hashlib.sha256(r["request_id"].encode()).hexdigest()
        / "native-consume-report.json"
        for r in rows
        if r["selected"]
    }
    require(
        existing_reports <= accounted_reports,
        "native report lacks its original request row",
    )
    complete = (
        len(rows) == 272
        and len(verified) == 32
        and all(
            r["native_verified"] and r["native_error"] is None and r["error"] is None
            for r in rows
            if r["selected"]
        )
    )
    if complete:
        require(
            prefixes and max(prefixes, key=len) == original_native,
            "complete native proof has unverified global tail",
        )
    cleanup_path = output / "device-cleanup-command.json"
    if cleanup_path.exists():
        cleanup = read(cleanup_path)
        require(
            cleanup["argv"] == launch["device_cleanup_command"]
            and cleanup["exit_code"] == 0,
            "actual device cleanup command failed",
        )
        cleanup_body = json.loads(
            base64.b64decode(cleanup["stdout_base64"], validate=True)
        )
        smi, _ = decode_observation(cleanup_body["original_command"])
        require(
            cleanup_body["devices_reclaimed"] is True
            and all(
                f"No running processes found in NPU {d}".encode() in smi for d in (0, 3)
            ),
            "source terminal device bytes not empty",
        )
    else:
        require(
            root["runner_exit_code"] != 0,
            "source device evidence absent without actual runner failure",
        )
    verify_root_cleanup(
        root_cleanup_ref,
        output,
        epoch["owner"],
        epoch["kernels"],
        native["allocated_tcp_ports"],
    )
    if not complete or result["failure"] is not None or root["runner_exit_code"] != 0:
        return failed_observation(
            campaign,
            start,
            root_cleanup_ref,
            rows=rows,
            verified=verified,
            reason=dict(
                kind="observed-sampled-runtime-failure",
                source_failure=result["failure"],
                runner_exit_code=root["runner_exit_code"],
                missing_original_requests=272 - len(rows),
                missing_complete_native_samples=32
                - sum(r["native_verified"] for r in rows if r["selected"]),
                full_phase_source_drained=history["full_phase_source_drained"]
                if history
                else None,
            ),
        )
    measured = [r for r in rows if r["kind"] == "measured"]
    successful = sum(
        r["status_code"] == 200
        and r["response_nonempty"] is True
        and r["response_model"] == launch["arms"][start["arm"]]["served_model"]
        and type(r["output_tokens"]) is int
        and 0 < r["output_tokens"] <= 64
        and r["native_clock"]["http_deadline_met"] is True
        and r["error"] is None
        for r in measured
    )
    health = result["health_observation"]
    require(
        health["status_code"] == 200
        and timing["after_ns"]
        <= health["observed_ns"]
        <= min(r["dispatch_ns"] for r in rows),
        "actual product-to-health RAW boundary differs",
    )
    return dict(
        schema="ecpa-h4-sampled-native-independent-start-observation/v1",
        start_id=start_id,
        cell_id=campaign["cell_id"],
        arm=start["arm"],
        repetition=start["repetition"],
        arm_order=start["arm_order"],
        formal_start_validated=True,
        start_validation="source-admitted-actual-sampled-start",
        full_native_sample_count=32,
        all_http_request_count=272,
        successful_measured=successful,
        source_native_complete=True,
        resources=result["resources"],
        status="succeeded" if successful == 256 else "failed",
        coverage="complete-observed",
        observed_failure=None
        if successful == 256
        else dict(
            kind="HTTP-success-threshold-not-met", successful_measured=successful
        ),
        performance_eligible=successful == 256 and result["failure"] is None,
        phase_bins=None,
        phase_bins_status="unobserved; no zero substitution",
        independent_root_cleanup=root_cleanup_ref,
        formal_result=False,
        H4_hypothesis_claim=False,
        limitation=(
            "Per-start validation only; original36 matched ag"
            "gregation and confound evaluation remain separat"
            "e"
        ),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("campaign", "launch-spec", "deployment-receipt", "root-cleanup"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--root-cleanup-sha256", required=True)
    parser.add_argument("--start-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = intake(
        args.campaign,
        args.launch_spec,
        args.deployment_receipt,
        args.start_id,
        {"path": str(args.root_cleanup), "sha256": args.root_cleanup_sha256},
    )
    from .run_h4_sampled import write_new

    write_new(args.output, result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
