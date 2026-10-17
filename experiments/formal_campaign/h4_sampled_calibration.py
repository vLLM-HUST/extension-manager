"""Independent tokenizer replay and an explicit unregistered native qualifier.

This domain never issues a deployment receipt or a formal experiment row. The
provider's HF statistics .pt is separate from the actual same-request KV proof.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def ref(path):
    path = Path(path).resolve()
    return dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def checked(reference):
    path = Path(reference["path"])
    require(
        path.is_absolute() and path.resolve() == path and not path.is_symlink(),
        "unsafe calibration leaf",
    )
    raw = path.read_bytes()
    require(
        hashlib.sha256(raw).hexdigest() == reference["sha256"].removeprefix("sha256:"),
        "calibration leaf changed",
    )
    return raw


def write_new_bytes(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def private_directory(path):
    from .h4_sampled_native_bootstrap import make_private_directory

    return make_private_directory(Path(path))


def _host_arguments(phase):
    argv = phase["argv"]
    if argv[2] == "manager":
        index = argv.index("--")
        host = argv[index + 1 :]
        require(
            host[:4] == [argv[0], argv[1], "managed-host", "serve"],
            "actual Manager Host prefix differs",
        )
    else:
        host = argv
        require(
            host[:4] == [argv[0], argv[1], "baseline", "serve"],
            "actual baseline Host prefix differs",
        )
    return host[3:]


def tokenizer_worker(document):
    """Actual selected Host APIs; no device/model forward or network download."""
    from vllm.engine.arg_utils import AsyncEngineArgs
    from vllm.entrypoints.launchers.cli_args import make_arg_parser
    from vllm.entrypoints.openai.completion.protocol import CompletionRequest
    from vllm.tokenizers.registry import get_tokenizer
    from vllm.utils.argparse_utils import FlexibleArgumentParser

    from vllm_hust_ext.runtime_activation import parse_activation

    _, arguments, probe = parse_activation(document["host_arguments"])
    require(not probe and arguments[0] == "serve", "actual serve invocation required")
    parser = make_arg_parser(FlexibleArgumentParser())
    args = parser.parse_args(arguments[1:])
    args.model = getattr(args, "model_tag", None) or args.model
    require(
        not args.trust_remote_code
        and not getattr(args, "skip_tokenizer_init", False)
        and getattr(args, "tokenizer_mode", "auto") in {"auto", "hf"},
        "unsupported tokenizer execution mode",
    )
    model_config = AsyncEngineArgs.from_cli_args(args).create_model_config()
    require(
        model_config.runner_type == "generate" and not model_config.trust_remote_code,
        "unsupported actual ModelConfig tokenizer execution",
    )
    require(
        not getattr(args, "enable_prompt_embeds", False),
        "embedding prompt requires another independent replay",
    )
    request = CompletionRequest.model_validate(document["payload"])
    require(
        type(request.prompt) is str
        and request.max_tokens == 64
        and request.truncate_prompt_tokens is None,
        "one exact untruncated string CompletionRequest required",
    )
    tokenizer = get_tokenizer(
        model_config.tokenizer,
        runner_type=model_config.runner_type,
        tokenizer_mode=model_config.tokenizer_mode,
        trust_remote_code=False,
        revision=model_config.tokenizer_revision,
        local_files_only=True,
    )
    ids = tokenizer.encode(
        request.prompt, add_special_tokens=request.add_special_tokens
    )
    require(
        type(ids) is list and ids and all(type(i) is int and i >= 0 for i in ids),
        "invalid actual tokenizer IDs",
    )
    return dict(
        schema="ecpa-h4-actual-tokenizer-replay/v1",
        request_sha256=hashlib.sha256(canonical(document["payload"])).hexdigest(),
        tokenizer=str(model_config.tokenizer),
        tokenizer_mode=model_config.tokenizer_mode,
        tokenizer_revision=model_config.tokenizer_revision,
        add_special_tokens=request.add_special_tokens,
        truncate_prompt_tokens=request.truncate_prompt_tokens,
        input_ids=ids,
        input_ids_sha256=hashlib.sha256(canonical(ids)).hexdigest(),
        prompt_token_count=len(ids),
    )


def replay_tokenizer(phase, payload, fixed, native, output=None):
    """Recompute IDs, not a caller's numeric count; audit exact interpreter first."""
    from experiments.native_attention_candidate import live_route_reader as routes

    from .h3_runtime_source_closure import verify_runtime_source_closure
    from .h4_sampled_registration import checked as checked_input

    closure = verify_runtime_source_closure(
        phase, fixed, native["repositories"], native["runtime_wheels"]
    )
    require(
        any(
            v["distribution"].replace("_", "-").lower()
            == "vllm-request-lifecycle-profiler-plugin"
            for k, v in native["runtime_wheels"].items()
            if k.startswith("plugin:")
        ),
        "actual paired runtime must explicitly include profiler source/wheel ownership",
    )
    policy = json.loads(checked_input(phase["native_guard"]))
    audits = policy["source_arguments"]["input_audits"]
    require(
        type(audits) is dict and audits,
        "independent actual tokenizer/model input audits missing",
    )
    inputs = []
    verified_audits = []
    providers = []
    for frozen in audits.values():
        actual = routes.audit_cell_inputs(
            frozen["config"]["path"], frozen["recipe"]["path"]
        )
        require(
            canonical(actual) == canonical(frozen),
            "actual source/model/tokenizer input audit changed",
        )
        require(
            actual["request_sha256"] == hashlib.sha256(canonical(payload)).hexdigest(),
            "input audit describes another request",
        )
        verified_audits.append(actual)
        config = json.loads(checked_input(actual["config"]))
        providers.append(config["calibration_artifact"])
        inputs.append(
            dict(
                config=actual["config"],
                recipe=actual["recipe"],
                tokenizer_sha256=actual["tokenizer_sha256"],
                model_sha256=actual["model_sha256"],
                calibration_sha256=actual["calibration_sha256"],
            )
        )
    require(
        all(canonical(p) == canonical(providers[0]) for p in providers),
        "provider statistics artifacts differ",
    )
    # Exact admitted interpreter/environment/cwd; no shell, pip, retry or global env.
    command = [phase["argv"][0], str(Path(__file__).resolve()), "--tokenizer-worker"]
    document = dict(host_arguments=_host_arguments(phase), payload=payload)
    environment = dict(phase["environment"])
    environment.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1")
    child = subprocess.run(
        command,
        input=canonical(document),
        capture_output=True,
        cwd=phase["cwd"],
        env=environment,
        timeout=120,
        check=False,
    )
    if output is not None:
        output = Path(output)
        private_directory(output)
        write_new_bytes(output / "tokenizer.stdout", child.stdout)
        write_new_bytes(output / "tokenizer.stderr", child.stderr)
        write_new_bytes(
            output / "tokenizer-command.json",
            canonical(dict(argv=command, exit_code=child.returncode)),
        )
    require(
        child.returncode == 0, "actual tokenizer child failed; original stderr retained"
    )
    replay = json.loads(child.stdout)
    require(
        canonical(replay) + b"\n" == child.stdout
        and replay["prompt_token_count"] == len(replay["input_ids"])
        and replay["input_ids_sha256"]
        == hashlib.sha256(canonical(replay["input_ids"])).hexdigest()
        and len(replay["input_ids"]) >= 1152,
        "actual full input IDs do not meet frozen long prompt intent",
    )
    for audit in verified_audits:
        for path, state in audit["file_state"].items():
            require(
                routes._state(routes._path(path).stat()) == state,
                "model/tokenizer source state changed across replay",
            )
        checked_input(audit["config"])
        checked_input(audit["recipe"])
    # Recheck actual admitted interpreter/payload after the independent execution.
    require(
        canonical(closure)
        == canonical(
            verify_runtime_source_closure(
                phase, fixed, native["repositories"], native["runtime_wheels"]
            )
        ),
        "runtime changed across tokenization",
    )
    return dict(
        tokenizer=replay,
        input_bindings=inputs,
        provider_statistics=dict(
            kind="provider-hf-statistics-pt",
            artifact=providers[0],
            evidence_scope=(
                "source-bound provider statistics; not request native execution"
            ),
        ),
    )


def verify_calibration_resources(proof, epoch, launch):
    """Pass exact actual result summary/root to the original three-arg reader."""
    from .h4_owned_resources import verify_archive

    result = json.loads(checked(proof["source_result"]))
    require(
        result["execution_domain"] == "unregistered-calibration"
        and result["formal_result"] is False
        and result["failure"] is None
        and result["cleanup_errors"] == []
        and result["actual_epochs_gone"] is True
        and result["actual_ports_closed"] is True
        and result["device_cleanup_exit_code"] == 0,
        "actual qualification source result/cleanup incomplete",
    )
    resource_raw = checked(proof["resources"])
    resources = verify_archive(
        Path(proof["resources"]["path"]), epoch["owner"], result["resources"]
    )
    require(
        checked(proof["resources"]) == resource_raw
        and resources["device_command"] == launch["npu_memory_command"],
        "actual resource archive/registered device command changed",
    )
    return resources, result


def verify_calibration_trace(proof, report, schedule, request_body, response_body):
    """Use original client clocks, never a report's self-selected deadline."""
    from .analyze import h4_body_binding, h4_request_identity_observation

    rows = [json.loads(line) for line in checked(proof["request_trace"]).splitlines()]
    require(len(rows) == 1, "one original unregistered HTTP trace required")
    row = rows[0]
    declaration = schedule["requests"][0]
    require(
        type(row["all_index"]) is int
        and row["all_index"] == declaration["all_index"] == 0
        and row["request_id"] == declaration["request_id"] == proof["request_id"]
        and row["selected"] is declaration["selected"] is True
        and row["native_verified"] is True
        and row["native_error"] is None
        and row["error"] is None
        and row["http_response"]["status_code"] == 200,
        "original qualification trace request/outcome differs",
    )
    require(
        canonical(row["http_request"]) == canonical(h4_body_binding(request_body))
        and canonical(
            {k: row["http_response"][k] for k in h4_body_binding(response_body)}
        )
        == canonical(h4_body_binding(response_body)),
        "original HTTP body evidence differs",
    )
    request_headers = row["request_headers"]
    require(
        [v for k, v in request_headers if k.lower() == "x-request-id"]
        == [proof["request_id"]]
        and canonical(row["request_identity"])
        == canonical(
            h4_request_identity_observation(
                proof["request_id"], request_headers, row["http_response"]
            )
        ),
        "original sent/returned request identity differs",
    )
    reference = row["native_report"]
    require(
        canonical({k: reference[k] for k in ("path", "sha256")})
        == canonical(proof["report"]),
        "original client trace names another native report",
    )
    clock = row["native_clock"]
    fields = ("sent_ns", "backend_sent_ns", "received_ns", "consumed_ns", "deadline_ns")
    require(
        all(type(clock[k]) is int for k in fields)
        and clock["deadline_ns"] - clock["sent_ns"] == 120_000_000_000
        and 0
        < clock["sent_ns"]
        <= clock["backend_sent_ns"]
        <= clock["received_ns"]
        <= clock["consumed_ns"]
        <= clock["deadline_ns"]
        and clock["http_deadline_met"] is True,
        "original client absolute120 budget was not met",
    )
    require(
        report["original_sent_ns"] == clock["sent_ns"]
        and report["backend_sent_ns"] == clock["backend_sent_ns"]
        and report["backend_received_ns"] == clock["received_ns"]
        and report["original_deadline_ns"] == clock["deadline_ns"]
        and type(report["verified_monotonic_ns"]) is int
        and clock["received_ns"]
        <= report["verified_monotonic_ns"]
        <= clock["consumed_ns"],
        "native report renewed or changed the original client clocks",
    )
    require(
        type(row["dispatch_ns"]) is int
        and type(row["complete_ns"]) is int
        and row["dispatch_ns"] <= row["complete_ns"]
        and row["complete_ns"] - row["dispatch_ns"] <= 120_000_000_000,
        "original raw HTTP interval exceeds120s",
    )
    return row, clock


def verify_calibration_epoch_links(epoch, semantic, membership, events):
    """Archived normal-intake context + Host7/kernel4 bridge, no live PID read.

    Mirrors normal H4 intake's exact context and three native-member predicates.
    The independent Host/resource roster remains four roles; enrollment stays
    API0/worker0/worker1 only. Original Host event objects are never rewritten.
    """
    from vllm_hust_ext.host_evidence import parse_host_event

    enrollment = epoch["enrollment"]
    context = (
        "execution_plan_id",
        "controller_instance",
        "candidate_generation",
        "membership_epoch",
    )
    require(
        canonical(enrollment["semantic_context"])
        == canonical({k: semantic[k] for k in context})
        and enrollment["native_plan_id"] == semantic["native_plan_id"],
        "qualified full semantic context/Plan differs from source-owned phase",
    )
    peers = enrollment["source_peers"]
    expected = {"api-server/0", "worker/0", "worker/1"}
    require(len(peers) == 3, "native peer slots missing or extra")
    peer_slots = set()
    for peer in peers:
        process = peer["process"]
        slot = f"{process['role']}/{process['ordinal']}"
        require(
            slot in expected
            and slot not in peer_slots
            and canonical(process)
            == canonical({**epoch["roster"][slot], **epoch["kernels"][slot]}),
            "archived native peer differs from exact Host7 plus independent kernel4",
        )
        peer_slots.add(slot)
    require(
        peer_slots == expected and len(membership) == 3,
        "all three original native members are mandatory",
    )
    membership_slots = set()
    for member in membership:
        event = parse_host_event(canonical(member["event"]))
        slot = f"{member['role']}/{member['ordinal']}"
        require(
            slot in peer_slots
            and slot not in membership_slots
            and canonical(event["process"]) == canonical(epoch["roster"][slot])
            and canonical(member["identity"])
            == canonical(
                {**epoch["kernels"][slot], "launch_id": enrollment["native_launch_id"]}
            )
            and event["plan_id"] == enrollment["native_plan_id"]
            and event["launch_id"] == enrollment["native_launch_id"]
            and any(canonical(event) == canonical(original) for original in events),
            "original membership event/kernel/launch changed",
        )
        membership_slots.add(slot)
    require(membership_slots == expected, "original native membership slots incomplete")


def validate_calibration(reference, *, campaign, launch, workload, native):
    """Independently replay exact typed leaves; no arbitrary raw_refs/ready flag."""
    from vllm_hust_ext.host_evidence import parse_host_event

    from .analyze import h4_request_payload
    from .h3_native_authority import native_host_roster
    from .h4_sampled_intake import coherent_roster, verify_profiler, verify_root_cleanup
    from .h4_sampled_native_replay import replay_sampled_native_report
    from .h4_sampled_native_source_scope import scope_native_senders
    from .h4_sampled_registration import (
        build_calibration_guard,
        read_registered_schedule,
    )

    value = json.loads(checked(reference))
    require(
        set(value)
        == {
            "schema",
            "workload_sha256",
            "fixed_identity",
            "phase",
            "tokenizer_replay",
            "provider_statistics",
            "native_request",
        }
        and value["schema"] == "ecpa-h4-independent-calibration/v2",
        "exact typed calibration contract required",
    )
    require(
        value["workload_sha256"] == campaign["workload"]["sha256"]
        and canonical(value["fixed_identity"]) == canonical(campaign["fixed_identity"]),
        "calibration tuple/workload changed",
    )
    phase = json.loads(checked(value["phase"]))
    guard = build_calibration_guard(
        campaign, native, {"phase": value["phase"]}, native["repositories"]
    )
    guard.verify_plan_current()
    proof = value["native_request"]
    require(
        set(proof)
        == {
            "report",
            "epoch",
            "host_journal",
            "resources",
            "root_cleanup",
            "run_directory",
            "request_body",
            "response_body",
            "schedule",
            "request_id",
            "arm",
            "source_result",
            "request_trace",
            "popen_timing",
            "runtime_closure",
            "membership",
        },
        "actual native calibration leaves incomplete",
    )
    run = Path(proof["run_directory"])
    for key, filename in (
        ("epoch", "sampled-epoch-archive.json"),
        ("host_journal", "final-original-Host.jsonl"),
        ("resources", "owned-resources.json"),
        ("source_result", "sampled-source-result.json"),
        ("request_trace", "request-results.jsonl"),
        ("popen_timing", "phase0.product-popen-timing.json"),
        ("runtime_closure", "actual-runtime-closure.json"),
        ("membership", "phase0.actual-membership.json"),
    ):
        require(
            Path(proof[key]["path"]) == run / filename,
            "qualification artifact moved to another run",
        )
    model = launch["arms"][proof["arm"]]["served_model"]
    body = h4_request_payload(workload, model)
    require(
        checked(proof["request_body"]) == body,
        "native calibration used a different exact HTTP request",
    )
    replay = replay_tokenizer(
        phase, json.loads(body), campaign["fixed_identity"], native
    )
    require(
        canonical(replay["tokenizer"])
        == canonical(json.loads(checked(value["tokenizer_replay"])))
        and canonical(replay["provider_statistics"])
        == canonical(value["provider_statistics"]),
        "actual token IDs/provider artifact differ",
    )
    epoch = json.loads(checked(proof["epoch"]))
    timing = json.loads(checked(proof["popen_timing"]))
    require(
        canonical(timing["actual_kernel"]) == canonical(epoch["owner"])
        and timing["argv"] == phase["argv"],
        "actual source product Popen differs",
    )
    from .h3_runtime_source_closure import verify_runtime_source_closure

    require(
        canonical(json.loads(checked(proof["runtime_closure"])))
        == canonical(
            verify_runtime_source_closure(
                phase,
                campaign["fixed_identity"],
                native["repositories"],
                native["runtime_wheels"],
            )
        ),
        "actual qualification runtime closure differs",
    )
    raw = checked(proof["host_journal"])
    require(
        hashlib.sha256(raw).hexdigest() == epoch["host_journal_sha256"],
        "original Host history changed",
    )
    events = [parse_host_event(line) for line in raw.splitlines()]
    require(
        canonical(
            native_host_roster(
                events,
                epoch["enrollment"]["native_plan_id"],
                epoch["enrollment"]["native_launch_id"],
            )
        )
        == canonical(epoch["roster"]),
        "original Host assignment history differs from actual sampled roster",
    )
    resources, source_result = verify_calibration_resources(proof, epoch, launch)
    coherent_roster(resources, epoch["owner"], epoch["roster"], epoch["kernels"])
    terminal = verify_root_cleanup(
        proof["root_cleanup"],
        Path(proof["run_directory"]),
        epoch["owner"],
        epoch["kernels"],
        native["allocated_tcp_ports"],
    )
    require(
        terminal["execution_domain"] == "unregistered-calibration",
        (
            "native feasibility proof must be independently observed qualification, "
            "not an old formal row"
        ),
    )
    record = json.loads(checked(proof["report"]))
    require(
        record["schema"] == "ecpa-h4-sampled-native-consume-report/v1",
        "wrong independent native report domain",
    )
    spec = json.loads(Path(record["native_spec"]).read_bytes())
    require(
        canonical(phase["semantic_launch_spec"])
        == canonical(guard.policy["native_launch_spec"]),
        "phase semantic source reference differs from independently verified guard",
    )
    semantic = json.loads(checked(phase["semantic_launch_spec"]))
    require(
        canonical(
            {
                k: semantic[k]
                for k in (
                    "execution_plan_id",
                    "controller_instance",
                    "candidate_generation",
                    "membership_epoch",
                    "native_plan_id",
                )
            }
        )
        == canonical(
            {
                k: guard.launch[k]
                for k in (
                    "execution_plan_id",
                    "controller_instance",
                    "candidate_generation",
                    "membership_epoch",
                    "native_plan_id",
                )
            }
        ),
        "phase semantic source differs from actual compiled fullPlan",
    )
    verify_calibration_epoch_links(
        epoch, guard.launch, json.loads(checked(proof["membership"])), events
    )
    require(
        spec["native_plan_id"] == semantic["native_plan_id"],
        "qualified fullPlan differs from source-compiled intent",
    )
    senders, _ = scope_native_senders(
        epoch["enrollment"]["source_peers"], phase["native_bootstrap"]["source_files"]
    )
    require(
        canonical(spec["senders"]) == canonical(senders)
        and canonical(spec["phases"]) == canonical(phase["native_bootstrap"]["phases"])
        and canonical(spec["kv_requirements"])
        == canonical(phase["native_bootstrap"]["kv_requirements"]),
        "native calibration changed full32 declaration/source scope",
    )
    schedule, schedule_raw = read_registered_schedule(proof["schedule"], spec["phases"])
    require(
        all(
            row["body_sha256"] == hashlib.sha256(body).hexdigest()
            for row in schedule["requests"]
        )
        and record["schedule_sha256"] == hashlib.sha256(schedule_raw).hexdigest(),
        "qualified full272 schedule belongs to another HTTP body",
    )
    require(
        any(
            r["request_id"] == proof["request_id"] and r["selected"]
            for r in schedule["requests"]
        ),
        "native calibration is not exact selected32 request",
    )
    response = checked(proof["response_body"])
    require(
        json.loads(response)["usage"]["prompt_tokens"]
        == len(replay["tokenizer"]["input_ids"]),
        "actual native response tokenization differs",
    )
    row, clock = verify_calibration_trace(proof, record, schedule, body, response)
    expected = (
        Path(phase["native_bootstrap"]["output"])
        / "snapshots"
        / hashlib.sha256(proof["request_id"].encode()).hexdigest()
        / "native-consume-report.json"
    )
    require(
        Path(proof["report"]["path"]) == expected
        and all(
            Path(record[key]) == Path(phase["native_bootstrap"]["output"]) / filename
            for key, filename in (
                ("native_spec", "native-spec.json"),
                ("tensor_policy", "tensor-policy.json"),
                ("drain_policy", "drain-policy.json"),
            )
        )
        and Path(record["journal"]) == expected.parent / "native.jsonl",
        "native qualification report moved to another request/source epoch",
    )
    require(
        source_result["start_id"] + "/warmup-0000" == row["request_id"]
        and timing["before_monotonic_ns"]
        <= timing["after_monotonic_ns"]
        <= clock["sent_ns"],
        "request did not follow the independently bound product Popen",
    )
    replayed = replay_sampled_native_report(
        proof["report"],
        request_id=proof["request_id"],
        request_body=body,
        response_body=response,
        response_expectation={"min_completion_tokens": 16, "max_completion_tokens": 64},
        enrollment=epoch["enrollment"],
        deadline_ns=clock["deadline_ns"],
    )
    require(
        canonical(replayed) == canonical(record),
        "native report changed across independent replay",
    )
    transaction = next(
        t
        for t in record["full_archive"]["attention_complete_transactions"]
        if t["phase_id"] == record["phase"]["phase_id"]
    )
    reference = row["native_report"]
    require(
        reference["runtime_request_id"] == transaction["runtime_request_id"]
        and reference["transaction_id"] == transaction["transaction_id"]
        and reference["profiler_snapshot_path"] == record["profiler_snapshot"]
        and reference["profiler_snapshot_sha256"] == record["profiler_snapshot_sha256"],
        "actual client summary changed native opaque request/profiler identity",
    )
    require(
        Path(record["journal"]).read_bytes()
        == (Path(phase["native_bootstrap"]["output"]) / "native.jsonl").read_bytes(),
        "actual full native qualification history has unverified tail/fork",
    )
    verify_profiler(record, proof["report"], epoch, raw)
    return replay["tokenizer"]


def produce(campaign_path, launch_path, locations_path, start_id, output):
    """Fresh source/input roots -> real Host -> one real full-native request.

    No deployment receipt is requested, constructed, or accepted by this domain.
    Independent root observer must subsequently supply actual cleanup evidence.
    """
    require(os.geteuid() == 0, "root-only unregistered native producer")
    os.umask(0o077)
    from .analyze import h4_request_payload
    from .h4_sampled_registration import build_calibration_guard, validate_inputs
    from .run_h4_sampled import run_start, write_new

    campaign, launch, workload, native = validate_inputs(
        campaign_path, launch_path, _calibration_only=True
    )
    starts = [s for s in native["starts"] if s["start_id"] == start_id]
    require(len(starts) == 1, "one distinct qualification start required")
    start = starts[0]
    phase = json.loads(checked(start["phase"]))
    payload = json.loads(
        h4_request_payload(workload, launch["arms"][start["arm"]]["served_model"])
    )
    guard = build_calibration_guard(
        campaign, native, start, json.loads(Path(locations_path).read_bytes())
    )
    tokenizer = replay_tokenizer(
        phase, payload, campaign["fixed_identity"], native, output
    )
    result = run_start(
        campaign, launch, workload, native, start, None, calibration_guard=guard
    )
    write_new(Path(output) / "actual-tokenizer-replay.json", tokenizer["tokenizer"])
    write_new(
        Path(output) / "provider-statistics-binding.json",
        tokenizer["provider_statistics"],
    )
    write_new(
        Path(output) / "unregistered-native-qualification-result.json",
        dict(
            schema="ecpa-h4-unregistered-native-qualification/v1",
            formal_result=False,
            deployment_receipt=None,
            result=result,
        ),
    )
    require(
        result["failure"] is None and result["native_verified_count"] == 1,
        "actual unregistered native qualification failed; raw retained",
    )
    return 0


def freeze_evidence(campaign_path, launch_path, start_id, observer_output, output):
    """Build typed leaves only from completed actual producer+root artifacts."""
    require(os.geteuid() == 0, "root-only independent qualification replay")
    os.umask(0o077)
    from .analyze import h4_request_payload
    from .h4_sampled_registration import validate_inputs
    from .run_h4_sampled import write_new

    campaign, launch, workload, native = validate_inputs(
        campaign_path, launch_path, require_fresh_paths=False, _calibration_only=True
    )
    starts = [s for s in native["starts"] if s["start_id"] == start_id]
    require(len(starts) == 1, "one original qualification start required")
    start = starts[0]
    run = Path(start["run_directory"])
    observer_output = Path(observer_output)
    root_ref = ref(observer_output / "independent-root-terminal.json")
    terminal = json.loads(checked(root_ref))
    require(
        terminal["execution_domain"] == "unregistered-calibration"
        and terminal["released"] is True,
        "independent real cleanup not complete",
    )
    rows = [
        json.loads(line)
        for line in (run / "request-results.jsonl").read_bytes().splitlines()
    ]
    require(
        len(rows) == 1
        and rows[0]["all_index"] == 0
        and rows[0]["selected"] is True
        and rows[0]["native_verified"] is True
        and rows[0]["error"] is None,
        "one actual selected full native calibration response is required",
    )
    row = rows[0]
    result = json.loads((run / "sampled-source-result.json").read_bytes())
    require(
        result["execution_domain"] == "unregistered-calibration"
        and result["request_count"] == result["native_verified_count"] == 1
        and result["formal_result"] is False,
        "qualification falsely attributed to original experiment",
    )
    output = private_directory(Path(output))
    payload = h4_request_payload(workload, launch["arms"][start["arm"]]["served_model"])
    body = __import__("base64").b64decode(
        row["http_response"]["body_base64"], validate=True
    )
    write_new_bytes(output / "request.bin", payload)
    write_new_bytes(output / "response.bin", body)
    artifacts = observer_output / "calibration-artifacts"
    value = dict(
        schema="ecpa-h4-independent-calibration/v2",
        workload_sha256=campaign["workload"]["sha256"],
        fixed_identity=campaign["fixed_identity"],
        phase=start["phase"],
        tokenizer_replay=ref(artifacts / "actual-tokenizer-replay.json"),
        provider_statistics=json.loads(
            (artifacts / "provider-statistics-binding.json").read_bytes()
        ),
        native_request=dict(
            report={k: row["native_report"][k] for k in ("path", "sha256")},
            epoch=ref(run / "sampled-epoch-archive.json"),
            host_journal=ref(run / "final-original-Host.jsonl"),
            resources=ref(run / "owned-resources.json"),
            root_cleanup=root_ref,
            run_directory=str(run),
            source_result=ref(run / "sampled-source-result.json"),
            request_trace=ref(run / "request-results.jsonl"),
            popen_timing=ref(run / "phase0.product-popen-timing.json"),
            runtime_closure=ref(run / "actual-runtime-closure.json"),
            membership=ref(run / "phase0.actual-membership.json"),
            request_body=ref(output / "request.bin"),
            response_body=ref(output / "response.bin"),
            schedule=start["schedule"],
            request_id=row["request_id"],
            arm=start["arm"],
        ),
    )
    write_new(output / "calibration.json", value)
    validate_calibration(
        ref(output / "calibration.json"),
        campaign=campaign,
        launch=launch,
        workload=workload,
        native=native,
    )
    write_new(
        output / "independent-replay-result.json",
        dict(
            schema="ecpa-h4-unregistered-calibration-replay-result/v1",
            calibration=ref(output / "calibration.json"),
            execution_domain="unregistered-calibration",
            formal_result=False,
            deployment_receipt=None,
        ),
    )
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tokenizer-worker", action="store_true")
    parser.add_argument("--produce", action="store_true")
    parser.add_argument("--freeze-evidence", action="store_true")
    parser.add_argument("--observer-output", type=Path)
    for name in ("campaign", "launch-spec", "source-repositories", "output"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--start-id")
    args = parser.parse_args()
    if args.tokenizer_worker:
        document = json.load(sys.stdin)
        with contextlib.redirect_stdout(sys.stderr):
            replay = tokenizer_worker(document)
        print(canonical(replay).decode())
        return 0
    if args.freeze_evidence:
        require(
            all(
                (
                    args.campaign,
                    args.launch_spec,
                    args.start_id,
                    args.observer_output,
                    args.output,
                )
            ),
            "actual completed producer and root observation inputs required",
        )
        return freeze_evidence(
            args.campaign,
            args.launch_spec,
            args.start_id,
            args.observer_output,
            args.output,
        )
    require(
        args.produce
        and all(
            (
                args.campaign,
                args.launch_spec,
                args.source_repositories,
                args.output,
                args.start_id,
            )
        ),
        "explicit unregistered producer inputs required",
    )
    return produce(
        args.campaign,
        args.launch_spec,
        args.source_repositories,
        args.start_id,
        args.output,
    )


if __name__ == "__main__":
    raise SystemExit(main())
