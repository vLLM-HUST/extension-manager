"""Source-only candidate unit tests; fixture tokens are never qualification."""

import hashlib
import json
import sys
import types

import pytest

from experiments.formal_campaign import h4_sampled_calibration as calibration
from experiments.formal_campaign import h4_sampled_registration as registration


def test_host_arguments_derive_from_actual_manager_and_baseline_prefix():
    baseline = {
        "argv": [
            "/actual/python",
            "/actual/h3_dynamic_host.py",
            "baseline",
            "serve",
            "--disable-ecpa-manager",
            "--enable-entrypoints",
            "/actual/model",
        ]
    }
    manager = {
        "argv": [
            "/actual/python",
            "/actual/h3_dynamic_host.py",
            "manager",
            "run",
            "--",
            "/actual/python",
            "/actual/h3_dynamic_host.py",
            "managed-host",
            "serve",
            "/actual/model",
        ]
    }
    assert calibration._host_arguments(baseline) == baseline["argv"][3:]
    assert calibration._host_arguments(manager) == ["serve", "/actual/model"]
    manager["argv"][8] = "baseline"
    with pytest.raises(ValueError):
        calibration._host_arguments(manager)


def test_guard_uses_fresh_observer_and_full_guard_factory_without_a_receipt(
    monkeypatch,
):
    current = {"actual_source_observation": "fixture"}
    calls = []
    guard = object()
    monkeypatch.setattr(
        registration.source_provenance,
        "observe_sources",
        lambda fixed, policy, locations: (
            calls.append((fixed, policy, locations)) or current
        ),
    )
    monkeypatch.setattr(
        registration, "verify_sampled_protocol_sources", lambda *args: None
    )
    monkeypatch.setattr(
        registration,
        "_build_guard_from_observation",
        lambda campaign, native, start, observation: calls.append(observation) or guard,
    )
    campaign = {
        "fixed_identity": {"manager_commit": "a" * 40},
        "source_provenance_policy": {"exact": "policy"},
    }
    result = registration.build_calibration_guard(
        campaign, {}, {}, {"manager": {"path": "/actual/sdk"}}
    )
    assert result is guard and calls[-1] is current and len(calls) == 2


def _leaf(tmp_path, value):
    path = tmp_path / "raw.json"
    raw = calibration.canonical(value)
    path.write_bytes(raw)
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}


@pytest.mark.parametrize(
    "value",
    [
        {
            "schema": "ecpa-h4-new-workload-actual-calibration/v1",
            "prompt_tokens": 1152,
            "raw_refs": [{}],
        },
        {"schema": "ecpa-h4-independent-calibration/v2", "ready": True},
        {
            "schema": "ecpa-h4-independent-calibration/v2",
            "native_request": {"report": {}},
        },
    ],
)
def test_opaque_raw_refs_ready_and_caller_count_are_not_calibration(tmp_path, value):
    with pytest.raises(ValueError):
        calibration.validate_calibration(
            _leaf(tmp_path, value), campaign={}, launch={}, workload={}, native={}
        )


def test_modified_calibration_leaf_rejected_before_replay(tmp_path):
    ref = _leaf(tmp_path, {"schema": "frozen-intent"})
    from pathlib import Path

    Path(ref["path"]).write_bytes(b'{"schema":"changed"}')
    with pytest.raises(ValueError, match="changed"):
        calibration.checked(ref)


@pytest.mark.parametrize("explicit", [None, False, True])
def test_worker_uses_actual_request_default_and_full_encode_ids(monkeypatch, explicit):
    # Controlled source API fixtures exercise option flow only; no model exists.
    observations = {}
    names = [
        "vllm",
        "vllm.engine",
        "vllm.engine.arg_utils",
        "vllm.entrypoints",
        "vllm.entrypoints.launchers",
        "vllm.entrypoints.launchers.cli_args",
        "vllm.entrypoints.openai",
        "vllm.entrypoints.openai.completion",
        "vllm.entrypoints.openai.completion.protocol",
        "vllm.tokenizers",
        "vllm.tokenizers.registry",
        "vllm.utils",
        "vllm.utils.argparse_utils",
    ]
    modules = {name: types.ModuleType(name) for name in names}
    for module in modules.values():
        module.__path__ = []
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)

    class Parser:
        def parse_args(self, arguments):
            observations["arguments"] = arguments
            return types.SimpleNamespace(
                model="/actual/model",
                model_tag=None,
                tokenizer=None,
                tokenizer_mode="auto",
                tokenizer_revision=None,
                trust_remote_code=False,
            )

    modules["vllm.utils.argparse_utils"].FlexibleArgumentParser = Parser
    modules["vllm.entrypoints.launchers.cli_args"].make_arg_parser = lambda parser: (
        parser
    )

    class EngineArgs:
        @staticmethod
        def from_cli_args(args):
            return types.SimpleNamespace(
                create_model_config=lambda: types.SimpleNamespace(
                    tokenizer="/actual/model",
                    tokenizer_mode="auto",
                    tokenizer_revision=None,
                    runner_type="generate",
                    trust_remote_code=False,
                )
            )

    modules["vllm.engine.arg_utils"].AsyncEngineArgs = EngineArgs

    class Request:
        @staticmethod
        def model_validate(value):
            return types.SimpleNamespace(
                prompt=value["prompt"],
                max_tokens=value["max_tokens"],
                add_special_tokens=value.get("add_special_tokens", True),
                truncate_prompt_tokens=None,
            )

    modules["vllm.entrypoints.openai.completion.protocol"].CompletionRequest = Request

    class Tokenizer:
        def encode(self, prompt, **options):
            observations.update(prompt=prompt, options=options)
            return [3, 7, 11]

    def get_tokenizer(path, **options):
        observations.update(tokenizer_path=path, tokenizer_options=options)
        return Tokenizer()

    modules["vllm.tokenizers.registry"].get_tokenizer = get_tokenizer
    payload = {"prompt": "exact frozen text", "max_tokens": 64}
    if explicit is not None:
        payload["add_special_tokens"] = explicit
    result = calibration.tokenizer_worker(
        {
            "host_arguments": [
                "serve",
                "--disable-ecpa-manager",
                "--enable-entrypoints",
                "/actual/model",
            ],
            "payload": payload,
        }
    )
    assert result["input_ids"] == [3, 7, 11] and result["prompt_token_count"] == 3
    assert observations["options"] == {
        "add_special_tokens": True if explicit is None else explicit
    }
    assert observations["tokenizer_options"]["trust_remote_code"] is False
    assert observations["tokenizer_options"]["local_files_only"] is True
    assert (
        result["input_ids_sha256"]
        == hashlib.sha256(calibration.canonical([3, 7, 11])).hexdigest()
    )


def test_original_resource_reader_receives_pinned_actual_summary_and_owner(
    tmp_path, monkeypatch
):
    from experiments.formal_campaign import h4_owned_resources

    result = dict(
        execution_domain="unregistered-calibration",
        formal_result=False,
        failure=None,
        cleanup_errors=[],
        actual_epochs_gone=True,
        actual_ports_closed=True,
        device_cleanup_exit_code=0,
        resources={"fixture_summary": "retained"},
    )
    source = tmp_path / "sampled-source-result.json"
    source.write_bytes(calibration.canonical(result))
    archive = tmp_path / "owned-resources.json"
    archive.write_bytes(b'{"unit_fixture":true}')
    owner = {"pid": 123, "start_ticks": 456, "session": 123, "boot_id": "unit-only"}
    calls = []

    def original_reader(path, expected_root, resources):
        calls.append((path, expected_root, resources))
        return {"device_command": ["registered-memory-command"]}

    monkeypatch.setattr(h4_owned_resources, "verify_archive", original_reader)
    proof = {
        "source_result": calibration.ref(source),
        "resources": calibration.ref(archive),
    }
    calibration.verify_calibration_resources(
        proof, {"owner": owner}, {"npu_memory_command": ["registered-memory-command"]}
    )
    assert calls == [(archive, owner, result["resources"])]
    # Frozen original summary changes fail before it reaches the resource reader.
    source.write_bytes(b'{"resources":{"caller":"replacement"}}')
    with pytest.raises(ValueError):
        calibration.verify_calibration_resources(
            proof,
            {"owner": owner},
            {"npu_memory_command": ["registered-memory-command"]},
        )
    assert len(calls) == 1


def test_native_report_cannot_renew_original_client_absolute120(tmp_path):
    import copy

    from experiments.formal_campaign.analyze import (
        h4_body_binding,
        h4_request_identity_observation,
    )

    rid = "new-unregistered/warmup-0000"
    request = calibration.canonical(
        {"model": "unit-model", "prompt": "unit-only", "max_tokens": 64}
    )
    response = calibration.canonical({"id": "cmpl-" + rid, "model": "unit-model"})
    report = {
        "original_sent_ns": 1_000_000_000,
        "backend_sent_ns": 1_000_000_010,
        "backend_received_ns": 1_000_000_020,
        "verified_monotonic_ns": 1_000_000_030,
        "original_deadline_ns": 121_000_000_000,
    }
    report_path = tmp_path / "native-consume-report.json"
    report_path.write_bytes(calibration.canonical(report))
    report_ref = calibration.ref(report_path)
    headers = [["X-Request-Id", rid]]
    http_response = dict(status_code=200, headers=[], **h4_body_binding(response))
    clock = dict(
        sent_ns=report["original_sent_ns"],
        backend_sent_ns=report["backend_sent_ns"],
        received_ns=report["backend_received_ns"],
        consumed_ns=1_000_000_040,
        deadline_ns=report["original_deadline_ns"],
        http_deadline_met=True,
    )
    row = dict(
        all_index=0,
        request_id=rid,
        selected=True,
        native_verified=True,
        native_error=None,
        error=None,
        http_request=h4_body_binding(request),
        http_response=http_response,
        request_headers=headers,
        request_identity=h4_request_identity_observation(rid, headers, http_response),
        native_report=report_ref,
        native_clock=clock,
        dispatch_ns=100,
        complete_ns=200,
    )
    trace = tmp_path / "request-results.jsonl"
    trace.write_bytes(calibration.canonical(row) + b"\n")
    proof = dict(
        request_id=rid, report=report_ref, request_trace=calibration.ref(trace)
    )
    schedule = {"requests": [dict(all_index=0, request_id=rid, selected=True)]}
    _, actual_clock = calibration.verify_calibration_trace(
        proof, report, schedule, request, response
    )
    assert actual_clock == clock
    shifted = {key: value + 121_000_000_000 for key, value in report.items()}
    assert (
        shifted["original_deadline_ns"] - shifted["original_sent_ns"] == 120_000_000_000
    )
    with pytest.raises(ValueError, match="original client clocks"):
        calibration.verify_calibration_trace(
            proof, shifted, schedule, request, response
        )
    # The actual trace SHA is a different immutable leaf, not rewritten to match.
    changed = copy.deepcopy(row)
    changed["native_clock"]["consumed_ns"] = 122_000_000_000
    trace.write_bytes(calibration.canonical(changed) + b"\n")
    with pytest.raises(ValueError, match="changed"):
        calibration.verify_calibration_trace(proof, report, schedule, request, response)


def _archived_epoch_link_fixture():
    # Real schema-shaped Host records, but no claim these unit PIDs ever ran.
    from vllm_hust_ext.host_evidence import parse_host_event

    semantic = dict(
        execution_plan_id="plan:sha256:" + "a" * 64,
        native_plan_id="a" * 64,
        controller_instance="controller:unit-current",
        candidate_generation=1,
        membership_epoch=0,
    )
    launch = "00000000-0000-4000-8000-000000000123"
    roster = {}
    kernels = {}
    events = []
    members = []
    peers = []
    entry = dict(
        group="vllm.general_plugins", name="unit-hook", value="unit.fixture:register"
    )
    for i, (role, ordinal) in enumerate(
        (("api-server", 0), ("worker", 0), ("worker", 1), ("engine-core-scheduler", 0))
    ):
        pid, ticks = 1000 + i, 900 + i
        slot = f"{role}/{ordinal}"
        process = dict(
            host="unit-host",
            role=role,
            ordinal=ordinal,
            pid=pid,
            start_identity=f"pid:{pid}:start_ticks:{ticks}",
            process_epoch=i + 1,
            assignment_source="host",
        )
        kernel = dict(
            pid=pid,
            start_ticks=ticks,
            session=1000,
            boot_id="00000000-0000-0000-0000-000000000001",
        )
        event = dict(
            schema="vllm-hust-plugin-evidence/0.1",
            event_id="",
            event="invoked",
            observation_kind="loader_lifecycle",
            entry_point=entry,
            process=process,
            observed_at_ns=150 + i,
            delivery_attempt=1,
            plan_id=semantic["native_plan_id"],
            launch_id=launch,
            binding_status="bound",
            occurrence_id=None,
            controller_instance_id=None,
            invocation_seq=None,
            dispatch_id=None,
            plugin_id=None,
            artifact_digest=None,
            identity_status="unresolved",
            detail="unit loader invocation",
        )
        material = [
            process["host"],
            pid,
            process["start_identity"],
            i + 1,
            role,
            ordinal,
            *entry.values(),
            event["event"],
            event["detail"],
            None,
            event["plan_id"],
            launch,
            event["observation_kind"],
            None,
            1,
            event["observed_at_ns"],
            "host",
        ]
        event["event_id"] = hashlib.sha256(
            json.dumps(material, separators=(",", ":")).encode()
        ).hexdigest()
        event = parse_host_event(calibration.canonical(event))
        roster[slot] = process
        kernels[slot] = kernel
        events.append(event)
        if role != "engine-core-scheduler":
            members.append(
                dict(
                    role=role,
                    ordinal=ordinal,
                    event=event,
                    identity={**kernel, "launch_id": launch},
                )
            )
            peers.append(dict(process={**process, **kernel}))
    epoch = dict(
        roster=roster,
        kernels=kernels,
        enrollment=dict(
            native_plan_id=semantic["native_plan_id"],
            native_launch_id=launch,
            semantic_context={
                k: semantic[k]
                for k in (
                    "execution_plan_id",
                    "controller_instance",
                    "candidate_generation",
                    "membership_epoch",
                )
            },
            source_peers=peers,
        ),
    )
    return epoch, semantic, members, events


def test_archived_bridge_retains_four_host_roles_but_only_three_native_senders():
    epoch, semantic, members, events = _archived_epoch_link_fixture()
    calibration.verify_calibration_epoch_links(epoch, semantic, members, events)
    assert (
        len(epoch["roster"]) == 4
        and len(epoch["enrollment"]["source_peers"]) == len(members) == 3
    )


@pytest.mark.parametrize(
    "field",
    [
        "execution_plan_id",
        "controller_instance",
        "candidate_generation",
        "membership_epoch",
    ],
)
def test_same_native_plan_rejects_stale_or_swapped_semantic_context(field):
    epoch, semantic, members, events = _archived_epoch_link_fixture()
    original_plan = epoch["enrollment"]["native_plan_id"]
    epoch["enrollment"]["semantic_context"][field] = (
        semantic[field] + 1
        if type(semantic[field]) is int
        else semantic[field] + "-another"
    )
    assert (
        epoch["enrollment"]["native_plan_id"]
        == original_plan
        == semantic["native_plan_id"]
    )
    with pytest.raises(ValueError, match="semantic context"):
        calibration.verify_calibration_epoch_links(epoch, semantic, members, events)


@pytest.mark.parametrize(
    "mutation", ["wrong-kernel", "duplicate-worker", "fourth-scheduler"]
)
def test_native_sender_chain_cannot_substitute_another_epoch_or_roster(mutation):
    import copy

    epoch, semantic, members, events = _archived_epoch_link_fixture()
    peers = epoch["enrollment"]["source_peers"]
    if mutation == "wrong-kernel":
        peers[1]["process"]["start_ticks"] += 100
    elif mutation == "duplicate-worker":
        peers[2] = copy.deepcopy(peers[1])
    else:
        peers.append(
            dict(
                process={
                    **epoch["roster"]["engine-core-scheduler/0"],
                    **epoch["kernels"]["engine-core-scheduler/0"],
                }
            )
        )
    with pytest.raises(ValueError):
        calibration.verify_calibration_epoch_links(epoch, semantic, members, events)


@pytest.mark.parametrize("field", ["launch_id", "boot_id"])
def test_original_membership_identity_cannot_join_a_different_launch_or_kernel(field):
    epoch, semantic, members, events = _archived_epoch_link_fixture()
    members[1]["identity"][field] += "-another"
    with pytest.raises(ValueError, match="membership"):
        calibration.verify_calibration_epoch_links(epoch, semantic, members, events)
