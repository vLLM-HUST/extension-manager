"""Mixed tensor journal + strict HTTP + final ACK consumer; never formal admission."""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

from experiments.native_challenge_candidate import (
    collector_client,
    kv_request_runner,
    kv_time_policy,
    request_runner,
)
from experiments.native_challenge_candidate.kv_request_runner import (
    SCHEMA_V2,
    validate_kv,
)
from experiments.native_challenge_candidate.kv_time_policy import (
    FINAL_PREFIX_POLICY,
    verify_time_contract,
)
from experiments.native_challenge_candidate.request_runner import (
    canonical,
    require,
    sha,
)

from . import artifact_transport, projection_tensor_join, runtime_contract, witness
from .projection_tensor_join import verify_projection_tensor_join

SCHEMA = "ecpa-selected-KV-mixed-request-observation/v1"
CONTRACT = "ecpa-selected-KV-mixed-consumer-preregistration/v1"
EXPECTED_LAYERS = list(range(28))


def expected_sources():
    return {
        str(Path(module.__file__).resolve()): sha(Path(module.__file__).read_bytes())
        for module in (
            artifact_transport,
            projection_tensor_join,
            runtime_contract,
            witness,
            collector_client,
            request_runner,
            kv_request_runner,
            kv_time_policy,
            artifact_transport.native,
        )
    } | {str(Path(__file__).resolve()): sha(Path(__file__).read_bytes())}


def declare_tensor_recipe(recipe):
    """Opt in before source/nonce freeze; never reinterpret an old frozen recipe."""
    validate_kv(recipe)
    value = copy.deepcopy(recipe)
    require(
        "tensor_consumer_contract" not in value, "mixed consumer was already declared"
    )
    sources = expected_sources()
    existing = {x["path"]: x["sha256"] for x in value["sources"]}
    require(
        all(p not in existing or existing[p] == d for p, d in sources.items()),
        "mixed consumer source already differs",
    )
    for path, digest in sources.items():
        if path not in existing:
            value["sources"].append(dict(path=path, sha256=digest))
    value["tensor_consumer_contract"] = {
        "schema": CONTRACT,
        "expected_layers": EXPECTED_LAYERS,
        "scope": "selected-logical-KV-metadata-upload-HTTP-finalACK-only",
        "source_sha256": sources,
        "formal_result": False,
    }
    return value


def require_declared_tensor_recipe(recipe, *, source_resolver=None):
    contract = recipe.get("tensor_consumer_contract")
    require(isinstance(contract, dict), "mixed consumer was not preregistered")
    expected = expected_sources()
    declared = contract.get("source_sha256")
    require(isinstance(declared, dict), "mixed source declaration missing")
    require(
        {k: v for k, v in contract.items() if k != "source_sha256"}
        == {
            "schema": CONTRACT,
            "expected_layers": EXPECTED_LAYERS,
            "scope": "selected-logical-KV-metadata-upload-HTTP-finalACK-only",
            "formal_result": False,
        },
        "mixed consumer scope changed",
    )
    if source_resolver is None:
        require(declared == expected, "live mixed consumer source paths changed")
    else:
        # Original frozen names remain evidence; never rewrite the recipe.
        # Every imported oracle must correspond to exactly one original name
        # and the resolver's copied bytes as well as the actual imported bytes.
        require(len(declared) == len(expected), "mixed source inventory changed")
        for current, digest in expected.items():
            originals = [p for p in declared if Path(p).name == Path(current).name]
            require(len(originals) == 1, "mixed source name absent or ambiguous")
            original = originals[0]
            resolved = Path(source_resolver(original))
            require(
                declared[original] == digest
                and resolved.is_absolute()
                and resolved.is_file()
                and sha(resolved.read_bytes()) == digest,
                "portable mixed source bytes differ from imported oracle",
            )
    pinned = {x["path"]: x["sha256"] for x in recipe["sources"]}
    require(
        all(pinned.get(p) == d for p, d in declared.items()),
        "mixed consumer source preregistration missing",
    )


def verify_observation(
    recipe,
    phase_id,
    output,
    *,
    descriptor,
    spec_path,
    journal_path,
    policy_path,
    source_resolver=None,
):
    """Portable recorded-clock/source/bytes oracle; no current PID authentication."""
    validate_kv(recipe, source_resolver=source_resolver)
    require_declared_tensor_recipe(recipe, source_resolver=source_resolver)
    require(recipe["schema"] == SCHEMA_V2, "mixed tensor request requires frozen KV v2")
    phase = next(p for p in recipe["phases"] if p["phase_id"] == phase_id)
    require(
        phase.get("ack_time_policy") == FINAL_PREFIX_POLICY
        and phase.get("rpc_budget_s") == 180,
        "mixed tensor request requires prospective final ACK budget180",
    )
    spec_raw, policy_raw = Path(spec_path).read_bytes(), Path(policy_path).read_bytes()
    spec, policy = json.loads(spec_raw), json.loads(policy_raw)
    request_runner.require_phase_registration(
        phase, spec, kv_requirements=phase["kv_requirements"], materialized_row=True
    )
    requirement = policy["requirements"][phase_id]
    require(
        requirement
        == dict(
            layer_indices=EXPECTED_LAYERS, semantic_anchor=1201, physical_anchor=1024
        ),
        "mixed request must retain all two-rank 28-layer requirements",
    )
    require(
        policy["native_spec_sha256"] == sha(spec_raw)
        and descriptor["spec_sha256"] == sha(spec_raw)
        and descriptor["collector"] == descriptor["launcher_observed_identity"]
        and descriptor["collector_source_sha256"]
        == sha(Path(artifact_transport.__file__).read_bytes()),
        "mixed collector/launcher/source/spec differs",
    )
    before, after = [
        json.loads((output / name).read_bytes())
        for name in ["collector-before.json", "collector-after.json"]
    ]
    for receipt in (before, after):
        require(
            receipt["status"]["failed"] is False
            and receipt["status"]["formal_producer_registration"] is False
            and receipt["formal_result"] is False,
            "mixed status is failed or scope promoted",
        )
    events = [json.loads(line) for line in Path(journal_path).read_bytes().splitlines()]
    typed = artifact_transport.verify_archive(
        spec_path,
        policy_path,
        journal_path,
        acknowledged_prefix=after["status"]["acknowledged_prefix"],
    )
    require(
        events[0]["collector"] == descriptor["collector"]
        and events[0]["archive_identity"] == descriptor["archive_identity"],
        "mixed raw collector owner differs",
    )
    metadata = json.loads((output / "response-metadata.json").read_bytes())
    body = (output / "response.bin").read_bytes()
    require(
        (output / "request.bin").read_bytes() == canonical(phase["payload"])
        and json.loads((output / "headers.json").read_bytes()) == phase["headers"]
        and metadata["schema"] == "ecpa-observed-KV-HTTP-response/v2"
        and metadata["status"] == 200
        and metadata["url"] == phase["url"]
        and metadata["request_sha256"] == sha((output / "request.bin").read_bytes())
        and metadata["response_sha256"] == sha(body)
        and metadata["client_source_sha256"]
        == sha(Path(request_runner.__file__).read_bytes())
        and metadata["client"]["boot_id"] == descriptor["collector"]["boot_id"],
        "mixed raw HTTP/client/source binding differs",
    )
    request_runner.verify_rpc_budget(phase, metadata)
    uids = {s["peer_uid"] for s in spec["senders"]}
    require(len(uids) == 1, "mixed registered peer UID ambiguous")
    # Retain full chain, including both starts and all phase events. This is not
    # generic verify_journal and never constructs a filtered fake proof.
    temporal = verify_time_contract(
        phase, events, metadata, before, after, descriptor, next(iter(uids))
    )
    selected = [t for t in typed["complete_transactions"] if t["phase_id"] == phase_id]
    require(
        len(selected) == 1 and typed["durable_artifact_join_complete"],
        "mixed request lacks complete fresh two-rank/all-layer typed transaction",
    )
    runtime, transaction = (
        selected[0]["runtime_request_id"],
        selected[0]["transaction_id"],
    )
    tensor_count = 0
    tensor_payloads_by_sequence = {}
    sent, received = metadata["sent_monotonic_ns"], metadata["received_monotonic_ns"]
    for event in events:
        if (
            event.get("kind") != "tensor.artifact.accepted"
            or event.get("phase", {}).get("phase_id") != phase_id
        ):
            continue
        envelope = json.loads(base64.b64decode(event["raw_base64"], validate=True))
        require(
            envelope["runtime_request_id"] == runtime
            and envelope["transaction_id"] == transaction,
            "mixed phase contains another tensor transaction",
        )
        payload_path = Path(journal_path).parent / event["artifact"]["basename"]
        payload_raw = payload_path.read_bytes()
        require(
            sha(payload_raw) == event["artifact"]["sha256"],
            "mixed typed payload changed after raw verification",
        )
        fact = json.loads(payload_raw)
        clocks = [
            fact[k]
            for k in [
                "source_before_gather_ns",
                "reference_after_gather_ns",
                "write_completed_barrier_ns",
                "destination_readback_completed_ns",
            ]
        ]
        require(
            all(type(x) is int and sent <= x <= received for x in clocks)
            and clocks == sorted(clocks),
            "actual tensor read/write materialization lies outside HTTP window",
        )
        tensor_payloads_by_sequence[event["sequence"]] = fact
        tensor_count += 1
    require(
        tensor_count == 56,
        "mixed request does not preserve both ranks/all28-layer receipts",
    )
    projection_join = verify_projection_tensor_join(
        events,
        tensor_payloads_by_sequence,
        runtime_request_id=runtime,
        transaction_id=transaction,
    )
    data = json.loads(body)
    choice = data["choices"][0]
    task_passed = bool(
        data["id"] == phase["expected_response_id"]
        and data["model"] == phase["payload"]["model"]
        and isinstance(choice["message"]["content"], str)
        and choice["message"]["content"].strip() == phase["response_oracle"]["expected"]
        and choice["finish_reason"] == "stop"
        and type(data["usage"]["prompt_tokens"]) is int
        and data["usage"]["prompt_tokens"] == 1201
        and type(data["usage"]["completion_tokens"]) is int
        and data["usage"]["completion_tokens"] >= 32
    )
    return dict(
        schema=SCHEMA,
        classification=policy["classification"],
        phase_id=phase_id,
        model_task_passed=task_passed,
        observed_typed_HTTP_ACK_join=task_passed,
        typed_archive_provenance=typed,
        typed_plan_projection_upload_join=projection_join,
        ACK_time_contract=temporal,
        materialization_read_write_clocks_inside_HTTP=True,
        tensor_receipt_count=tensor_count,
        policy_sha256=sha(policy_raw),
        whole_journal_sha256=sha(Path(journal_path).read_bytes()),
        actual_raw_response_sha256=sha(body),
        fresh_OS_authentication_performed=False,
        formal_result=False,
        hardware_result=False,
        GPU_qualification=None,
        attention_consumption=None,
        full_model_quality=None,
        full_objective_satisfied=None,
    )


def execute_with_tensor(
    recipe,
    phase_id,
    output,
    *,
    socket_path,
    descriptor,
    spec_path,
    collector_source_path,
    journal_path,
    policy_path,
):
    """One real RPC, actual before/after OS authentication, unfiltered mixed oracle."""
    output = Path(output)
    validate_kv(recipe)
    require_declared_tensor_recipe(recipe)
    require(recipe["schema"] == SCHEMA_V2, "mixed tensor request requires KV v2")
    phase = next(p for p in recipe["phases"] if p["phase_id"] == phase_id)
    require(
        phase.get("ack_time_policy") == FINAL_PREFIX_POLICY
        and phase.get("rpc_budget_s") == 180,
        "mixed tensor request requires prospective clock policy",
    )
    spec = json.loads(collector_client.private_read(Path(spec_path)))
    policy = json.loads(collector_client.private_read(Path(policy_path)))
    request_runner.require_phase_registration(
        phase, spec, kv_requirements=phase["kv_requirements"], materialized_row=True
    )
    require(
        policy["requirements"][phase_id]
        == dict(
            layer_indices=EXPECTED_LAYERS, semantic_anchor=1201, physical_anchor=1024
        ),
        "mixed tensor full layer/anchor preregistration differs",
    )
    require(
        sha(Path(collector_source_path).read_bytes())
        == sha(Path(artifact_transport.__file__).read_bytes()),
        "mixed caller must pin actual typed collector wrapper source",
    )
    before = collector_client.authenticate(
        Path(socket_path), descriptor, Path(spec_path), Path(collector_source_path)
    )
    result = request_runner.run_rpc_only(recipe, phase_id, output)
    output.chmod(0o700)
    (output / "collector-before.json").write_bytes(canonical(before))
    (output / "collector-launcher-descriptor.json").write_bytes(canonical(descriptor))
    result["classification"] = policy["classification"]
    result["mixed_typed_HTTP_ACK_join"] = None
    try:
        after = collector_client.authenticate(
            Path(socket_path), descriptor, Path(spec_path), Path(collector_source_path)
        )
        (output / "collector-after.json").write_bytes(canonical(after))
        observed = verify_observation(
            recipe,
            phase_id,
            output,
            descriptor=descriptor,
            spec_path=Path(spec_path),
            journal_path=Path(journal_path),
            policy_path=Path(policy_path),
        )
        (output / "typed-HTTP-ACK-observation.json").write_bytes(canonical(observed))
        result["mixed_typed_HTTP_ACK_join"] = observed["observed_typed_HTTP_ACK_join"]
        result["typed_model_task_passed"] = observed["model_task_passed"]
        result["tensor_receipt_count"] = observed["tensor_receipt_count"]
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        result["mixed_typed_join_failure"] = str(error)
    result.update(
        formal_result=False,
        hardware_result=False,
        GPU_qualification=None,
        attention_consumption=None,
        full_model_quality=None,
        full_objective_satisfied=None,
    )
    (output / "result.json").write_bytes(canonical(result))
    return result


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument(
        "--source-map",
        type=Path,
        help="Original frozen path to copied absolute source path JSON",
    )
    args = parser.parse_args()
    source_map = json.loads(args.source_map.read_bytes()) if args.source_map else None
    observed = verify_observation(
        json.loads(args.recipe.read_bytes()),
        args.phase,
        args.output,
        descriptor=json.loads(args.descriptor.read_bytes()),
        spec_path=args.spec,
        journal_path=args.journal,
        policy_path=args.policy,
        source_resolver=(lambda original: Path(source_map[original]))
        if source_map is not None
        else None,
    )
    print(json.dumps(observed, sort_keys=True))


if __name__ == "__main__":
    main()
