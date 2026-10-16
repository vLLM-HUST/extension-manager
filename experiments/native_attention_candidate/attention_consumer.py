"""Full mixed-chain cached native OP consumer; no formal qualification."""

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
from experiments.native_kv_tensor_candidate import artifact_transport as transport
from experiments.native_kv_tensor_candidate import campaign_consumer as tensor_consumer
from experiments.native_kv_tensor_candidate.projection_tensor_join import (
    verify_projection_tensor_join,
)

from . import collector as attention_collector
from . import operator_observer as observer

native = transport.native
require = transport.require
POLICY = transport.POLICY
RUNTIME_POLICY = transport.RUNTIME_POLICY
policy_predicate = transport.policy_predicate
witness = transport.witness
runtime_contract = transport.runtime_contract
NAME = transport.NAME
MAX_ARTIFACT = transport.MAX_ARTIFACT
descriptor_predicate = transport.descriptor_predicate
tensor_predicate = transport.tensor_predicate


def verify_attention_archive(
    spec_path,
    policy_path,
    journal_path,
    *,
    acknowledged_prefix=None,
    drain_policy_path=None,
    drain_protocol=None,
):
    """Portable complete archive oracle; internal parsed ownership never escapes."""
    return _verify_attention_archive(
        spec_path,
        policy_path,
        journal_path,
        acknowledged_prefix=acknowledged_prefix,
        drain_policy_path=drain_policy_path,
        drain_protocol=drain_protocol,
        _owner=object(),
    )


def _verify_attention_archive(
    spec_path,
    policy_path,
    journal_path,
    *,
    acknowledged_prefix=None,
    drain_policy_path=None,
    drain_protocol=None,
    _owner,
    _owned_materializations=None,
):
    """Portable bytes oracle. An ACK prefix must come from authenticated live status.

    This function reads no current native PIDs or mutable sender paths. Archived
    file inodes are not portable; the original identities remain recorded, while
    the archived payload's exact bytes/digest are independently checked.
    """
    spec_raw = Path(spec_path).read_bytes()
    policy_raw = Path(policy_path).read_bytes()
    spec, policy = json.loads(spec_raw), json.loads(policy_raw)
    require(
        policy["schema"] == RUNTIME_POLICY
        and policy["classification"]
        in {"CPU_SOURCE_CANDIDATE_ONLY", runtime_contract.CLASSIFICATION}
        and policy["formal_registration"] is False
        and policy["native_spec_sha256"] == native.sha(spec_raw),
        "portable artifact policy scope/source differs",
    )
    policy_predicate(policy, spec, native.sha(spec_raw))
    senders = {s["process"]["pid"]: s for s in spec["senders"]}
    events = [json.loads(line) for line in Path(journal_path).read_bytes().splitlines()]
    require(
        len(events) >= 3
        and events[0]["kind"] == "collector.start"
        and events[0]["spec_sha256"] == native.sha(spec_raw)
        and events[0]["collector_source_sha256"]
        == native.sha(Path(native.__file__).read_bytes())
        and events[1]["kind"] == "tensor.transport.start"
        and events[1]["policy_sha256"] == native.sha(policy_raw)
        and events[1]["transport_source_sha256"]
        == native.sha(Path(transport.__file__).read_bytes())
        and events[1]["witness_source_sha256"]
        == native.sha(Path(witness.__file__).read_bytes()),
        "portable collector/transport/source start differs",
    )
    if policy["schema"] == RUNTIME_POLICY:
        require(
            events[1].get("runtime_contract_source_sha256")
            == native.sha(Path(runtime_contract.__file__).read_bytes()),
            "runtime contract source start differs",
        )
    require(
        events[2]["kind"] == "attention.transport.start"
        and events[2]["schema"] == attention_collector.START
        and events[2]["source_sha256"]
        == native.sha(Path(attention_collector.__file__).read_bytes())
        and events[2]["operator_source_sha256"]
        == native.sha(Path(observer.__file__).read_bytes())
        and events[2]["tensor_transport_source_sha256"]
        == native.sha(Path(transport.__file__).read_bytes())
        and events[2]["formal_registration"] is False,
        "portable attention wrapper/source start differs",
    )
    drain_module = None
    starts = 3
    ack_source_sha = native.sha(Path(attention_collector.__file__).read_bytes())
    if drain_policy_path is not None:
        if drain_protocol is None:
            from . import drain_collector as drain_module
        else:
            drain_module = drain_protocol
        from . import phase_drain

        drain_raw = Path(drain_policy_path).read_bytes()
        drain_policy = json.loads(drain_raw)
        require(
            drain_policy
            == {
                "schema": drain_module.POLICY,
                "native_spec_sha256": native.sha(spec_raw),
                "tensor_policy_sha256": native.sha(policy_raw),
                "phase_ids": [p["phase_id"] for p in spec["phases"]],
                "required_ranks": [0, 1],
                "formal_registration": False,
            },
            "portable source drain policy differs",
        )
        ack_source_sha = native.sha(Path(drain_module.__file__).read_bytes())
        require(
            len(events) >= 4
            and events[3]["kind"]
            == (
                "attention.drain.start"
                if drain_protocol is None
                else drain_protocol.START_KIND
            )
            and events[3]["schema"] == drain_module.START
            and events[3]["source_sha256"] == ack_source_sha
            and events[3]["producer_source_sha256"]
            == native.sha(Path(phase_drain.__file__).read_bytes())
            and events[3]["drain_policy_sha256"] == native.sha(drain_raw)
            and events[3]["formal_registration"] is False,
            "portable source drain start differs",
        )
        starts = 4
    sender_records, sender_last_accept, drained = {}, {}, {}
    operator_seen, operator_completed = set(), {}
    typed_by_sequence = {}
    maps, mapping_stamps, upload_stamps, upload_counts = {}, {}, {}, {}
    seen, tensor_seen, completed = set(), set(), {}
    previous = "0" * 64
    last_clock = events[0]["started_monotonic_ns"]
    for sequence, event in enumerate(events):
        require(
            event["sequence"] == sequence
            and event["previous_sha256"] == previous
            and event["event_sha256"]
            == native.sha(
                native.canonical(
                    {k: v for k, v in event.items() if k != "event_sha256"}
                )
            ),
            "portable authority chain prefix differs",
        )
        previous = event["event_sha256"]
        if sequence < starts:
            continue
        allowed_kinds = {
            "native.accepted",
            "tensor.artifact.accepted",
            "attention.operator.accepted",
        }
        if drain_module is not None:
            allowed_kinds.add("attention.worker.drained")
        require(
            event["kind"] in allowed_kinds, "portable authority event kind unsupported"
        )
        raw = base64.b64decode(event["raw_base64"], validate=True)
        digest = native.sha(raw)
        require(
            digest == event["raw_sha256"] and digest not in seen,
            "portable native bytes are changed or replayed",
        )
        seen.add(digest)
        sender = senders.get(event["peer"]["pid"])
        require(
            sender is not None
            and event["peer"]["uid"] == sender["peer_uid"]
            and event["peer"]["gid"] == sender["peer_gid"]
            and event["source_sha256"]
            == {s["path"]: s["sha256"] for s in sender["source_files"]}
            and event["process"]
            == {
                k: sender["process"][k]
                for k in ["pid", "start_ticks", "start_identity", "boot_id", "session"]
            }
            and event["archive_identity"] == events[0]["archive_identity"],
            "portable sender source/kernel binding differs",
        )
        accepted = event["accepted_monotonic_ns"]
        require(
            type(accepted) is int and accepted >= last_clock,
            "portable collector accept chronology differs",
        )
        last_clock = accepted
        sender_key = (event["peer"]["pid"], event["runtime_request_id"])
        require(sender_key not in drained, "portable fact after source drain")
        if event["kind"] == "attention.worker.drained":
            fact = json.loads(raw)
            require(native.canonical(fact) == raw, "source drain is noncanonical")
            runtime = fact["runtime_request_id"]
            require(runtime in maps, "source drain lacks actual API mapping")
            phase = maps[runtime]
            require(
                native.sha(Path(phase_drain.__file__).read_bytes())
                in event["source_sha256"].values()
                and ack_source_sha in event["source_sha256"].values(),
                "portable drain sources are unregistered",
            )
            drain_module.verify_drain(
                fact,
                sender=sender,
                spec=spec,
                phase=phase,
                records=sender_records.get(sender_key, []),
                accepted_monotonic_ns=accepted,
                previous_ack_accepted_monotonic_ns=sender_last_accept.get(sender_key),
            )
            drained[sender_key] = {
                "runtime_request_id": runtime,
                "phase_id": phase["phase_id"],
                "rank": sender["process"]["ordinal"],
                "source_completed_monotonic_ns": fact[
                    "source_drain_completed_monotonic_ns"
                ],
                "accepted_monotonic_ns": accepted,
                "sequence": sequence,
            }
        elif event["kind"] == "native.accepted":
            fact, phase, update = native.native_fact_predicate(
                raw,
                sender,
                spec,
                accepted_monotonic_ns=accepted,
                mappings=maps,
                mapping_stamps=mapping_stamps,
                upload_stamps=upload_stamps,
                upload_counts=upload_counts,
            )
            runtime = fact["runtime_request_id"]
            if update[0] == "mapping":
                maps[runtime], mapping_stamps[runtime] = phase, fact["monotonic_ns"]
            elif update[0] == "upload":
                upload_stamps[(runtime, update[1])] = fact[
                    "observed_after_barrier_monotonic_ns"
                ]
                upload_counts[(runtime, update[1])] = (
                    upload_counts.get((runtime, update[1]), 0) + 1
                )
            else:
                upload_counts[("projection", runtime, update[1])] = 1
        elif event["kind"] == "tensor.artifact.accepted":
            envelope = json.loads(raw)
            require(
                native.canonical(envelope) == raw
                and envelope["transport_policy_sha256"] == native.sha(policy_raw),
                "portable tensor envelope policy differs",
            )
            artifact = event["artifact"]
            descriptor_predicate(artifact)
            require(
                event["source_artifact"] == envelope["artifact"],
                "portable observed source artifact inode differs",
            )
            require(
                NAME.fullmatch(artifact["basename"])
                and artifact["sha256"] == envelope["artifact"]["sha256"],
                "portable artifact digest descriptor differs",
            )
            path = Path(journal_path).parent / artifact["basename"]
            require(
                not path.is_symlink() and path.is_file(),
                "portable artifact path is not regular",
            )
            payload = path.read_bytes()
            require(
                0 < len(payload) <= MAX_ARTIFACT
                and len(payload) == artifact["size"] == envelope["artifact"]["size"]
                and native.sha(payload) == artifact["sha256"],
                "portable archived blob changed",
            )
            owned = observer._own_materialization(payload, _owner)
            fact = owned._detached(_owner)
            phase = tensor_predicate(
                fact, envelope, policy, sender, maps, mapping_stamps, accepted, spec
            )
            owned._compact_after_tensor_check(_owner)
            key = (
                fact["binding"]["runtime_request_id"],
                envelope["transaction_id"],
                fact["binding"]["rank"],
                fact["binding"]["layer_index"],
            )
            require(key not in tensor_seen, "portable tensor rank/layer replay")
            tensor_seen.add(key)
            completed.setdefault(key[:2], set()).add(key[2:])
            typed_by_sequence[sequence] = (event, owned)
            if _owned_materializations is not None:
                _owned_materializations[sequence] = owned
        else:
            fact = json.loads(raw)
            require(native.canonical(fact) == raw, "attention fact noncanonical")
            require(
                fact["process"] == sender["process"]
                and fact["launch_id"] == spec["native_launch_id"]
                and fact["plan_id"] == spec["native_plan_id"]
                and sender["process"]["role"] == "worker"
                and native.sha(Path(attention_collector.__file__).read_bytes())
                in event["source_sha256"].values()
                and native.sha(Path(observer.__file__).read_bytes())
                in event["source_sha256"].values()
                and type(fact["monotonic_ns"]) is int
                and spec["frozen_monotonic_ns"] <= fact["monotonic_ns"] <= accepted
                and accepted - fact["monotonic_ns"] <= spec["max_event_age_ns"],
                "portable attention source/kernel/clock differs",
            )
            reference_sequence = fact["materialization_ack"]["sequence"]
            require(
                type(reference_sequence) is int
                and reference_sequence in typed_by_sequence,
                "attention reference does not precede its actual typed receipt",
            )
            reference, owned = typed_by_sequence[reference_sequence]
            payload = owned._raw(_owner)
            issued_ack = {
                "schema": native.ACK,
                "raw_sha256": reference["raw_sha256"],
                "event_sha256": reference["event_sha256"],
                "sequence": reference["sequence"],
                "phase": reference["phase"],
                "collector": events[0]["collector"],
                "collector_source_sha256": ack_source_sha,
                "archive_identity": reference["archive_identity"],
                "formal_producer_registration": False,
                "classification": policy["classification"],
            }
            issued_ack["ack_sha256"] = native.sha(native.canonical(issued_ack))
            require(
                fact["materialization_ack"] == issued_ack,
                "attention reference differs from complete issued typed ACK",
            )
            attention_collector._verify_owned_reference(
                fact,
                reference,
                payload,
                owned,
                _owner,
                collector_source_sha256=ack_source_sha,
                collector_identity=events[0]["collector"],
            )
            owned._release_operator_tree(_owner)
            runtime = fact["runtime_request_id"]
            require(runtime in maps, "attention lacks API mapping")
            phase = maps[runtime]
            key = (
                runtime,
                fact["materialization_transaction_id"],
                fact["process"]["ordinal"],
                fact["layer_index"],
            )
            require(
                key[:2] in completed and key[2:] in completed[key[:2]],
                "attention layer is not materialized",
            )
            require(
                key not in operator_seen, "attention first witness rank/layer replay"
            )
            operator_seen.add(key)
            operator_completed.setdefault(key[:2], set()).add(key[2:])
        require(
            event["phase"] == phase
            and event["runtime_request_id"]
            == (
                fact["binding"]["runtime_request_id"]
                if event["kind"] == "tensor.artifact.accepted"
                else fact["runtime_request_id"]
            ),
            "portable phase/runtime join differs",
        )
        if (
            sender["process"]["role"] == "worker"
            and event["kind"] != "attention.worker.drained"
        ):
            sender_last_accept[sender_key] = accepted
            sender_records.setdefault(sender_key, []).append(
                {k: event[k] for k in ("sequence", "event_sha256", "raw_sha256")}
            )
    if acknowledged_prefix is not None:
        require(
            acknowledged_prefix
            == {"next_sequence": len(events), "last_event_sha256": previous},
            "authenticated ACK prefix differs from archived chain",
        )
    complete = []
    for (runtime, tx), observed in completed.items():
        phase = maps[runtime]
        expected = {
            (rank, layer)
            for rank in phase["expected_ranks"]
            for layer in policy["requirements"][phase["phase_id"]]["layer_indices"]
        }
        if observed == expected and acknowledged_prefix is not None:
            complete.append(
                {
                    "phase_id": phase["phase_id"],
                    "runtime_request_id": runtime,
                    "transaction_id": tx,
                }
            )
    attention_complete = [
        t
        for t in complete
        if operator_completed.get((t["runtime_request_id"], t["transaction_id"]))
        == {
            (rank, layer)
            for rank in maps[t["runtime_request_id"]]["expected_ranks"]
            for layer in policy["requirements"][
                maps[t["runtime_request_id"]]["phase_id"]
            ]["layer_indices"]
        }
    ]
    if drain_module is not None:
        require(
            maps
            and all(
                {
                    d["rank"]
                    for d in drained.values()
                    if d["runtime_request_id"] == runtime
                }
                == set(phase["expected_ranks"])
                for runtime, phase in maps.items()
            ),
            "portable full phase source drain is incomplete",
        )
    return {
        "attention_complete_transactions": attention_complete,
        "source_operator_completion_join": bool(attention_complete),
        "schema": "ecpa-selected-KV-attention-portable-analysis/v1",
        "classification": policy["classification"],
        "complete_transactions": complete,
        "durable_artifact_join_complete": bool(complete),
        "acknowledged_prefix_status": "verified"
        if acknowledged_prefix is not None
        else "unknown",
        "GPU_qualification": None,
        "attention_consumption": None,
        "full_model_quality": None,
        "formal_registration": False,
        **(
            {"source_drains": list(drained.values()), "full_phase_source_drained": True}
            if drain_module is not None
            else {}
        ),
    }


artifact_transport = transport
canonical = native.canonical
sha = native.sha
SCHEMA_V2 = kv_request_runner.SCHEMA_V2
validate_kv = kv_request_runner.validate_kv
FINAL_PREFIX_POLICY = kv_time_policy.FINAL_PREFIX_POLICY
verify_time_contract = kv_time_policy.verify_time_contract
EXPECTED_LAYERS = list(range(28))
CONTRACT = "ecpa-cached-native-attention-consumer-preregistration/v1"
SCHEMA = "ecpa-cached-native-attention-mixed-request-observation/v1"


def expected_sources():
    return (
        tensor_consumer.expected_sources()
        | {
            str(Path(module.__file__).resolve()): sha(
                Path(module.__file__).read_bytes()
            )
            for module in (attention_collector, observer, tensor_consumer)
        }
        | {str(Path(__file__).resolve()): sha(Path(__file__).read_bytes())}
    )


def declare_attention_recipe(recipe):
    tensor_consumer.require_declared_tensor_recipe(recipe)
    value = copy.deepcopy(recipe)
    require(
        "attention_consumer_contract" not in value,
        "attention contract already declared",
    )
    sources = expected_sources()
    existing = {x["path"]: x["sha256"] for x in value["sources"]}
    require(
        all(p not in existing or existing[p] == d for p, d in sources.items()),
        "attention source previously differs",
    )
    for path, digest in sources.items():
        if path not in existing:
            value["sources"].append(dict(path=path, sha256=digest))
    value["attention_consumer_contract"] = {
        "schema": CONTRACT,
        "expected_layers": EXPECTED_LAYERS,
        "expected_ranks": [0, 1],
        "scope": "first-eager-single-request-single-token-"
        "cached-native-argument-completion-only",
        "source_sha256": sources,
        "formal_result": False,
    }
    return value


def require_declared_attention_recipe(recipe, *, source_resolver=None):
    tensor_consumer.require_declared_tensor_recipe(
        recipe, source_resolver=source_resolver
    )
    contract = recipe.get("attention_consumer_contract")
    require(isinstance(contract, dict), "attention consumer not preregistered")
    expected = expected_sources()
    declared = contract.get("source_sha256")
    require(isinstance(declared, dict), "attention source declaration missing")
    require(
        {k: v for k, v in contract.items() if k != "source_sha256"}
        == {
            "schema": CONTRACT,
            "expected_layers": EXPECTED_LAYERS,
            "expected_ranks": [0, 1],
            "scope": "first-eager-single-request-single-token-"
            "cached-native-argument-completion-only",
            "formal_result": False,
        },
        "attention consumer scope differs",
    )
    if source_resolver is None:
        require(declared == expected, "live attention source paths changed")
    else:
        require(len(declared) == len(expected), "attention source inventory changed")
        for current, digest in expected.items():
            originals = [p for p in declared if Path(p).name == Path(current).name]
            require(
                len(originals) == 1, "attention source basename missing or ambiguous"
            )
            original = originals[0]
            resolved = Path(source_resolver(original))
            require(
                declared[original] == digest
                and resolved.is_absolute()
                and resolved.is_file()
                and sha(resolved.read_bytes()) == digest,
                "attention copied/imported source bytes differ",
            )
    pinned = {x["path"]: x["sha256"] for x in recipe["sources"]}
    require(
        all(pinned.get(p) == d for p, d in declared.items()),
        "attention source preregistration missing",
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
    drain_policy_path=None,
    observation_protocol=None,
):
    """Portable recorded-clock/source/bytes oracle; no current PID authentication."""
    if observation_protocol is None:
        validate_kv(recipe, source_resolver=source_resolver)
        require_declared_attention_recipe(recipe, source_resolver=source_resolver)
        collector_module = attention_collector
        time_predicate = verify_time_contract
        if drain_policy_path is not None:
            from . import drain_collector, drain_consumer, drain_time_policy

            drain_consumer.require_declared_drain_recipe(
                recipe, source_resolver=source_resolver
            )
            collector_module = drain_collector
            from functools import partial

            time_predicate = partial(
                drain_time_policy.verify_time_contract,
                upload_tail_policy=recipe["attention_drain_contract"].get(
                    "upload_tail_policy"
                ),
            )
        require(
            recipe["schema"] == SCHEMA_V2, "mixed tensor request requires frozen KV v2"
        )
        metadata_schema = "ecpa-observed-KV-HTTP-response/v2"
        http_client_source = Path(request_runner.__file__)
    else:
        observation_protocol.validate_recipe(recipe, source_resolver=source_resolver)
        collector_module = observation_protocol.collector
        time_predicate = observation_protocol.verify_time_contract
        metadata_schema = observation_protocol.http_runner.METADATA
        http_client_source = Path(observation_protocol.http_runner.__file__)
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
        == sha(Path(collector_module.__file__).read_bytes()),
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
    if drain_policy_path is not None:
        sealed_predicate = (
            drain_consumer.verify_sealed_status
            if observation_protocol is None
            else observation_protocol.verify_sealed_status
        )
        require(
            sealed_predicate(after, phase, drain_policy_path),
            "mixed source phase is not actually sealed",
        )
    events = [json.loads(line) for line in Path(journal_path).read_bytes().splitlines()]
    materialization_owner = object()
    owned_materializations = {}
    typed = _verify_attention_archive(
        spec_path,
        policy_path,
        journal_path,
        acknowledged_prefix=(
            after["status"]["acknowledged_prefix"]
            if observation_protocol is None
            else observation_protocol.sealed_prefix(after, phase, drain_policy_path)
        ),
        drain_policy_path=drain_policy_path,
        drain_protocol=(
            observation_protocol.collector if observation_protocol is not None else None
        ),
        _owner=materialization_owner,
        _owned_materializations=owned_materializations,
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
        and metadata["schema"] == metadata_schema
        and metadata["status"] == 200
        and metadata["url"] == phase["url"]
        and metadata["request_sha256"] == sha((output / "request.bin").read_bytes())
        and metadata["response_sha256"] == sha(body)
        and metadata["client_source_sha256"] == sha(http_client_source.read_bytes())
        and metadata["client"]["boot_id"] == descriptor["collector"]["boot_id"],
        "mixed raw HTTP/client/source binding differs",
    )
    request_runner.verify_rpc_budget(phase, metadata, metadata_schema=metadata_schema)
    uids = {s["peer_uid"] for s in spec["senders"]}
    require(len(uids) == 1, "mixed registered peer UID ambiguous")
    # Retain full chain, including both starts and all phase events. This is not
    # generic verify_journal and never constructs a filtered fake proof.
    temporal = time_predicate(
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
    attention_selected = [
        t for t in typed["attention_complete_transactions"] if t["phase_id"] == phase_id
    ]
    require(
        attention_selected == selected and typed["source_operator_completion_join"],
        "attention lacks full56 same typed transaction completion witnesses",
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
        fact = owned_materializations[event["sequence"]]._report_after_fresh_read(
            payload_raw, materialization_owner
        )
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
        effect_upload_sequences=set(temporal["effect_upload_sequences"])
        if "effect_upload_sequences" in temporal
        else None,
        phase_id=phase_id if observation_protocol is not None else None,
    )
    operator_count = 0
    projections = {}
    for event in events:
        if (
            event.get("phase", {}).get("phase_id") != phase_id
            or "raw_base64" not in event
        ):
            continue
        fact = json.loads(base64.b64decode(event["raw_base64"], validate=True))
        if (
            event["kind"] == "native.accepted"
            and fact["schema"] == native.PROJECTION_V2
        ):
            projections[fact["process"]["ordinal"]] = fact
    for event in events:
        if event["kind"] != "attention.operator.accepted":
            continue
        if (
            observation_protocol is not None
            and event.get("phase", {}).get("phase_id") != phase_id
        ):
            # Every original global record was already semantically verified above.
            # Select only this request's report; never filter/rechain raw evidence.
            continue
        fact = json.loads(base64.b64decode(event["raw_base64"], validate=True))
        require(
            event["phase"]["phase_id"] == phase_id
            and fact["runtime_request_id"] == runtime
            and fact["materialization_transaction_id"] == transaction,
            "attention contains another phase/runtime/transaction",
        )
        require(
            all(
                type(fact[k]) is int and sent <= fact[k] <= received
                for k in [
                    "materialization_ack_registered_monotonic_ns",
                    "metadata_bound_monotonic_ns",
                    "native_entry_readback_started_ns",
                    "native_entry_readback_completed_ns",
                    "native_call_started_ns",
                    "native_call_returned_ns",
                    "native_stream_completed_ns",
                    "monotonic_ns",
                ]
            ),
            "native attention source/completion clock outside HTTP",
        )
        projection = projections[fact["process"]["ordinal"]]
        row = projection["host_cpu_block_ids"]
        require(
            fact["process"] == projection["process"]
            and fact["actual_cpu_block_ids"][: len(row)] == row
            and projection["monotonic_ns"] <= fact["metadata_bound_monotonic_ns"],
            "cached native call does not follow same-worker materialized full row",
        )
        operator_count += 1
    require(
        operator_count == 56,
        "attention first witnesses do not cover both ranks/all28layers",
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
        operator_receipt_count=operator_count,
        finite_native_argument_completion_join=True,
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


def execute_with_attention(
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
    drain_policy_path=None,
):
    """One real RPC, actual before/after OS authentication, unfiltered mixed oracle."""
    output = Path(output)
    validate_kv(recipe)
    require_declared_attention_recipe(recipe)
    collector_module = attention_collector
    if drain_policy_path is not None:
        from . import drain_collector, drain_consumer

        drain_consumer.require_declared_drain_recipe(recipe)
        collector_module = drain_collector
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
        == sha(Path(collector_module.__file__).read_bytes()),
        "mixed caller must pin actual typed collector wrapper source",
    )
    before = collector_client.authenticate(
        Path(socket_path),
        descriptor,
        Path(spec_path),
        Path(collector_source_path),
        drain_policy_path=drain_policy_path,
    )
    result = request_runner.run_rpc_only(recipe, phase_id, output)
    output.chmod(0o700)
    (output / "collector-before.json").write_bytes(canonical(before))
    (output / "collector-launcher-descriptor.json").write_bytes(canonical(descriptor))
    result["classification"] = policy["classification"]
    result["mixed_typed_HTTP_ACK_join"] = None
    result["mixed_attention_HTTP_ACK_join"] = None
    try:
        after = collector_client.authenticate(
            Path(socket_path),
            descriptor,
            Path(spec_path),
            Path(collector_source_path),
            drain_policy_path=drain_policy_path,
        )
        if drain_policy_path is not None:
            import time

            deadline_ns = (
                before["authentication_clock"]["dispatch_monotonic_ns"]
                + phase["rpc_budget_s"] * 1_000_000_000
            )
            poll = 0
            while True:
                (output / f"collector-drain-poll-{poll:04d}.json").write_bytes(
                    canonical(after)
                )
                if drain_consumer.verify_sealed_status(after, phase, drain_policy_path):
                    break
                require(
                    time.monotonic_ns() < deadline_ns,
                    "source drain exceeds frozen phase budget",
                )
                # Waiting follows an authenticated source-state predicate; a
                # quiet interval is never considered a source completion proof.
                time.sleep(0.01)
                after = collector_client.authenticate(
                    Path(socket_path),
                    descriptor,
                    Path(spec_path),
                    Path(collector_source_path),
                    drain_policy_path=drain_policy_path,
                )
                poll += 1
        (output / "collector-after.json").write_bytes(canonical(after))
        observed = verify_observation(
            recipe,
            phase_id,
            output,
            descriptor=descriptor,
            spec_path=Path(spec_path),
            journal_path=Path(journal_path),
            policy_path=Path(policy_path),
            drain_policy_path=drain_policy_path,
        )
        (output / "attention-HTTP-ACK-observation.json").write_bytes(
            canonical(observed)
        )
        result["mixed_typed_HTTP_ACK_join"] = observed["observed_typed_HTTP_ACK_join"]
        result["mixed_attention_HTTP_ACK_join"] = observed[
            "observed_typed_HTTP_ACK_join"
        ]
        result["operator_receipt_count"] = observed["operator_receipt_count"]
        result["typed_model_task_passed"] = observed["model_task_passed"]
        result["tensor_receipt_count"] = observed["tensor_receipt_count"]
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        result["mixed_attention_join_failure"] = str(error)
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
