"""Pure additional join after the full typed archive and time predicates pass."""

import base64
import json

from experiments.exposure_gate import native_semantic_collector as native

from . import artifact_transport


def verify_projection_tensor_join(
    events, tensor_payloads_by_sequence, *, runtime_request_id, transaction_id
):
    runtime, transaction = runtime_request_id, transaction_id
    decoded = []
    for event in events:
        if "raw_base64" not in event:
            continue
        fact = json.loads(base64.b64decode(event["raw_base64"], validate=True))
        if fact["runtime_request_id"] != runtime:
            raise ValueError("phase joins another runtime")
        decoded.append((event, fact))
    projections = {}
    uploads = []
    tensors = []
    for event, fact in decoded:
        if event["kind"] == "tensor.artifact.accepted":
            if fact["transaction_id"] != transaction:
                raise ValueError("tensor transaction differs")
            payload = tensor_payloads_by_sequence[event["sequence"]]
            tensors.append((fact, payload))
        elif fact["schema"] == native.PROJECTION_V2:
            rank = fact["process"]["ordinal"]
            if rank in projections:
                raise ValueError("repeated rank projection")
            projections[rank] = fact
        elif fact["schema"] == native.UPLOAD:
            uploads.append(fact)
    if set(projections) != {0, 1}:
        raise ValueError("missing actual two-rank materialized projections")
    if projections[0]["host_cpu_block_ids"] != projections[1]["host_cpu_block_ids"]:
        raise ValueError("two ranks materialized different logical full block rows")
    joined = {}
    for rank, projection in projections.items():
        later = [
            upload
            for upload in uploads
            if native.projection_upload_match(projection, upload)
        ]
        if not later:
            raise ValueError("projection has no later same-worker uploaded full row")
        joined[rank] = {
            "projection_transaction_id": projection["transaction_id"],
            "later_matching_uploads": len(later),
        }
    for envelope, payload in tensors:
        rank = payload["binding"]["rank"]
        projection = projections[rank]
        plan = payload["binding"]["compression_plan"]
        if not (
            envelope["process"] == projection["process"]
            and envelope["launch_id"] == projection["launch_id"]
            and envelope["plan_id"] == projection["plan_id"]
            and all(
                plan[k] == projection[k]
                for k in ("semantic_anchor", "physical_anchor", "destination_block_ids")
            )
            and payload["destination_readback_completed_ns"]
            <= projection["metadata_effect_monotonic_ns"]
            <= projection["monotonic_ns"]
        ):
            raise ValueError(
                "tensor plan/readback does not precede the same-worker projection"
            )
        # The two different transaction schemas are not interchangeable hashes.
        if artifact_transport.transaction(payload) != transaction:
            raise ValueError("actual tensor plan transaction changed")
    if len(tensors) != 56:
        raise ValueError("join requires both ranks all28 typed receipts")
    return {
        "two_rank_plan_projection_upload_join": True,
        "ranks": joined,
        "full_quality": None,
        "attention_consumption": None,
        "formal_result": False,
    }
