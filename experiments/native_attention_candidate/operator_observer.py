"""Opt-in source contacts; callback return is not attention/formal qualification."""

from __future__ import annotations

import hashlib
import json
import math
import time

SCHEMA = "ecpa-native-cached-attention-operator-source-candidate/v1"
_publisher = None
_scope = None
_current_stream = None
_get_format = None
_read_prefix = None
_materialized = {}
_metadata = {}
_observed = set()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def enabled():
    return _publisher is not None


def register_source_candidate(
    publisher, *, scope, current_stream, get_format, read_prefix=None
):
    """Explicit new source-only opt-in. No existing source producer is upgraded."""
    global _publisher, _scope, _current_stream, _get_format, _read_prefix
    require(not enabled(), "attention source callback already registered")
    require(
        all(callable(f) for f in (publisher, scope, current_stream, get_format)),
        "attention source callbacks missing",
    )
    _publisher, _scope = publisher, scope
    _current_stream, _get_format = current_stream, get_format
    _read_prefix = read_prefix or read_destination_prefix


def remember_acknowledged_materialization(fact, ack):
    """Called ONLY after actual artifact publish validates its Unix source ACK."""
    if not enabled():
        return
    scope = _scope()
    require(
        fact["native_producer"] == scope["process"], "materialization worker changed"
    )
    require(
        fact["classification"] == "REAL_RUNTIME_UNQUALIFIED",
        "source candidate requires actual native runtime materialization",
    )
    require(
        ack["schema"] == "ecpa-native-semantic-collector-ack/v1"
        and ack["formal_producer_registration"] is False
        and ack["ack_sha256"]
        == sha(canonical({k: v for k, v in ack.items() if k != "ack_sha256"})),
        "actual source ACK is absent or corrupt",
    )
    require(ack["phase"]["expected_ranks"] == [0, 1], "source ACK rank scope changed")
    binding = fact["binding"]
    key = (binding["runtime_request_id"], binding["layer_name"])
    require(len(_materialized) < 64, "bounded fresh materialization scope exceeded")
    require(key not in _materialized, "ambiguous materialization for request/layer")
    # Actual ACK raw digest binds the transport envelope, whereas this digest
    # binds its privately archived typed payload; they are intentionally distinct.
    _materialized[key] = {
        "fact": fact,
        "fact_sha256": sha(canonical(fact)),
        "ack": ack,
        "registered_monotonic_ns": time.monotonic_ns(),
    }


def bind_actual_input_batch(runner, metadata, *, eager):
    """Source-owned IDs and row mapping after real attention metadata construction."""
    if not enabled():
        return
    _metadata.clear()
    # These are explicit unsupported paths, not inferred successful consumption.
    if not eager or isinstance(metadata, list):
        return
    require(isinstance(metadata, dict), "per-layer metadata mapping unsupported")
    req_ids = runner.input_batch.req_ids[: runner.input_batch.num_reqs]
    if len(req_ids) != 1:
        return
    request_id = req_ids[0]
    require(
        runner.input_batch.req_id_to_index[request_id] == 0,
        "actual InputBatch request row differs",
    )
    require(runner.requests[request_id] is not None, "actual runner request absent")
    for layer_name, value in metadata.items():
        if (request_id, layer_name) not in _materialized:
            continue
        state = getattr(getattr(value, "attn_state", None), "name", None)
        if state != "DecodeOnly":
            continue
        require(
            value.num_prefills == 0 and value.num_decodes == 1,
            "cached decode metadata includes another request",
        )
        require(value.actual_seq_lengths_q == [1], "decode is not one actual token")
        tables = runner.input_batch.block_table.block_tables
        require(len(tables) == 1, "only actual single attention group supported")
        table = tables[0]
        width = int(table.num_blocks_per_row[0])
        require(0 < width <= table.block_table.gpu.shape[1], "actual row width invalid")
        cpu_blocks = table.block_table.np[0, :width].tolist()
        require(
            cpu_blocks == list(runner.requests[request_id].block_ids[0]),
            "actual CPU row and request metadata differ",
        )
        lengths = value.seq_lens.detach().cpu().tolist()
        require(
            lengths == list(value.seq_lens_list) and len(lengths) == 1,
            "actual native decode sequence metadata fields diverged",
        )
        _metadata[id(value)] = {
            "object": value,
            "runtime_request_id": request_id,
            "layer_name": layer_name,
            "metadata_row": 0,
            "actual_cpu_block_ids": cpu_blocks,
            "metadata_seq_lengths_kv": lengths,
            "metadata_actual_seq_lengths_q": list(value.actual_seq_lengths_q),
            "bound_monotonic_ns": time.monotonic_ns(),
        }


def cache_view(tensor):
    return {
        "device": str(tensor.device),
        "dtype": str(tensor.dtype),
        "shape": list(tensor.shape),
        "stride": list(tensor.stride()),
        "data_ptr": tensor.data_ptr(),
        "storage_ptr": tensor.untyped_storage().data_ptr(),
        "storage_offset": tensor.storage_offset(),
        "npu_format": _get_format(tensor)
        if str(tensor.device).startswith("npu:")
        else None,
    }


def read_destination_prefix(cache, fact, kind):
    """Actual logical block exports at OP entry; independent of KV gather helper."""
    import torch

    reference_shape = fact["cache_views"][kind]["after"]["shape"]
    reference = fact["cache_views"][kind]["after"]
    actual_shape, actual_stride = list(cache.shape), list(cache.stride())
    require(
        (actual_shape == reference_shape and actual_stride == reference["stride"])
        or (
            actual_shape
            == [
                reference_shape[0],
                reference_shape[1],
                reference_shape[2] * reference_shape[3],
            ]
            and actual_stride == [reference["stride"][0], reference["stride"][1], 1]
        ),
        "native cache layout is not actual typed 4D or exact flatten",
    )
    require(
        str(cache.dtype) in {"torch.float16", "torch.bfloat16"}
        and str(cache.dtype) == reference["dtype"],
        "native prefix reader supports actual binary16 cache dtype only",
    )
    logical = cache.view(reference_shape)
    remaining = len(fact["keep_indices"])
    block_size = fact["block_size"]
    digest = hashlib.sha256()
    for block in fact["destination_blocks"]:
        if remaining <= 0:
            break
        count = min(remaining, block_size)
        # Copy the actual logical block through framework device-to-CPU. No
        # compression workspace or previous digest supplies these bytes.
        raw = logical[block].detach().to(device="cpu", non_blocking=False).contiguous()
        raw = raw.view(torch.uint8).numpy().tobytes()
        token_bytes = reference_shape[2] * reference_shape[3] * 2
        require(
            len(raw) == block_size * token_bytes, "native cache block extent differs"
        )
        digest.update(raw[: count * token_bytes])
        remaining -= count
    require(remaining == 0, "native destination prefix allocation incomplete")
    return digest.hexdigest()


def argument_descriptor(value):
    if hasattr(value, "data_ptr") and hasattr(value, "untyped_storage"):
        return {"kind": "tensor", "view": cache_view(value)}
    if value is None or type(value) in (str, bool, int):
        return {"kind": "scalar", "value": value}
    if type(value) is float and math.isfinite(value):
        return {"kind": "scalar", "value": value}
    if isinstance(value, (list, tuple)) and len(value) <= 4096:
        return {"kind": "sequence", "value": [argument_descriptor(x) for x in value]}
    raise ValueError("actual native argument type unsupported")


def verify_observation(value, materialization):
    """Pure bounded source predicate; cannot authenticate sender or prove quality."""
    require(
        value["schema"] == SCHEMA
        and value["classification"] == "REAL_RUNTIME_UNQUALIFIED"
        and value["formal_registration"] is False
        and all(
            value[k] is None
            for k in (
                "GPU_qualification",
                "attention_consumption",
                "full_model_quality",
            )
        ),
        "attention source candidate scope promoted",
    )
    require(
        value["operator"]
        in {
            "torch_npu._npu_paged_attention",
            "torch_npu.npu_fused_infer_attention_score",
        }
        and value["attn_state"] == "DecodeOnly"
        and value["execution_mode"] == "eager-single-request-cached-decode",
        "unsupported actual attention branch",
    )
    descriptors = value["native_argument_descriptors"]
    require(
        value["native_argument_descriptors_sha256"] == sha(canonical(descriptors)),
        "native argument descriptor bytes changed",
    )
    query = descriptors["query"]
    require(
        query["kind"] == "tensor"
        and query["view"]["device"]
        == materialization["cache_views"]["K"]["after"]["device"]
        and query["view"]["dtype"]
        == materialization["cache_views"]["K"]["after"]["dtype"],
        "native query is not actual matching-device tensor",
    )
    binding = materialization["binding"]
    require(
        value["runtime_request_id"] == binding["runtime_request_id"]
        and value["layer_name"] == binding["layer_name"]
        and value["layer_index"] == binding["layer_index"]
        and value["process"] == materialization["native_producer"],
        "attention request/actual layer/worker does not match materialization",
    )
    transaction = sha(
        canonical(
            {
                "runtime_request_id": binding["runtime_request_id"],
                "compression_plan": binding["compression_plan"],
            }
        )
    )
    require(
        value["materialization_transaction_id"] == transaction,
        "actual source compression plan transaction differs",
    )
    require(
        value["source_materialization_sha256"] == sha(canonical(materialization)),
        "attention reference is not actual archived materialization",
    )
    clocks = [
        materialization["destination_readback_completed_ns"],
        value["materialization_ack_registered_monotonic_ns"],
        value["metadata_bound_monotonic_ns"],
        value["native_entry_readback_started_ns"],
        value["native_entry_readback_completed_ns"],
        value["native_call_started_ns"],
        value["native_call_returned_ns"],
        value["native_stream_completed_ns"],
        value["monotonic_ns"],
    ]
    require(
        all(type(x) is int and x > 0 for x in clocks) and clocks == sorted(clocks),
        "actual native completion chronology differs",
    )
    require(
        type(value["stream"]["npu_stream"]) is int
        and value["stream"]["npu_stream"] >= 0
        and value["stream_before"] == value["stream_after"] == value["stream"],
        "native operation changed completion stream",
    )
    rows = value["native_arguments"]["block_table_rows"]
    seq = value["native_arguments"]["sequence_lengths"]
    require(
        isinstance(rows, list)
        and len(rows) == 1
        and all(type(x) is int and x >= 0 for x in rows[0])
        and len(rows[0]) <= 4096
        and isinstance(seq, list)
        and len(seq) == 1
        and type(seq[0]) is int
        and seq[0] >= len(materialization["keep_indices"]),
        "native block table or sequence extent is unsupported",
    )
    require(
        value["actual_cpu_block_ids"]
        and rows[0][: len(value["actual_cpu_block_ids"])]
        == value["actual_cpu_block_ids"],
        "native OP block table differs from source-owned actual InputBatch row",
    )
    require(
        seq == value["metadata_seq_lengths_kv"]
        and value["metadata_actual_seq_lengths_q"] == [1],
        "actual native sequence lengths differ from bound source metadata",
    )
    destinations = materialization["destination_blocks"]
    require(
        rows[0][: len(destinations)] == destinations,
        "actual native block table does not address materialized destinations",
    )
    require(
        len(value["actual_cpu_block_ids"]) * materialization["block_size"] >= seq[0],
        "native sequence extends beyond actual block table",
    )
    require(
        value["stream"]["device"]
        == materialization["cache_views"]["K"]["after"]["device"],
        "native completion stream is on another device",
    )
    ack = value["materialization_ack"]
    require(
        ack["schema"] == "ecpa-native-semantic-collector-ack/v1"
        and ack["formal_producer_registration"] is False
        and ack["ack_sha256"]
        == sha(canonical({k: v for k, v in ack.items() if k != "ack_sha256"})),
        "materialization acknowledgement provenance changed",
    )
    require(
        value["native_selected_destination_sha256"]
        == materialization["destination_readback_sha256"],
        "actual selected destination bytes changed before native OP entry",
    )
    for kind in ("K", "V"):
        native_name = (
            ("key_cache" if kind == "K" else "value_cache")
            if (value["operator"] == "torch_npu._npu_paged_attention")
            else ("key" if kind == "K" else "value")
        )
        require(
            descriptors[native_name]["kind"] == "tensor"
            and descriptors[native_name]["view"]
            == value["native_arguments"]["cache_views"][kind],
            "native actual argument and interpreted cache view differ",
        )
        actual = value["native_arguments"]["cache_views"][kind]
        ref = materialization["cache_views"][kind]["after"]
        require(
            set(actual)
            == {
                "device",
                "dtype",
                "shape",
                "stride",
                "data_ptr",
                "storage_ptr",
                "storage_offset",
                "npu_format",
            }
            and all(
                type(actual[k]) is int and actual[k] > 0
                for k in ("data_ptr", "storage_ptr")
            )
            and type(actual["storage_offset"]) is int
            and actual["storage_offset"] >= 0
            and type(actual["npu_format"]) is int
            and actual["npu_format"] >= 0,
            "native cache view fields/types unsupported",
        )
        require(
            actual["device"].startswith("npu:")
            and all(
                actual[k] == ref[k]
                for k in (
                    "device",
                    "dtype",
                    "storage_ptr",
                    "storage_offset",
                    "data_ptr",
                    "npu_format",
                )
            ),
            "native OP uses another cache allocation/view/format",
        )
        require(
            (actual["shape"] == ref["shape"] and actual["stride"] == ref["stride"])
            or (
                value["operator"] == "torch_npu.npu_fused_infer_attention_score"
                and actual["shape"]
                == [ref["shape"][0], ref["shape"][1], ref["shape"][2] * ref["shape"][3]]
                and actual["stride"] == [ref["stride"][0], ref["stride"][1], 1]
            ),
            "native OP view is not actual cache or supported exact flatten",
        )
    require(len(canonical(value)) <= 49152, "bounded native operator fact required")
    return {
        "source_argument_completion_relation": True,
        "formal_registration": False,
        "attention_consumption": None,
        "GPU_qualification": None,
        "full_model_quality": None,
    }


def observe_native_call(operator, native_call, arguments, *, metadata, layer_name):
    """Wrap actual final native call; default/unsupported paths produce no witness."""
    if not enabled() or id(metadata) not in _metadata:
        return native_call(**arguments)
    bound = _metadata[id(metadata)]
    require(
        bound["object"] is metadata and bound["layer_name"] == layer_name,
        "native metadata/layer source binding changed",
    )
    key_id = (bound["runtime_request_id"], layer_name)
    if key_id in _observed:
        return native_call(**arguments)
    registered = _materialized[key_id]
    fact = registered["fact"]
    require(
        registered["fact_sha256"] == sha(canonical(fact)),
        "registered materialization changed",
    )
    if operator == "torch_npu._npu_paged_attention":
        key, val = arguments["key_cache"], arguments["value_cache"]
        seq = arguments["context_lens"].detach().cpu().tolist()
    else:
        key, val = arguments["key"], arguments["value"]
        seq = list(arguments["actual_seq_lengths_kv"])
    table = arguments["block_table"].detach().cpu().tolist()
    entry_readback_started = time.monotonic_ns()
    entry_digests = {
        "K": _read_prefix(key, fact, "K"),
        "V": _read_prefix(val, fact, "V"),
    }
    entry_readback_completed = time.monotonic_ns()
    descriptors = {
        name: argument_descriptor(value) for name, value in arguments.items()
    }
    stream = _current_stream(key.device)
    stream_id = {"npu_stream": stream.npu_stream, "device": str(stream.device)}
    observed = {
        "schema": SCHEMA,
        "classification": "REAL_RUNTIME_UNQUALIFIED",
        "formal_registration": False,
        **_scope(),
        "operator": operator,
        "execution_mode": "eager-single-request-cached-decode",
        "attn_state": "DecodeOnly",
        "runtime_request_id": bound["runtime_request_id"],
        "layer_name": layer_name,
        "layer_index": fact["binding"]["layer_index"],
        "metadata_row": 0,
        "actual_cpu_block_ids": bound["actual_cpu_block_ids"],
        "metadata_seq_lengths_kv": bound["metadata_seq_lengths_kv"],
        "metadata_actual_seq_lengths_q": bound["metadata_actual_seq_lengths_q"],
        "source_materialization_sha256": registered["fact_sha256"],
        "materialization_transaction_id": sha(
            canonical(
                {
                    "runtime_request_id": bound["runtime_request_id"],
                    "compression_plan": fact["binding"]["compression_plan"],
                }
            )
        ),
        "materialization_ack": registered["ack"],
        "materialization_ack_registered_monotonic_ns": registered[
            "registered_monotonic_ns"
        ],
        "metadata_bound_monotonic_ns": bound["bound_monotonic_ns"],
        "native_selected_destination_sha256": entry_digests,
        "native_entry_readback_started_ns": entry_readback_started,
        "native_entry_readback_completed_ns": entry_readback_completed,
        "native_argument_descriptors": descriptors,
        "native_argument_descriptors_sha256": sha(canonical(descriptors)),
        "native_arguments": {
            "cache_views": {"K": cache_view(key), "V": cache_view(val)},
            "block_table_rows": table,
            "sequence_lengths": seq,
        },
        "stream": stream_id,
        "stream_before": stream_id,
        "native_call_started_ns": time.monotonic_ns(),
        "GPU_qualification": None,
        "attention_consumption": None,
        "full_model_quality": None,
    }
    result = native_call(**arguments)
    observed["native_call_returned_ns"] = time.monotonic_ns()
    stream.synchronize()
    observed["native_stream_completed_ns"] = time.monotonic_ns()
    after = _current_stream(key.device)
    observed["stream_after"] = {
        "npu_stream": after.npu_stream,
        "device": str(after.device),
    }
    observed["monotonic_ns"] = time.monotonic_ns()
    verify_observation(observed, fact)
    _publisher(observed)  # Failure propagates; no return is an authority ACK claim.
    _observed.add(key_id)
    return result
