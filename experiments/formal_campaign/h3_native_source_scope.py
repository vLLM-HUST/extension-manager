"""Role-specific H3 preregistration; full context/runtime closure is retained.

API mappings do not execute worker KV/tensor/OP paths. Both workers retain the
entire original native source union. Host bootstrap contexts also retain that
union, and the authority independently keeps its complete runtime source refs.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

API_SOURCE_SUFFIXES = (
    "/vllm/plugins/evidence.py",
    "/vllm/plugins/native_block_table_observer.py",
    "/vllm/plugins/native_phase_drain.py",
    "/vllm/plugins/native_semantic_bootstrap.py",
    "/vllm/plugins/native_semantic_collector.py",
    "/vllm/v1/engine/input_processor.py",
    "/experiments/exposure_gate/native_semantic_collector.py",
    "/experiments/formal_campaign/h3_native_collector.py",
)
WORKER_RECEIVER_SUFFIXES = (
    "/experiments/native_attention_candidate/collector.py",
    "/experiments/native_attention_candidate/drain_collector.py",
    "/experiments/native_attention_candidate/operator_observer.py",
    "/experiments/native_attention_candidate/phase_drain.py",
    "/experiments/native_kv_tensor_candidate/artifact_transport.py",
    "/experiments/native_kv_tensor_candidate/runtime_contract.py",
    "/experiments/native_kv_tensor_candidate/witness.py",
)


def require(value, reason):
    if not value:
        raise ValueError(reason)


def scope_native_senders(senders, source_files):
    """Return detached senders and complete context union; never drop its rows."""
    require(
        [(s["process"]["role"], s["process"]["ordinal"]) for s in senders]
        == [("api-server", 0), ("worker", 0), ("worker", 1)],
        "exact API and both TP2 source slots required",
    )
    sources = {}
    for row in source_files:
        require(set(row) == {"path", "sha256"}, "exact native source ref required")
        path = Path(row["path"])
        require(
            path.is_absolute()
            and path.resolve() == path
            and not path.is_symlink()
            and path.is_file()
            and str(path) not in sources
            and re.fullmatch("[0-9a-f]{64}", row["sha256"])
            and hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"],
            "native source union is repeated, changed or noncanonical",
        )
        sources[str(path)] = dict(row)
    selected = {}
    for suffix in API_SOURCE_SUFFIXES + WORKER_RECEIVER_SUFFIXES:
        rows = [row for path, row in sources.items() if path.endswith(suffix)]
        require(
            len(rows) == 1, "native producer/receiver dependency missing: " + suffix
        )
        selected[suffix] = rows[0]
    # Preserve any independently declared sender-specific source beyond union.
    require(
        all(
            all(sources.get(row["path"]) == row for row in sender["source_files"])
            for sender in senders
        ),
        "original sender source escaped context union",
    )
    union = [sources[path] for path in sorted(sources)]
    result = copy.deepcopy(senders)
    result[0]["source_files"] = [dict(selected[s]) for s in API_SOURCE_SUFFIXES]
    for sender in result[1:]:
        sender["source_files"] = copy.deepcopy(union)
    return result, copy.deepcopy(union)


def checked_spec_bytes(spec):
    """Preflight the unchanged Host read_private 64KiB bound before any Popen."""
    raw = json.dumps(
        spec, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    require(
        0 < len(raw) <= 65536, "actual H3 native spec exceeds original Host64KiB bound"
    )
    return raw


def native_spec_size_upper_bound(spec):
    """Bound a fully declared spec before launch; this never authenticates PIDs.

    Callers must supply the real campaign IDs and source paths. Only fields
    inherently created at launch (kernel integers/UUID clocks) are widened. The
    returned sizing report is not usable as preregistration or native evidence.
    """
    planned = copy.deepcopy(spec)
    phases = planned["phases"]
    require(len(phases) == 60, "actual frozen60 request declarations required")
    ids = set()
    nonces = set()
    for phase in phases:
        rid = phase["client_request_id"]
        nonce = phase["challenge_nonce"]
        require(
            isinstance(rid, str)
            and rid
            and rid not in ids
            and phase["external_request_id"] == "cmpl-" + rid + "-0"
            and phase["expected_ranks"] == [0, 1]
            and isinstance(nonce, str)
            and re.fullmatch("[0-9a-f]{32}", nonce)
            and nonce not in nonces,
            "actual request IDs/nonces/native mapping differ",
        )
        ids.add(rid)
        nonces.add(nonce)
    require(
        set(planned["kv_requirements"]) == {p["phase_id"] for p in phases},
        "actual request requirements are incomplete",
    )
    union = {}
    for sender in planned["senders"]:
        for row in sender["source_files"]:
            require(
                row["path"] not in union or union[row["path"]] == row,
                "native declaration source conflicts",
            )
            union[row["path"]] = row
    scoped, _ = scope_native_senders(planned["senders"], list(union.values()))
    require(scoped == planned["senders"], "preregistration must use exact role scope")
    declared_bytes = len(checked_spec_bytes(planned))
    for sender in planned["senders"]:
        process = sender["process"]
        require(
            isinstance(process["host"], str) and process["host"],
            "actual launch machine name must be declared",
        )
        process.update(
            pid=4_194_304,
            session=4_194_304,
            start_ticks=18_446_744_073_709_551_615,
            process_epoch=18_446_744_073_709_551_615,
            start_identity="pid:4194304:start_ticks:18446744073709551615",
            boot_id="00000000-0000-0000-0000-000000000000",
        )
        sender["cmdline_sha256"] = "0" * 64
    planned["frozen_monotonic_ns"] = 18_446_744_073_709_551_615
    # Manager owns the actual UUID after launch. Source-bound launch intent must
    # use the native UUID width; no future UUID is guessed or admitted here.
    planned["native_launch_id"] = "00000000-0000-4000-8000-000000000000"
    raw = checked_spec_bytes(planned)
    return {
        "classification": "PRELAUNCH_DECLARATION_SIZE_UPPER_BOUND_ONLY",
        "formal_result": False,
        "native_or_kernel_authentication_performed": False,
        "actual_declared_spec_bytes": declared_bytes,
        "conservative_spec_bytes": len(raw),
        "original_Host_limit_bytes": 65536,
        "remaining_bytes": 65536 - len(raw),
        "actual_request_count": 60,
        "source_paths": len(union),
    }
