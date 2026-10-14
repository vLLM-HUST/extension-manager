"""Contract rejection tests are CPU; no synthetic metadata becomes NPU evidence."""

from __future__ import annotations

import copy
import os

import pytest
from test_native_kv_tensor_artifact import fact

from experiments.exposure_gate import native_semantic_collector as native
from experiments.native_kv_tensor_candidate import artifact_transport as transport
from experiments.native_kv_tensor_candidate import runtime_contract


def process():
    return native.identity(os.getpid()) | dict(
        role="worker",
        ordinal=0,
        assignment_source="host",
        process_epoch=1,
        host="CPU_CONTRACT_TEST_ONLY",
    )


def test_cpu_readback_cannot_be_reclassified_as_actual_runtime():
    with pytest.raises(ValueError, match="rejects CPU"):
        runtime_contract.from_actual_native_readback(fact(0), process())
    assert fact(0)["classification"] == "CPU_SOURCE_CANDIDATE_ONLY"


@pytest.mark.parametrize(
    "field,value",
    [
        ("role", "api-server"),
        ("assignment_source", "owner"),
        ("ordinal", 1),
        ("pid", False),
        ("start_ticks", 0),
    ],
)
def test_runtime_source_rejects_missing_actual_worker_identity(field, value):
    original = fact(0)
    # Schema-only NPU metadata here is not a hardware result; it allows this
    # negative to reach the identity gate instead of the CPU-device rejection.
    for view in original["cache_views"].values():
        for stage in view.values():
            stage["device"], stage["npu_format"] = "npu:3", 2
    peer = process() | {field: value}
    with pytest.raises(ValueError, match="worker identity"):
        runtime_contract.from_actual_native_readback(original, peer)


def test_runtime_contract_keeps_quality_unknown_for_schema_only_example():
    example = fact(0)
    for view in example["cache_views"].values():
        for stage in view.values():
            stage["device"], stage["npu_format"] = "npu:3", 2
    encoded = runtime_contract.from_actual_native_readback(example, process())
    result = runtime_contract.verify(encoded, process())
    assert result["classification"] == "REAL_RUNTIME_UNQUALIFIED"
    assert (
        result["GPU_qualification"]
        is result["attention_consumption"]
        is result["full_model_quality"]
        is None
    )
    assert result["formal_result"] is False
    # The unchanged original CPU schema is not relabelled or accepted by runtime.
    assert example["classification"] == "CPU_SOURCE_CANDIDATE_ONLY"
    with pytest.raises(ValueError, match="schema/source role"):
        runtime_contract.verify(example, process())
    promoted = copy.deepcopy(encoded)
    promoted["GPU_qualification"] = True
    with pytest.raises(ValueError):
        runtime_contract.verify(promoted, process())


def test_cpu_policy_cannot_accept_runtime_envelope():
    payload = fact(0)
    peer = process()
    envelope = dict(
        schema=transport.RUNTIME_ENVELOPE,
        process=peer,
        plan_id="p",
        launch_id="l",
        monotonic_ns=100,
        runtime_request_id="CPU-runtime",
        transaction_id=transport.transaction(payload),
        transport_policy_sha256="0" * 64,
        artifact=dict(
            basename="0" * 64 + ".json",
            device=1,
            inode=1,
            size=1,
            sha256="0" * 64,
            mtime_ns=1,
            ctime_ns=1,
        ),
    )
    with pytest.raises(ValueError, match="envelope fields"):
        transport.tensor_predicate(
            payload,
            envelope,
            dict(schema=transport.POLICY),
            dict(process=peer),
            {},
            {},
            101,
            {},
        )


def test_runtime_policy_cannot_accept_cpu_selected_bytes():
    with pytest.raises(ValueError, match="schema/source role"):
        transport.tensor_predicate(
            fact(0),
            {},
            dict(schema=transport.RUNTIME_POLICY),
            dict(process=process()),
            {},
            {},
            101,
            {},
        )


def test_genuine_wheel_source_audit_rejects_substituted_python_bytes(tmp_path):
    import zipfile

    from experiments.native_kv_tensor_candidate.build_handoff import audit_wheel

    source = tmp_path / "source"
    path = source / "vllm/plugins/native_tensor_runtime_contract.py"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"native_contract = True\n")
    wheel = tmp_path / "CPU-audit-only.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "vllm/plugins/native_tensor_runtime_contract.py", path.read_bytes()
        )
    assert audit_wheel(source, wheel)["packaged_python_count"] == 1
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "vllm/plugins/native_tensor_runtime_contract.py",
            b"native_contract = False\n",
        )
    with pytest.raises(ValueError, match="source bytes differ"):
        audit_wheel(source, wheel)


def test_npu_metadata_cannot_silently_use_cpu_source_publication_contract():
    source = fact(0)
    for view in source["cache_views"].values():
        for stage in view.values():
            stage["device"], stage["npu_format"] = "npu:3", 2
    with pytest.raises(ValueError, match="CPU contract cannot publish"):
        transport.verify_cpu_source(source)
