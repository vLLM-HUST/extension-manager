from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = (
    Path(__file__).parents[1]
    / "experiments/native_upload_candidate/native_block_table_observer.py"
)


@pytest.fixture
def observer():
    spec = importlib.util.spec_from_file_location("native_upload_test", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rig(monkeypatch, observer, *, same=True, device_type="npu"):
    calls, events = [], []

    class Tensor:
        device = SimpleNamespace(type=device_type)
        shape = (1, 2)

        def __getitem__(self, key):
            return self

        def to(self, *, device, non_blocking):
            assert calls == ["barrier"] and device == "cpu" and non_blocking is False
            calls.append("readback")
            return SimpleNamespace(tolist=lambda: [4, 5] if same else [8, 9])

    class CPU:
        def __getitem__(self, key):
            return SimpleNamespace(tolist=lambda: [4, 5])

    tensor = Tensor()
    table = SimpleNamespace(
        block_table=SimpleNamespace(gpu=tensor, np=CPU()), num_blocks_per_row=[2]
    )
    batch = SimpleNamespace(
        req_ids=["native-randomized-id"],
        num_reqs=1,
        block_table=SimpleNamespace(block_tables=[table]),
    )
    monkeypatch.setitem(
        sys.modules,
        "torch",
        SimpleNamespace(
            npu=SimpleNamespace(
                current_stream=lambda device: SimpleNamespace(
                    synchronize=lambda: calls.append("barrier")
                )
            )
        ),
    )
    monkeypatch.setattr(
        observer,
        "_scope",
        lambda role: {
            "process": {
                "role": role,
                "assignment_source": "host",
                "pid": 12,
                "start_identity": "pid:12:start_ticks:30",
                "process_epoch": 42,
            },
            "launch_id": "launch",
            "plan_id": "plan",
            "monotonic_ns": 1,
        },
    )
    observer.register_observer(events.append)
    return (
        SimpleNamespace(input_batch=batch),
        SimpleNamespace(num_scheduled_tokens={"native-randomized-id": 1}),
        calls,
        events,
    )


def test_cpu_contract_requires_barrier_and_actual_readback(monkeypatch, observer):
    runner, step, calls, events = rig(monkeypatch, observer)
    observer.observe_block_table_upload(runner, step)
    assert calls == ["barrier", "readback"]
    assert events[0]["runtime_request_id"] == "native-randomized-id"
    assert events[0]["uploaded_rows"] == [{"group": 0, "row": 0, "blocks": [4, 5]}]
    assert events[0]["kv_tensor_equivalence"] is None
    assert events[0]["attention_consumed_observed_tensor"] is None
    assert events[0]["full_generation_quality"] is None


def test_cpu_projection_cannot_replace_device_readback(monkeypatch, observer):
    runner, step, _, events = rig(monkeypatch, observer, same=False)
    with pytest.raises(RuntimeError, match="prefix differs"):
        observer.observe_block_table_upload(runner, step)
    assert events == []


def test_cpu_tensor_cannot_claim_native_npu_observation(monkeypatch, observer):
    runner, step, calls, events = rig(monkeypatch, observer, device_type="cpu")
    with pytest.raises(RuntimeError, match="NPU block tables required"):
        observer.observe_block_table_upload(runner, step)
    assert calls == [] and events == []


def test_unregistered_hook_does_not_synchronize(observer):
    observer.observe_block_table_upload(None, None)
    observer.observe_request_id_mapping(None)


def test_native_mapping_uses_both_exact_ids(monkeypatch, observer):
    events = []
    monkeypatch.setattr(observer, "_scope", lambda role: {"role": role})
    observer.register_observer(events.append)
    observer.observe_request_id_mapping(
        SimpleNamespace(
            external_req_id="chatcmpl-authority-request",
            request_id="native-real-suffix",
        )
    )
    assert events[0]["external_request_id"] == "chatcmpl-authority-request"
    assert events[0]["runtime_request_id"] == "native-real-suffix"
    assert events[0]["role"] == "api-server"
    with pytest.raises(RuntimeError, match="already registered"):
        observer.register_observer(events.append)
