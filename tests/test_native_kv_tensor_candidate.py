"""Real CPU byte buffers/pinned source patch; never GPU or model evidence."""

from __future__ import annotations

import array
import base64
import copy
import hashlib
import json
import struct
import subprocess
from pathlib import Path

import pytest

from experiments.native_kv_tensor_candidate import witness

SOURCE = Path(witness.__file__).with_name("source")


def packet():
    # Actual binary16 encodings in owned CPU memory, with two independent planes.
    arrays = {
        kind: array.array(
            "H",
            [
                int.from_bytes(struct.pack("<e", float(i % 16) + delta), "little")
                for i in range(6 * 128 * 2)
            ],
        )
        for kind, delta in [("K", 0), ("V", 0.5)]
    }
    keep = [0, 127, 128]
    source_blocks = [0, 1]
    destination_blocks = [3]
    selected = {}
    exports = {}
    views = {}
    for kind, storage in arrays.items():
        raw = storage.tobytes()
        exports[kind] = {
            str(block): base64.b64encode(
                raw[block * 128 * 4 : (block + 1) * 128 * 4]
            ).decode()
            for block in source_blocks
        }
        selected[kind] = b"".join(raw[i * 4 : (i + 1) * 4] for i in keep)
        views[kind] = {
            "device": "cpu",
            "dtype": "torch.float16",
            "shape": [6, 128, 1, 2],
            "stride": [256, 2, 2, 1],
            "npu_format": None,
            "data_ptr": storage.buffer_info()[0],
            "storage_ptr": storage.buffer_info()[0],
            "storage_offset": 0,
        }
    encoded = {
        kind: base64.b64encode(value).decode() for kind, value in selected.items()
    }
    return {
        "schema": witness.SCHEMA,
        "classification": "CPU_SOURCE_CANDIDATE_ONLY",
        "formal_registration": False,
        "GPU_qualification": None,
        "attention_consumption": None,
        "full_model_quality": None,
        "binding": {
            "runtime_request_id": "CPU-frozen-candidate",
            "layer_name": "CPU-layer.0",
            "layer_index": 0,
            "expected_layer_indices": [0],
            "rank": 0,
            "tensor_parallel_size": 1,
            "physical_num_tokens": 129,
            "semantic_num_tokens": 129,
        },
        "source_blocks": source_blocks,
        "destination_blocks": destination_blocks,
        "keep_indices": keep,
        "source_slots": [0, 127, 128],
        "destination_slots": [384, 385, 386],
        "block_size": 128,
        "source_before_gather_ns": 1,
        "reference_after_gather_ns": 2,
        "write_completed_barrier_ns": 3,
        "destination_readback_completed_ns": 4,
        "cache_views": {
            kind: {"before": view, "after": copy.deepcopy(view)}
            for kind, view in views.items()
        },
        "exported_source_block_bytes": exports,
        "source_after_write_block_bytes": copy.deepcopy(exports),
        "selected_source_bytes": encoded,
        "gathered_workspace_bytes": copy.deepcopy(encoded),
        "destination_readback_bytes": copy.deepcopy(encoded),
        "selected_source_sha256": {
            kind: witness.digest(value) for kind, value in selected.items()
        },
        "destination_readback_sha256": {
            kind: witness.digest(value) for kind, value in selected.items()
        },
    }


def test_real_cpu_bytes_reference_workspace_destination_match_only_limited_scope():
    result = witness.verify(packet())
    assert result["selected_KV_bytes_match"] is True
    assert result["GPU_qualification"] is result["attention_consumption"] is None
    assert result["formal_result"] is False


@pytest.mark.parametrize(
    "change",
    [
        "same-wrong-copy",
        "destination-bit",
        "keep-index",
        "slot",
        "dtype",
        "page-stride",
        "pointer",
        "format",
        "workspace-reuse",
        "clock",
        "promote",
        "destination-alias",
        "source-alias",
        "allocation-bound",
        "rank",
        "layer",
        "source-mutated",
    ],
)
def test_byte_level_counterfactuals_fail_even_if_digests_recomputed(change):
    fact = packet()
    if change == "same-wrong-copy":
        wrong = bytes(12)
        for key in [
            "selected_source_bytes",
            "gathered_workspace_bytes",
            "destination_readback_bytes",
        ]:
            fact[key]["K"] = base64.b64encode(wrong).decode()
        for key in ["selected_source_sha256", "destination_readback_sha256"]:
            fact[key]["K"] = witness.digest(wrong)
    elif change == "destination-bit":
        value = bytearray(base64.b64decode(fact["destination_readback_bytes"]["V"]))
        value[0] ^= 1
        fact["destination_readback_bytes"]["V"] = base64.b64encode(value).decode()
        fact["destination_readback_sha256"]["V"] = witness.digest(value)
    elif change == "keep-index":
        fact["keep_indices"][-1] = 129
    elif change == "slot":
        fact["destination_slots"][-1] += 1
    elif change == "dtype":
        fact["cache_views"]["K"]["before"]["dtype"] = "torch.float32"
    elif change == "page-stride":
        for item in fact["cache_views"]["K"].values():
            item["stride"][0] = 1
    elif change == "pointer":
        fact["cache_views"]["K"]["after"]["data_ptr"] += 2
    elif change == "format":
        fact["cache_views"]["V"]["after"]["npu_format"] = 29
    elif change == "workspace-reuse":
        fact["gathered_workspace_bytes"]["K"] = fact["gathered_workspace_bytes"]["V"]
    elif change == "clock":
        fact["write_completed_barrier_ns"] = 1
    elif change == "destination-alias":
        fact["destination_blocks"] = [3, 3]
    elif change == "source-alias":
        fact["source_blocks"] = [0, 0]
    elif change == "allocation-bound":
        fact["destination_blocks"] = [6]
        fact["destination_slots"] = [768, 769, 770]
    elif change == "rank":
        fact["binding"]["rank"] = 1
    elif change == "layer":
        fact["binding"]["layer_index"] = 2
    elif change == "source-mutated":
        fact["source_after_write_block_bytes"]["K"]["0"] = base64.b64encode(
            bytes(512)
        ).decode()
    elif change == "promote":
        fact["GPU_qualification"] = True
    with pytest.raises(ValueError):
        witness.verify(fact)


def test_exact_source_patch_applies_and_declares_true_before_after_hooks(tmp_path):
    binding = json.loads((SOURCE / "source-binding.json").read_text())
    for item in binding["source_files"]:
        raw = (SOURCE / item["snapshot"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == item["preimage_sha256"]
        path = tmp_path / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    subprocess.run(
        ["git", "apply", str(SOURCE / "kv-selected-tensor-hook.patch")],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    for item in binding["source_files"]:
        raw = (tmp_path / item["path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == item["postimage_sha256"]
        compile(raw, item["path"], "exec")
    module = tmp_path / "src/vllm_ascend_kvcompress/native_tensor_witness.py"
    assert (
        hashlib.sha256(module.read_bytes()).hexdigest()
        == binding["candidate_module_sha256"]
    )
    assert module.read_bytes() == Path(witness.__file__).read_bytes()


def test_portable_attention_contacts_bind_exact_source_bytes(tmp_path):
    from experiments.native_kv_tensor_candidate.source_audit import verify_sources

    result = verify_sources()
    assert result["attention_hook_implemented"] is False
    assert result["attention_consumption"] is None
    assert len(result["source_contacts_verified"]) == 5
    import shutil

    shutil.copytree(SOURCE, tmp_path / "source")
    path = tmp_path / "source" / "ascend-attention_v1.py.snapshot"
    path.write_bytes(path.read_bytes() + b"\n# counterfactual\n")
    with pytest.raises(ValueError, match="source bytes differ"):
        verify_sources(tmp_path / "source")


def test_default_sink_neither_reads_tensors_nor_grants_ack(monkeypatch):
    monkeypatch.setattr(witness, "_sink", None)
    assert witness.enabled() is False
    assert witness.capture_before_actual_gather(None, None, None, None, None) is None
    assert witness.observe_actual_workspace(None, None, None) is None
    assert witness.observe_after_actual_write(None, None, None, None, None) is None


def test_candidate_registration_true_is_not_ack(monkeypatch):
    monkeypatch.setattr(witness, "_sink", None)
    witness.register_candidate_sink(lambda fact: True)
    assert witness.enabled() is True
    with pytest.raises(ValueError, match="single callable"):
        witness.register_candidate_sink(lambda fact: True)
    # Registration only enables local instrumentation, never a source/worker role.
    result = witness.verify(packet())
    assert result["formal_result"] is False
