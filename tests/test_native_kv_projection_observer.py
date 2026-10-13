"""Actual pinned after-mutation hook executed on CPU objects, never GPU proof."""

import ast
import hashlib
import json
import subprocess
import sys
import types
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from experiments.exposure_gate.native_kv_projection_observer import projection_fact

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "experiments/exposure_gate/native_kv_source"


def provider_fixture():
    class CPUArrayFixture:
        def __init__(self):
            self.rows = [[0] * 8]

        def __getitem__(self, index):
            row, columns = index
            return self.rows[row][columns]

        def __setitem__(self, index, value):
            row, columns = index
            self.rows[row][columns] = value

    table = NS(block_size=128, num_blocks_per_row=[0], data=CPUArrayFixture())
    table.get_numpy_array = lambda: table.data

    def add_row(groups, row):
        table.data[row, : len(groups[0])] = groups[0]
        table.num_blocks_per_row[row] = len(groups[0])

    request = NS(block_ids=([1, 2, 3],))
    batch = NS(
        req_id_to_index={"native-r": 0},
        block_table=NS(block_tables=[table], add_row=add_row),
    )
    pending = NS(
        block_ids=(10, 11),
        semantic_anchor=384,
        physical_anchor=256,
        per_layer_physical_num_tokens=None,
    )
    provider = NS(
        runner=NS(requests={"native-r": request}, input_batch=batch),
        attention_group_index=0,
        runtime_spec=NS(compression_threshold_tokens=384),
        active={},
        pending={"native-r": pending},
        query_window_tokens=0,
    )
    scheduled = NS(
        finished_req_ids=[],
        preempted_req_ids=[],
        scheduled_cached_reqs=NS(resumed_req_ids=[]),
        num_scheduled_tokens={"native-r": 1},
    )
    return provider, scheduled, pending


def apply_patch(tmp_path, name, target, preimage):
    path = tmp_path / target
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((SOURCES / preimage).read_bytes())
    subprocess.run(
        ["git", "apply", str(SOURCES / name)],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    return path.read_bytes()


def test_pinned_after_effect_source_patch_reads_actual_objects(tmp_path, monkeypatch):
    manifest = json.loads((SOURCES / "source-binding.json").read_text())
    raw = apply_patch(
        tmp_path,
        "kvcompress-native-projection.patch",
        "src/vllm_ascend_kvcompress/provider.py",
        "provider-00cc.py.snapshot",
    )
    assert hashlib.sha256(raw).hexdigest() == manifest["provider_postimage_sha256"]
    parsed = ast.parse(raw)
    method = next(
        n
        for n in ast.walk(parsed)
        if isinstance(n, ast.FunctionDef) and n.name == "before_update_states"
    )
    module = ast.Module(body=[method], type_ignores=[])
    recorded = []
    scope = dict(
        process={"role": "worker", "ordinal": 0},
        plan_id="cpu-only",
        launch_id="cpu-only",
        monotonic_ns=1,
    )
    hook = types.ModuleType("vllm.plugins.native_kv_projection_observer")
    hook.observe_kv_projection = lambda p, s, r, pending: recorded.append(
        projection_fact(p, s, r, pending, scope)
    )
    monkeypatch.setitem(sys.modules, hook.__name__, hook)
    namespace = {
        "Any": object,
        "ActiveCompression": lambda a, b, c: NS(semantic_anchor=a, physical_anchor=b),
        "logger": NS(info=lambda *args: None),
    }
    exec(compile(module, "actual-patched-provider-method", "exec"), namespace)
    provider, scheduled, pending = provider_fixture()
    with pytest.raises(KeyError):
        projection_fact(provider, scheduled, "native-r", pending, scope)
    namespace["before_update_states"](provider, scheduled)
    assert len(recorded) == 1
    assert recorded[0]["host_cpu_block_ids"] == [10, 11]
    assert recorded[0]["physical_anchor"] == 256
    assert not provider.pending

    # Source-owned callback failure propagates; no log/pop falsely ACKs it.
    provider, scheduled, pending = provider_fixture()

    def fail(*args):
        raise RuntimeError("authenticated sink did not ACK")

    hook.observe_kv_projection = fail
    with pytest.raises(RuntimeError, match="did not ACK"):
        namespace["before_update_states"](provider, scheduled)
    assert "native-r" in provider.pending


def test_public_emit_patch_is_lazy_and_propagates_failure(tmp_path):
    manifest = json.loads((SOURCES / "source-binding.json").read_text())
    raw = apply_patch(
        tmp_path,
        "native-observer-projection.patch",
        "vllm/plugins/native_block_table_observer.py",
        "native-observer-34f.py.snapshot",
    )
    assert (
        hashlib.sha256(raw).hexdigest() == manifest["native_observer_postimage_sha256"]
    )
    method = next(
        n
        for n in ast.walk(ast.parse(raw))
        if isinstance(n, ast.FunctionDef) and n.name == "emit_native_fact"
    )
    calls = []
    namespace = {"_observer": lambda fact: calls.append(fact)}
    exec(
        compile(ast.Module(body=[method], type_ignores=[]), "public-emit", "exec"),
        namespace,
    )
    namespace["emit_native_fact"](lambda: {"actual": "cpu-only"})
    assert calls == [{"actual": "cpu-only"}]

    def reject(fact):
        raise RuntimeError("reject")

    namespace["_observer"] = reject
    with pytest.raises(RuntimeError, match="reject"):
        namespace["emit_native_fact"](lambda: {})


def test_cpu_projection_rejects_actual_mismatch():
    provider, scheduled, pending = provider_fixture()
    provider.active["native-r"] = NS(semantic_anchor=384, physical_anchor=256)
    provider.runner.requests["native-r"].block_ids = ([10, 11],)
    provider.runner.input_batch.block_table.add_row(([12, 13],), 0)
    with pytest.raises(ValueError, match="inconsistent"):
        projection_fact(provider, scheduled, "native-r", pending, {})
