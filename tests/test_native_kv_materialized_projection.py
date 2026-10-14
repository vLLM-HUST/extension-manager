"""Pinned actual Host methods with symbolic list CPU storage; no GPU result."""

import ast
import copy
import importlib
import sys
import time
from pathlib import Path
from types import SimpleNamespace as NS


class CPUArray:
    """Only indexed CPU storage; actual pinned Host methods perform mutations."""

    def __init__(self, rows, columns):
        self.rows = [[0] * columns for _ in range(rows)]

    def __getitem__(self, index):
        row, columns = index
        return self.rows[row][columns]

    def __setitem__(self, index, value):
        row, columns = index
        if isinstance(columns, slice) and not isinstance(value, list):
            value = [value] * len(self.rows[row][columns])
        self.rows[row][columns] = value


ROOT = Path(__file__).parents[1]
SOURCES = ROOT / "experiments/exposure_gate/native_kv_materialized_source"
HELPER = (
    ROOT / "experiments/exposure_gate/native_kv_materialized_projection_observer.py"
)
paths = {
    "HostInputBatch": SOURCES / "gpu_input_batch.py.snapshot",
    "HostBlockTable": SOURCES / "block_table.py.snapshot",
    "HostBaseRunner": SOURCES / "gpu_model_runner.py.snapshot",
    "NativeEmitter": SOURCES / "native_block_table_observer.py.snapshot",
}


def method(path, cls, name):
    tree = ast.parse(path.read_bytes())
    c = next(x for x in tree.body if isinstance(x, ast.ClassDef) and x.name == cls)
    return copy.deepcopy(
        next(x for x in c.body if isinstance(x, ast.FunctionDef) and x.name == name)
    )


def compile_functions(nodes, env):
    future = ast.ImportFrom(
        module="__future__", names=[ast.alias(name="annotations")], level=0
    )
    exec(
        compile(
            ast.fix_missing_locations(
                ast.Module(body=[future] + nodes, type_ignores=[])
            ),
            "<pinned-Host-AST>",
            "exec",
        ),
        env,
    )
    return env


class Batch(NS):
    @property
    def num_reqs(self):
        return len(self.req_id_to_index)


class Table(NS):
    pass


class Groups(NS):
    pass


blockenv = compile_functions(
    [
        method(paths["HostBlockTable"], "BlockTable", n)
        for n in ["append_row", "add_row", "get_numpy_array"]
    ],
    {},
)
for name in ["append_row", "add_row", "get_numpy_array"]:
    setattr(Table, name, blockenv[name])
groupenv = compile_functions(
    [method(paths["HostBlockTable"], "MultiGroupBlockTable", "add_row")], {}
)
Groups.add_row = groupenv["add_row"]
batchenv = compile_functions(
    [
        method(paths["HostInputBatch"], "InputBatch", n)
        for n in ["_register_add_request", "add_request"]
    ],
    {
        "SamplingType": NS(GREEDY="GREEDY"),
        "length_from_prompt_token_ids_or_embeds": lambda ids, embeds: len(ids),
    },
)
Batch._register_add_request = batchenv["_register_add_request"]
Batch.add_request = batchenv["add_request"]
runner_method = method(paths["HostBaseRunner"], "GPUModelRunner", "_update_states")
append = next(
    n
    for n in ast.walk(runner_method)
    if isinstance(n, ast.If) and ast.unparse(n.test) == "not resumed_from_preemption"
)
append = copy.deepcopy(append)


def test_actual_pinned_host_materializes_destination_and_append(tmp_path):
    temp = str(tmp_path)
    p = Path(temp) / "private_native_candidate"
    p.mkdir()
    (p / "__init__.py").write_text("")
    (p / "native_kv_materialized_projection_observer.py").write_bytes(
        HELPER.read_bytes()
    )
    (p / "native_kv_projection_observer.py").write_bytes(
        (
            ROOT / "experiments/exposure_gate/native_kv_projection_observer.py"
        ).read_bytes()
    )
    sys.path.insert(0, temp)
    m = importlib.import_module(
        "private_native_candidate.native_kv_materialized_projection_observer"
    )

    def fixture(row=0):
        table = Table(
            num_blocks_per_row=[0, 0],
            block_table=NS(np=CPUArray(2, 16)),
            block_size=128,
        )
        b = Batch(
            _req_ids=[] if row == 0 else [None, None],
            req_output_token_ids=[] if row == 0 else [None, None],
            spec_token_ids=[] if row == 0 else [[], []],
            req_id_to_index={},
            max_num_reqs=2,
            batch_update_builder=NS(
                pop_removed=lambda: None if row == 0 else row,
                batch_changed=False,
                added=[],
            ),
            req_prompt_embeds={},
            use_replayssm=False,
            block_table=Groups(block_tables=[table]),
            greedy_reqs=set(),
            random_reqs=set(),
            top_p_reqs=set(),
            top_k_reqs=set(),
            frequency_penalties_reqs=set(),
            presence_penalties_reqs=set(),
            repetition_penalties_reqs=set(),
            generators={},
            num_logprobs={},
            logprob_token_ids={},
            has_allowed_token_ids=set(),
            allowed_token_ids_mask_cpu_tensor=None,
            bad_words_token_ids={},
            vocab_size=100,
            lora_id_to_request_ids={},
            lora_id_to_lora_request={},
        )
        for name in [
            "num_prompt_tokens",
            "num_tokens_no_spec",
            "num_computed_tokens_cpu",
            "temperature_cpu",
            "top_p_cpu",
            "top_k_cpu",
            "frequency_penalties_cpu",
            "presence_penalties_cpu",
            "repetition_penalties_cpu",
            "num_accepted_tokens_cpu",
            "request_lora_mapping",
        ]:
            setattr(b, name, [0, 0])
        b.token_ids_cpu = CPUArray(2, 8)
        b.is_token_ids = CPUArray(2, 8)
        sampling = NS(
            sampling_type="GREEDY",
            top_p=1.0,
            top_k=-1,
            frequency_penalty=0.0,
            presence_penalty=0.0,
            repetition_penalty=1.0,
            logprobs=None,
            logprob_token_ids=None,
            allowed_token_ids=None,
            bad_words_token_ids=None,
        )
        request = NS(
            req_id="CPU-candidate-only",
            block_ids=(list(range(10, 18)),),
            prompt_token_ids=[1, 2],
            prompt_embeds=None,
            prompt_is_token_ids=None,
            output_token_ids=[3],
            num_tokens=3,
            num_computed_tokens=2,
            sampling_params=sampling,
            pooling_params=None,
            generator=None,
            lora_request=None,
        )
        provider = NS(
            runner=NS(requests={request.req_id: request}, input_batch=b),
            attention_group_index=0,
            active={request.req_id: NS(semantic_anchor=1201, physical_anchor=1024)},
            runtime_spec=NS(compression_threshold_tokens=1152),
        )
        pending = NS(
            block_ids=tuple(range(10, 18)), semantic_anchor=1201, physical_anchor=1024
        )
        scheduler = NS(
            num_scheduled_tokens={request.req_id: 1},
            scheduled_cached_reqs=NS(req_ids=[request.req_id], new_block_ids=[([19],)]),
        )
        marker = m.capture_marker(provider, scheduler, request.req_id, pending)
        return provider, scheduler, request, marker

    def restore(provider, scheduler, request):
        env = {
            "resumed_from_preemption": False,
            "new_block_ids": scheduler.scheduled_cached_reqs.new_block_ids[0],
            "req_state": request,
            "req_index": None,
        }
        exec(
            compile(
                ast.Module(body=[append], type_ignores=[]),
                "<pinned-Host-1429-append>",
                "exec",
            ),
            env,
        )
        provider.runner.input_batch.add_request(request)

    def fact(provider, scheduler, request, marker):
        return m.projection_fact(
            provider,
            scheduler,
            request.req_id,
            marker,
            {"monotonic_ns": time.monotonic_ns()},
        )

    results = []
    for row in [0, 1]:
        a, b, c, d = fixture(row)
        try:
            fact(a, b, c, d)
            raise AssertionError("missing CPU row accepted")
        except ValueError:
            pass
        restore(a, b, c)
        f = fact(a, b, c, d)
        assert (
            f["host_cpu_block_ids"] == list(range(10, 18)) + [19]
            and f["metadata_row"] == row
        )
        results.append(
            {"case": f"actual-Host-add_request-dest8-suffix19-row{row}", "passed": True}
        )
    for case in ["wrong-table", "wrong-scheduled-suffix", "wrong-row"]:
        a, b, c, d = fixture()
        restore(a, b, c)
        if case == "wrong-table":
            a.runner.input_batch.block_table.block_tables[0].block_table.np[0, 0] = 99
        elif case == "wrong-scheduled-suffix":
            c.block_ids[0][-1] = 20
            a.runner.input_batch.block_table.add_row(c.block_ids, 0)
        else:
            a.runner.input_batch.req_id_to_index[c.req_id] = 1
        try:
            fact(a, b, c, d)
            raise AssertionError(case + " accepted")
        except ValueError:
            results.append({"case": case, "rejected": True})
    emitter = next(
        x
        for x in ast.parse(paths["NativeEmitter"].read_bytes()).body
        if isinstance(x, ast.FunctionDef) and x.name == "emit_native_fact"
    )

    def reject_ACK(value):
        raise RuntimeError("deliberate candidate ACK failure")

    env = compile_functions([copy.deepcopy(emitter)], {"_observer": reject_ACK})
    a, b, c, d = fixture()
    restore(a, b, c)
    try:
        env["emit_native_fact"](lambda: fact(a, b, c, d))
        raise AssertionError("ACK failure swallowed")
    except RuntimeError as e:
        assert str(e) == "deliberate candidate ACK failure"
        results.append(
            {"case": "actual-source-public-emitter-ACK-failure", "rejected": True}
        )

    assert len(results) == 6


def test_exact_provider_patch_defers_until_real_row_and_retains_failed_ack(
    tmp_path, monkeypatch
):
    import hashlib
    import json
    import subprocess
    import types

    import pytest
    from test_native_kv_projection_observer import provider_fixture

    from experiments.exposure_gate import (
        native_kv_materialized_projection_observer as m,
    )

    manifest = json.loads((SOURCES / "source-binding.json").read_text())
    target = tmp_path / "src/vllm_ascend_kvcompress/provider.py"
    target.parent.mkdir(parents=True)
    raw = (SOURCES / "provider-d30.py.snapshot").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest["provider_preimage_sha256"]
    target.write_bytes(raw)
    subprocess.run(
        ["git", "apply", str(SOURCES / "kvcompress-materialized-projection.patch")],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    raw = target.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest["provider_postimage_sha256"]
    nodes = [
        n
        for n in ast.walk(ast.parse(raw))
        if isinstance(n, ast.FunctionDef)
        and n.name in {"before_update_states", "after_update_states"}
    ]
    env = compile_functions(
        nodes,
        {
            "ActiveCompression": lambda a, b, c: NS(
                semantic_anchor=a, physical_anchor=b
            ),
            "logger": NS(info=lambda *args: None),
        },
    )
    hook = types.ModuleType("vllm.plugins.native_kv_materialized_projection_observer")
    hook.capture_marker = m.capture_marker
    calls = []
    hook.observe_materialized_projection = lambda *args: calls.append(args)
    monkeypatch.setitem(sys.modules, hook.__name__, hook)
    provider, scheduled, pending = provider_fixture()
    provider._native_projection_markers = {}
    provider._sync_request_offset_rows = lambda: None
    scheduled.scheduled_cached_reqs.req_ids = ["native-r"]
    scheduled.scheduled_cached_reqs.new_block_ids = [([19],)]
    provider.runner.input_batch.req_id_to_index.clear()
    env["before_update_states"](provider, scheduled)
    assert not calls and "native-r" in provider._native_projection_markers
    marker = provider._native_projection_markers["native-r"]
    with pytest.raises(ValueError, match="not materialized"):
        m.projection_fact(
            provider,
            scheduled,
            "native-r",
            marker,
            {"monotonic_ns": time.monotonic_ns()},
        )

    def reject(*args):
        raise RuntimeError("durable source ACK absent")

    hook.observe_materialized_projection = reject
    with pytest.raises(RuntimeError, match="ACK absent"):
        env["after_update_states"](provider, scheduled)
    assert provider._native_projection_markers["native-r"] is marker
    hook.observe_materialized_projection = lambda *args: calls.append(args)
    env["after_update_states"](provider, scheduled)
    assert len(calls) == 1 and not provider._native_projection_markers


def test_materialized_effect_clock_must_follow_actual_mapping():
    import pytest
    from test_native_semantic_collector import projection

    from experiments.exposure_gate import native_semantic_collector as c
    from experiments.native_challenge_candidate.kv_request_runner import REQUIREMENTS

    fact = projection()
    fact.update(
        destination_block_ids=list(range(10, 18)),
        semantic_anchor=1201,
        physical_anchor=1024,
        compression_threshold_tokens=1152,
    )
    fact.update(
        schema=c.PROJECTION_V2,
        scheduled_appended_block_ids=[19],
        metadata_effect_monotonic_ns=90,
        host_cpu_block_ids=fact["destination_block_ids"] + [19],
        host_mapping="identity-host-block-id-projection-with-scheduled-append",
        monotonic_ns=110,
        process={"role": "worker", "ordinal": 0},
    )
    transaction = {
        k: fact[k]
        for k in [
            "runtime_request_id",
            "attention_group",
            "semantic_anchor",
            "physical_anchor",
            "destination_block_ids",
            "host_cpu_block_ids",
            "allocation_block_size",
            "compression_threshold_tokens",
            "scheduled_appended_block_ids",
            "metadata_effect_monotonic_ns",
        ]
    }
    fact["transaction_id"] = c.sha(c.canonical(transaction))
    phase = {"phase_id": "p", "external_request_id": "e"}
    spec = {
        "schema": c.KV_SPEC_V2,
        "phases": [phase],
        "native_plan_id": fact["plan_id"],
        "native_launch_id": fact["launch_id"],
        "frozen_monotonic_ns": 1,
        "max_event_age_ns": 1000,
        "kv_requirements": {"p": dict(REQUIREMENTS)},
    }
    kwargs = dict(
        accepted_monotonic_ns=120,
        mappings={fact["runtime_request_id"]: phase},
        mapping_stamps={fact["runtime_request_id"]: 100},
        upload_stamps={},
        upload_counts={},
    )
    sender = {"process": fact["process"]}
    with pytest.raises(ValueError, match="effect/row chronology"):
        c.native_fact_predicate(c.canonical(fact), sender, spec, **kwargs)
    fact["metadata_effect_monotonic_ns"] = 100
    transaction["metadata_effect_monotonic_ns"] = 100
    fact["transaction_id"] = c.sha(c.canonical(transaction))
    assert c.native_fact_predicate(c.canonical(fact), sender, spec, **kwargs)
    spec["schema"] = c.KV_SPEC
    with pytest.raises(ValueError, match="opt-in scope"):
        c.native_fact_predicate(c.canonical(fact), sender, spec, **kwargs)
