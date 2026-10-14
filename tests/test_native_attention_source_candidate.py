"""CPU source/argument fixtures run pinned native-call bodies, never NPU evidence."""

from __future__ import annotations

import ast
import copy
import importlib
import sys
import time
import types
from types import SimpleNamespace as NS

import pytest
from test_native_kv_tensor_artifact import fact
from test_native_kv_tensor_runtime_contract import process

from experiments.native_attention_candidate import build_source_patch, operator_observer
from experiments.native_kv_tensor_candidate import runtime_contract


class Tensor:
    """Schema-only NPU view on CPU; no actual NPU allocation is asserted."""

    def __init__(self, values=None, view=None):
        self.values, self.view = values, view
        if view is None:
            shape = (
                [len(values), len(values[0])]
                if isinstance(values[0], list)
                else [len(values)]
            )
            view = dict(
                device="cpu",
                dtype="torch.int32",
                shape=shape,
                stride=[shape[-1], 1] if len(shape) == 2 else [1],
                data_ptr=1,
                storage_ptr=1,
                storage_offset=0,
                npu_format=None,
            )
            self.view = view
        if view is not None:
            self.device, self.dtype, self.shape = (
                view["device"],
                view["dtype"],
                view["shape"],
            )

    def stride(self):
        return self.view["stride"]

    def data_ptr(self):
        return self.view["data_ptr"]

    def untyped_storage(self):
        return NS(data_ptr=lambda: self.view["storage_ptr"])

    def storage_offset(self):
        return self.view["storage_offset"]

    def detach(self):
        return self

    def cpu(self):
        return self

    def tolist(self):
        return copy.deepcopy(self.values)


@pytest.fixture
def context(monkeypatch):
    observer = importlib.reload(operator_observer)
    materialization = fact(0)
    for view in materialization["cache_views"].values():
        for stage in view.values():
            stage["device"], stage["npu_format"] = "npu:0", 2
    peer = process()
    materialization = runtime_contract.from_actual_native_readback(
        materialization, peer
    )
    stamp = time.monotonic_ns()
    for key in (
        "source_before_gather_ns",
        "reference_after_gather_ns",
        "write_completed_barrier_ns",
        "destination_readback_completed_ns",
    ):
        materialization[key] = stamp
    ack = dict(
        schema="ecpa-native-semantic-collector-ack/v1",
        formal_producer_registration=False,
        phase=dict(expected_ranks=[0, 1]),
        sequence=4,
        event_sha256="0" * 64,
        raw_sha256="1" * 64,
    )
    ack["ack_sha256"] = observer.sha(observer.canonical(ack))
    events, native_calls, completions = [], [], []
    stream = NS(
        npu_stream=9, device="npu:0", synchronize=lambda: completions.append(True)
    )
    observer.register_source_candidate(
        events.append,
        scope=lambda: dict(process=peer, launch_id="CPU-launch", plan_id="CPU-plan"),
        current_stream=lambda device=None: stream,
        get_format=lambda t: t.view["npu_format"],
        read_prefix=lambda tensor, f, kind: f["destination_readback_sha256"][kind],
    )
    observer.remember_acknowledged_materialization(materialization, ack)
    runtime = materialization["binding"]["runtime_request_id"]
    layer = materialization["binding"]["layer_name"]
    destinations = materialization["destination_blocks"]
    cpu_blocks = destinations + [4]

    class Row:
        def __getitem__(self, key):
            return Tensor(cpu_blocks)

    table = NS(
        num_blocks_per_row=[len(cpu_blocks)],
        block_table=NS(gpu=NS(shape=[1, 32]), np=Row()),
    )
    runner = NS(
        input_batch=NS(
            req_ids=[runtime],
            num_reqs=1,
            req_id_to_index={runtime: 0},
            block_table=NS(block_tables=[table]),
        ),
        requests={runtime: NS(block_ids=[cpu_blocks])},
    )
    metadata = NS(
        attn_state=NS(name="DecodeOnly"),
        num_prefills=0,
        num_decodes=1,
        actual_seq_lengths_q=[1],
        block_tables=Tensor([cpu_blocks]),
        seq_lens=Tensor([4]),
        seq_lens_list=[4],
    )
    observer.bind_actual_input_batch(runner, {layer: metadata}, eager=True)
    tensors = {
        k: Tensor(view=materialization["cache_views"][k]["after"]) for k in ("K", "V")
    }

    query_view = dict(materialization["cache_views"]["K"]["after"])
    query_view.update(shape=[1, 14, 128], stride=[1792, 128, 1])
    query = Tensor(view=query_view)

    def native(**arguments):
        native_calls.append(arguments)
        return "CPU_NATIVE_SENTINEL"

    monkeypatch.setitem(sys.modules, "vllm", types.ModuleType("vllm"))
    monkeypatch.setitem(sys.modules, "vllm.plugins", types.ModuleType("vllm.plugins"))
    monkeypatch.setitem(
        sys.modules, "vllm.plugins.native_attention_operator_observer", observer
    )
    yield NS(
        observer=observer,
        fact=materialization,
        ack=ack,
        events=events,
        native=native,
        calls=native_calls,
        completions=completions,
        tensors=tensors,
        runner=runner,
        metadata=metadata,
        layer=layer,
        stream=stream,
        query=query,
    )
    importlib.reload(operator_observer)


def extract(source, function, owner=None):
    tree = ast.parse(source)
    nodes = (
        tree.body
        if owner is None
        else next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == owner
        ).body
    )
    node = next(
        node
        for node in nodes
        if isinstance(node, ast.FunctionDef) and node.name == function
    )
    node.decorator_list, node.returns = [], None
    for argument in node.args.args + node.args.kwonlyargs:
        argument.annotation = None
    return compile(
        ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
        "pinned-native-source",
        "exec",
    )


def pa(context):
    c = context
    _, patched = build_source_patch.patched()
    env = {
        "_EXTRA_CTX": NS(capturing=False),
        "torch_npu": NS(_npu_paged_attention=c.native),
    }
    exec(
        extract(
            patched["vllm_ascend/attention/attention_v1.py"],
            "forward_paged_attention",
            "AscendAttentionBackendImpl",
        ),
        env,
    )
    owner = NS(
        key_cache=c.tensors["K"],
        value_cache=c.tensors["V"],
        num_kv_heads=2,
        num_heads=14,
        scale=0.125,
        _layer_name=c.layer,
    )
    return env["forward_paged_attention"](owner, c.query, c.metadata, c.query)


def test_pinned_pa_final_native_call_and_same_stream_completion(context):
    assert pa(context) is context.query
    assert len(context.calls) == len(context.completions) == len(context.events) == 1
    observed = context.events[0]
    assert (
        observed["native_arguments"]["block_table_rows"]
        == context.metadata.block_tables.tolist()
    )
    assert context.observer.verify_observation(observed, context.fact)[
        "source_argument_completion_relation"
    ]
    assert observed["attention_consumption"] is None


def test_pinned_a2_fia_final_native_call(context):
    c = context
    _, patched = build_source_patch.patched()
    env = {
        "device_utils": NS(FIA_TND_LARGE_HEAD_FALLBACK_HEAD_SIZE=512),
        "torch_npu": NS(npu_fused_infer_attention_score=c.native),
    }
    exec(
        extract(
            patched["vllm_ascend/device/device_op.py"],
            "npu_fused_infer_attention_score",
            "BaseDeviceAdaptor",
        ),
        env,
    )
    assert (
        env["npu_fused_infer_attention_score"](
            None,
            query=c.query,
            key=c.tensors["K"],
            value=c.tensors["V"],
            attn_metadata=c.metadata,
            key_cache=c.tensors["K"],
            value_cache=c.tensors["V"],
            current_key=None,
            current_value=None,
            num_heads=14,
            num_key_value_heads=2,
            head_size=128,
            scale=0.125,
            is_prefill_no_cache=False,
            native_layer_name=c.layer,
            block_table=c.metadata.block_tables,
            actual_seq_lengths_kv=[4],
        )
        == "CPU_NATIVE_SENTINEL"
    )
    assert len(c.calls) == len(c.completions) == len(c.events) == 1
    assert "native_layer_name" not in c.calls[0]


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_cache",
        "wrong_stride",
        "wrong_row",
        "wrong_seq",
        "wrong_layer",
        "late_materialization",
        "different_stream",
        "promoted_quality",
        "changed_selected_bytes",
    ],
)
def test_pure_source_argument_counterexamples(context, mutation):
    pa(context)
    c = context
    observed = copy.deepcopy(c.events[0])
    if mutation == "wrong_cache":
        observed["native_arguments"]["cache_views"]["K"]["storage_ptr"] += 1
    elif mutation == "wrong_stride":
        observed["native_arguments"]["cache_views"]["K"]["stride"][0] += 1
    elif mutation == "wrong_row":
        observed["native_arguments"]["block_table_rows"][0][0] = 20
    elif mutation == "wrong_seq":
        observed["native_arguments"]["sequence_lengths"] = [100000]
    elif mutation == "wrong_layer":
        observed["layer_name"] = "another-layer"
    elif mutation == "late_materialization":
        observed["materialization_ack_registered_monotonic_ns"] = (
            observed["native_call_started_ns"] + 1
        )
    elif mutation == "different_stream":
        observed["stream_after"]["npu_stream"] += 1
    elif mutation == "changed_selected_bytes":
        observed["native_selected_destination_sha256"]["K"] = "0" * 64
    else:
        observed["attention_consumption"] = True
    with pytest.raises(ValueError):
        c.observer.verify_observation(observed, c.fact)


@pytest.mark.parametrize(
    "branch", ["PrefillNoCache", "graph", "no_source_ACK", "multi_request"]
)
def test_unsupported_branch_has_no_witness(context, branch):
    c = context
    c.observer._metadata.clear()
    if branch == "PrefillNoCache":
        c.metadata.attn_state.name = branch
    elif branch == "no_source_ACK":
        c.observer._materialized.clear()
    elif branch == "multi_request":
        c.runner.input_batch.req_ids += ["CPU-other-runtime"]
        c.runner.input_batch.num_reqs = 2
    c.observer.bind_actual_input_batch(
        c.runner, {c.layer: c.metadata}, eager=branch != "graph"
    )
    pa(c)
    assert len(c.calls) == 1 and not c.events and not c.completions


def test_native_error_is_not_completed_and_publisher_error_propagates(context):
    c = context

    def fail(**kwargs):
        raise RuntimeError("actual native fixture failure")

    c.native = fail
    with pytest.raises(RuntimeError, match="native fixture"):
        pa(c)
    assert not c.events and not c.completions
    c.native = lambda **kwargs: "CPU-result"
    c.observer._publisher = lambda fact: (_ for _ in ()).throw(
        RuntimeError("source ACK failure")
    )
    with pytest.raises(RuntimeError, match="source ACK failure"):
        pa(c)


def test_first_successful_native_call_witness_is_finite_not_all_steps(context):
    pa(context)
    pa(context)
    assert len(context.calls) == 2 and len(context.events) == 1
    assert len(context.completions) == 1


def test_corrupt_source_materialization_ack_cannot_register(context):
    c = context
    other = copy.deepcopy(c.fact)
    other["binding"]["layer_name"] = "CPU-unacknowledged-layer"
    bad_ack = copy.deepcopy(c.ack)
    bad_ack["event_sha256"] = "bad-event"
    with pytest.raises(ValueError, match="ACK"):
        c.observer.remember_acknowledged_materialization(other, bad_ack)
    assert (
        other["binding"]["runtime_request_id"],
        other["binding"]["layer_name"],
    ) not in c.observer._materialized


def test_generated_exact_patch_applies_and_compiles(tmp_path):
    import subprocess

    old, new = build_source_patch.patched()
    output = tmp_path / "patches"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "experiments.native_attention_candidate.build_source_patch",
            "--output",
            str(output),
        ],
        check=True,
        capture_output=True,
    )
    for repository, prefix in (("host", "vllm/"), ("ascend", "vllm_ascend/")):
        root = tmp_path / repository
        root.mkdir()
        for path, text in old.items():
            if path.startswith(prefix) and text:
                location = root / path
                location.parent.mkdir(parents=True, exist_ok=True)
                location.write_text(text)
        subprocess.run(
            ["git", "apply", "--check", str(output / (repository + ".patch"))],
            cwd=root,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "apply", str(output / (repository + ".patch"))],
            cwd=root,
            check=True,
            capture_output=True,
        )
        for path, text in new.items():
            if path.startswith(prefix):
                assert (root / path).read_text() == text
                compile(text, path, "exec")


def pinned_shared_layer_metadata(metadata, layers):
    """Execute the exact pinned Ascend builder's actual aliasing assignment."""
    _, patched = build_source_patch.patched()
    tree = ast.parse(patched["vllm_ascend/worker/model_runner_v1.py"])
    loops = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.For)
        and ast.unparse(node.target) == "layer_name"
        and ast.unparse(node.iter) == "attn_group.layer_names"
        and len(node.body) == 1
        and ast.unparse(node.body[0])
        == "attn_metadata_dict[layer_name] = attn_metadata_i"
    ]
    assert len(loops) == 1, "pinned native metadata aliasing source changed"
    code = compile(
        ast.fix_missing_locations(ast.Module(body=loops, type_ignores=[])),
        "pinned-Ascend-shared-metadata-builder",
        "exec",
    )
    env = dict(
        attn_group=NS(layer_names=layers),
        attn_metadata_dict={},
        attn_metadata_i=metadata,
    )
    exec(code, env)
    return env["attn_metadata_dict"]


def pinned_fia(c):
    _, patched = build_source_patch.patched()
    env = dict(
        device_utils=NS(FIA_TND_LARGE_HEAD_FALLBACK_HEAD_SIZE=512),
        torch_npu=NS(npu_fused_infer_attention_score=c.native),
    )
    exec(
        extract(
            patched["vllm_ascend/device/device_op.py"],
            "npu_fused_infer_attention_score",
            "BaseDeviceAdaptor",
        ),
        env,
    )
    return env["npu_fused_infer_attention_score"](
        None,
        query=c.query,
        key=c.tensors["K"],
        value=c.tensors["V"],
        attn_metadata=c.metadata,
        key_cache=c.tensors["K"],
        value_cache=c.tensors["V"],
        current_key=None,
        current_value=None,
        num_heads=14,
        num_key_value_heads=2,
        head_size=128,
        scale=0.125,
        is_prefill_no_cache=False,
        native_layer_name=c.layer,
        block_table=c.metadata.block_tables,
        actual_seq_lengths_kv=c.metadata.seq_lens_list,
    )


@pytest.mark.parametrize("rank", [0, 1])
def test_actual_shared_metadata_builder_keeps_28_distinct_layer_edges(context, rank):
    c = context
    # NPU fields/native callbacks are explicit CPU fixtures, not device evidence.
    c.observer._materialized.clear()
    c.observer._scope()["process"]["ordinal"] = rank
    c.fact["native_producer"]["ordinal"] = rank
    layers = [f"model.layers.{index}.self_attn.attn" for index in range(28)]
    facts = {}
    for index, layer in enumerate(layers):
        current = copy.deepcopy(c.fact)
        current["binding"].update(layer_name=layer, layer_index=index)
        ack = copy.deepcopy(c.ack)
        ack["sequence"] = index + 4
        ack["event_sha256"] = c.observer.sha(f"CPU-typed-{rank}-{index}".encode())
        ack["ack_sha256"] = c.observer.sha(
            c.observer.canonical(
                {key: value for key, value in ack.items() if key != "ack_sha256"}
            )
        )
        c.observer.remember_acknowledged_materialization(current, ack)
        facts[layer] = current
    mapping = pinned_shared_layer_metadata(c.metadata, layers)
    assert len(mapping) == 28 and len({id(value) for value in mapping.values()}) == 1
    c.observer.bind_actual_input_batch(c.runner, mapping, eager=True)
    assert len(c.observer._metadata) == 28
    for layer in layers:
        c.layer, c.fact = layer, facts[layer]
        assert pinned_fia(c) == "CPU_NATIVE_SENTINEL"
        assert c.observer.verify_observation(c.events[-1], c.fact)[
            "source_argument_completion_relation"
        ]
        assert c.events[-1]["layer_name"] == layer
    assert len(c.events) == len(c.calls) == len(c.completions) == 28
    assert {event["layer_index"] for event in c.events} == set(range(28))
    assert all(event["attention_consumption"] is None for event in c.events)


@pytest.mark.parametrize(
    "mutation",
    ["unknown_layer", "foreign_object", "retained_object_corrupt", "late_source_clock"],
)
def test_shared_metadata_binding_cannot_bypass_wrong_layer_object_clock(
    context, mutation
):
    c = context
    mapping = pinned_shared_layer_metadata(c.metadata, [c.layer])
    c.observer.bind_actual_input_batch(c.runner, mapping, eager=True)
    if mutation == "unknown_layer":
        c.layer = "CPU-unregistered-layer"
    elif mutation == "foreign_object":
        c.metadata = copy.deepcopy(c.metadata)
    elif mutation == "retained_object_corrupt":
        c.observer._metadata[(id(c.metadata), c.layer)]["object"] = copy.deepcopy(
            c.metadata
        )
    else:
        c.observer._metadata[(id(c.metadata), c.layer)]["bound_monotonic_ns"] = (
            time.monotonic_ns() + 10**12
        )
    with pytest.raises(ValueError, match="binding|chronology"):
        pinned_fia(c)
    assert not c.events


def test_host_only_shared_metadata_patch_applies_exactly(tmp_path):
    import subprocess

    from experiments.native_attention_candidate import (
        build_shared_metadata_patch as fix,
    )

    before, after = fix.source_pair()
    manifest = fix.emit(tmp_path / "patch")
    module = tmp_path / "host" / fix.MODULE
    module.parent.mkdir(parents=True)
    module.write_bytes(before)
    subprocess.run(
        ["git", "apply", "--check", str(tmp_path / "patch/host.patch")],
        cwd=tmp_path / "host",
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "apply", str(tmp_path / "patch/host.patch")],
        cwd=tmp_path / "host",
        check=True,
        capture_output=True,
    )
    assert module.read_bytes() == after
    assert manifest["Ascend_source_changed"] is False
    assert manifest["native_ELF_rebuild_required"] is False
    assert manifest["attention_consumption"] is None
