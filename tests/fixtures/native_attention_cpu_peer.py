"""CPU fixture only: synthetic serving/upload metadata; no NPU qualification."""

import array
import base64
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace as NS

from experiments.exposure_gate import native_semantic_collector as n
from experiments.native_attention_candidate import operator_observer as observer
from experiments.native_kv_tensor_candidate import artifact_transport as t
from experiments.native_kv_tensor_candidate import runtime_contract, witness

materializations = {}
registered = False

p = n.identity(os.getpid()) | dict(
    host="CPU_FIXTURE_ONLY",
    role=sys.argv[1],
    ordinal=int(sys.argv[2]),
    process_epoch=1,
    assignment_source="host",
)
print(json.dumps(p), flush=True)


def fixture(rank, layer):
    planes = {
        k: array.array("H", [(i + d) % 65536 for i in range(32 * 128 * 2)])
        for k, d in [("K", 0), ("V", 7)]
    }
    exports, selected, views = {}, {}, {}
    for k, a in planes.items():
        raw = a.tobytes()
        exports[k] = {
            str(b): base64.b64encode(raw[b * 512 : (b + 1) * 512]).decode()
            for b in range(8)
        }
        selected[k] = raw[:4096]
        views[k] = dict(
            device="cpu",
            dtype="torch.float16",
            shape=[32, 128, 1, 2],
            stride=[256, 2, 2, 1],
            npu_format=None,
            data_ptr=a.buffer_info()[0],
            storage_ptr=a.buffer_info()[0],
            storage_offset=0,
        )
    encoded = {k: base64.b64encode(v).decode() for k, v in selected.items()}
    stamp = time.monotonic_ns()
    return dict(
        schema=witness.SCHEMA,
        classification="CPU_SOURCE_CANDIDATE_ONLY",
        formal_registration=False,
        GPU_qualification=None,
        attention_consumption=None,
        full_model_quality=None,
        binding=dict(
            runtime_request_id="CPU-runtime",
            layer_name="CPU-layer." + str(layer),
            layer_index=layer,
            expected_layer_indices=list(range(28)),
            rank=rank,
            tensor_parallel_size=2,
            physical_num_tokens=1201,
            semantic_num_tokens=1201,
            compression_plan=dict(
                semantic_anchor=1201,
                physical_anchor=1024,
                source_block_ids=list(range(10)),
                destination_block_ids=list(range(11, 19)),
            ),
            cache_blocks_per_scheduler_block=1,
        ),
        source_blocks=list(range(10)),
        destination_blocks=list(range(11, 19)),
        keep_indices=list(range(1024)),
        source_slots=list(range(1024)),
        destination_slots=list(range(11 * 128, 19 * 128)),
        block_size=128,
        source_before_gather_ns=stamp,
        reference_after_gather_ns=stamp,
        write_completed_barrier_ns=stamp,
        destination_readback_completed_ns=stamp,
        cache_views={k: dict(before=v, after=dict(v)) for k, v in views.items()},
        exported_source_block_bytes=exports,
        source_after_write_block_bytes=exports,
        selected_source_bytes=encoded,
        gathered_workspace_bytes=encoded,
        destination_readback_bytes=encoded,
        selected_source_sha256={k: n.sha(v) for k, v in selected.items()},
        destination_readback_sha256={k: n.sha(v) for k, v in selected.items()},
    )


for line in sys.stdin:
    c = json.loads(line)
    ready = c["ready"]

    def scope():
        return dict(
            process=p,
            plan_id="plan",
            launch_id="launch",
            monotonic_ns=time.monotonic_ns(),
        )

    receiver = dict(
        expected_collector=ready["collector"],
        expected_socket_identity=tuple(ready["socket_identity"]),
        expected_collector_source_sha256=ready["collector_source_sha256"],
        expected_archive_identity=ready["archive_identity"],
    )
    try:
        if c["op"] == "attack":
            ack = n.submit_fact(Path(ready["socket_path"]), c["fact"], **receiver)
        elif c["op"] == "attention":
            if not registered:
                observer.register_source_candidate(
                    lambda fact, socket_path=ready["socket_path"], receiver=receiver: (
                        n.submit_fact(Path(socket_path), fact, **receiver)
                    ),
                    scope=scope,
                    current_stream=lambda device: NS(
                        npu_stream=9, device=device, synchronize=lambda: None
                    ),
                    get_format=lambda tensor: tensor.view["npu_format"],
                    read_prefix=lambda tensor, f, kind: f[
                        "destination_readback_sha256"
                    ][kind],
                )
                registered = True
                for f, ack in materializations.values():
                    observer.remember_acknowledged_materialization(f, ack)

            class Tensor:
                def __init__(self, values=None, view=None):
                    self.values, self.view = values, view
                    if view is None:
                        view = dict(
                            device="cpu",
                            dtype="torch.int32",
                            shape=[1, 9] if isinstance(values[0], list) else [1],
                            stride=[9, 1] if isinstance(values[0], list) else [1],
                            data_ptr=1,
                            storage_ptr=1,
                            storage_offset=0,
                            npu_format=None,
                        )
                        self.view = view
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
                    return self.values

            cpu_blocks = list(range(11, 20))

            class Row:
                def __getitem__(self, key, blocks=cpu_blocks):
                    return Tensor(blocks)

            batch = NS(
                req_ids=["CPU-runtime"],
                num_reqs=1,
                req_id_to_index={"CPU-runtime": 0},
                block_table=NS(
                    block_tables=[
                        NS(
                            num_blocks_per_row=[9],
                            block_table=NS(np=Row(), gpu=NS(shape=[1, 32])),
                        )
                    ]
                ),
            )
            runner = NS(
                input_batch=batch, requests={"CPU-runtime": NS(block_ids=[cpu_blocks])}
            )
            for _layer, (f, _ack) in materializations.items():
                name = f["binding"]["layer_name"]
                metadata = NS(
                    attn_state=NS(name="DecodeOnly"),
                    num_prefills=0,
                    num_decodes=1,
                    actual_seq_lengths_q=[1],
                    seq_lens=Tensor([1025]),
                    seq_lens_list=[1025],
                    block_tables=Tensor([cpu_blocks]),
                )
                observer.bind_actual_input_batch(runner, {name: metadata}, eager=True)
                arguments = dict(
                    query=Tensor(view=f["cache_views"]["K"]["after"]),
                    key_cache=Tensor(view=f["cache_views"]["K"]["after"]),
                    value_cache=Tensor(view=f["cache_views"]["V"]["after"]),
                    block_table=metadata.block_tables,
                    context_lens=metadata.seq_lens,
                )
                observer.observe_native_call(
                    "torch_npu._npu_paged_attention",
                    lambda **kwargs: None,
                    arguments,
                    metadata=metadata,
                    layer_name=name,
                )
            ack = {"CPU_FIXTURE_ONLY": True}
        elif c["op"] == "mapping":
            ack = n.submit_fact(
                Path(ready["socket_path"]),
                dict(
                    schema=n.MAPPING,
                    **scope(),
                    external_request_id=c["external"],
                    runtime_request_id="CPU-runtime",
                ),
                **receiver,
            )
        else:
            for layer in range(28):
                f = fixture(p["ordinal"], layer)
                for views in f["cache_views"].values():
                    for view in views.values():
                        view.update(device="npu:" + str(p["ordinal"]), npu_format=2)
                f = runtime_contract.from_actual_native_readback(f, p)
                actual_ack = t.publish_candidate(
                    f,
                    directory_path=c["dir"]["path"],
                    directory_identity=c["dir"]["identity"],
                    policy_sha256=ready["policy_sha256"],
                    scope=scope,
                    socket_path=ready["socket_path"],
                    receiver=receiver,
                    runtime=True,
                )
                materializations[layer] = (f, actual_ack)
            effect = time.monotonic_ns()
            fields = dict(
                runtime_request_id="CPU-runtime",
                attention_group=0,
                semantic_anchor=1201,
                physical_anchor=1024,
                destination_block_ids=list(range(11, 19)),
                host_cpu_block_ids=list(range(11, 20)),
                allocation_block_size=128,
                compression_threshold_tokens=1152,
                scheduled_appended_block_ids=[19],
                metadata_effect_monotonic_ns=effect,
            )
            projection = dict(
                schema=n.PROJECTION_V2,
                **scope(),
                **fields,
                metadata_row=0,
                transaction_id=n.sha(n.canonical(fields)),
                operation=n.PROJECTION_OPERATION,
                scope=n.PROJECTION_SCOPE,
                host_mapping="identity-host-block-id-projection-with-scheduled-append",
                kv_tensor_equivalence=None,
                attention_consumed_observed_tensor=None,
                full_generation_quality=None,
            )
            n.submit_fact(Path(ready["socket_path"]), projection, **receiver)
            rows = [dict(group=0, row=0, blocks=list(range(11, 20)))]
            upload = dict(
                schema=n.UPLOAD,
                **scope(),
                observed_after_barrier_monotonic_ns=time.monotonic_ns(),
                runtime_request_id="CPU-runtime",
                device="npu:" + str(p["ordinal"]),
                uploaded_rows=rows,
                uploaded_rows_sha256=n.sha(n.canonical(rows)),
                scope="NPU-block-table-prefix-readback-only",
                kv_tensor_equivalence=None,
                attention_consumed_observed_tensor=None,
                full_generation_quality=None,
            )
            ack = n.submit_fact(Path(ready["socket_path"]), upload, **receiver)
        print(json.dumps(dict(ack=ack)), flush=True)
    except Exception as e:
        print(json.dumps(dict(rejected=str(e))), flush=True)
