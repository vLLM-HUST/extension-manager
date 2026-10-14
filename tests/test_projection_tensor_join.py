import base64
import copy
import json
import pathlib
import tempfile
import unittest

from experiments.exposure_gate import native_semantic_collector as native
from experiments.native_kv_tensor_candidate import artifact_transport
from experiments.native_kv_tensor_candidate import projection_tensor_join as join


class Join(unittest.TestCase):
    def test_positive_and_semantic_counterexamples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            events = []
            phase = {"phase_id": "p"}

            def emit(kind, fact, artifact=None):
                e = {
                    "sequence": len(events),
                    "kind": kind,
                    "phase": phase,
                    "raw_base64": base64.b64encode(json.dumps(fact).encode()).decode(),
                }
                if artifact:
                    e["artifact"] = {"basename": artifact}
                events.append(e)

            for rank in [0, 1]:
                process = {"ordinal": rank, "pid": 100 + rank}
                projection = {
                    "schema": native.PROJECTION_V2,
                    "runtime_request_id": "r",
                    "process": process,
                    "launch_id": "l",
                    "plan_id": "p",
                    "semantic_anchor": 4,
                    "physical_anchor": 2,
                    "destination_block_ids": [9],
                    "host_cpu_block_ids": [9, 10],
                    "attention_group": 0,
                    "metadata_effect_monotonic_ns": 10,
                    "monotonic_ns": 11,
                    "transaction_id": "projection-distinct-schema",
                }
                emit("native.accepted", projection)
                emit(
                    "native.accepted",
                    {
                        "schema": native.UPLOAD,
                        "runtime_request_id": "r",
                        "process": process,
                        "launch_id": "l",
                        "plan_id": "p",
                        "monotonic_ns": 13,
                        "observed_after_barrier_monotonic_ns": 12,
                        "uploaded_rows": [{"group": 0, "blocks": [9, 10]}],
                    },
                )
                for layer in range(28):
                    payload = {
                        "binding": {
                            "runtime_request_id": "r",
                            "rank": rank,
                            "compression_plan": {
                                "semantic_anchor": 4,
                                "physical_anchor": 2,
                                "source_block_ids": [1],
                                "destination_block_ids": [9],
                            },
                            "semantic_num_tokens": 4,
                            "cache_blocks_per_scheduler_block": 1,
                        },
                        "keep_indices": [0, 1],
                        "source_blocks": [1],
                        "destination_blocks": [9],
                        "destination_readback_completed_ns": 5,
                    }
                    tx = artifact_transport.transaction(payload)
                    name = f"{rank}-{layer}.json"
                    (root / name).write_text(json.dumps(payload))
                    emit(
                        "tensor.artifact.accepted",
                        {
                            "runtime_request_id": "r",
                            "transaction_id": tx,
                            "process": process,
                            "launch_id": "l",
                            "plan_id": "p",
                        },
                        name,
                    )

            def verify(data):
                payloads = {
                    event["sequence"]: json.loads(
                        (root / event["artifact"]["basename"]).read_bytes()
                    )
                    for event in data
                    if event["kind"] == "tensor.artifact.accepted"
                }
                return join.verify_projection_tensor_join(
                    data, payloads, runtime_request_id="r", transaction_id=tx
                )

            self.assertTrue(verify(events)["two_rank_plan_projection_upload_join"])
            for mutate in [
                "wrong_projection_dest",
                "wrong_row",
                "wrong_epoch",
                "missing_rank",
                "readback_after_effect",
                "rank_fullrow_diverged",
            ]:
                e = copy.deepcopy(events)
                if mutate == "missing_rank":
                    e = [
                        x
                        for x in e
                        if not (
                            x["kind"] == "native.accepted"
                            and json.loads(base64.b64decode(x["raw_base64"]))["schema"]
                            == native.PROJECTION_V2
                            and json.loads(base64.b64decode(x["raw_base64"]))[
                                "process"
                            ]["ordinal"]
                            == 1
                        )
                    ]
                else:
                    index = 0 if mutate != "wrong_row" else 1
                    if mutate == "rank_fullrow_diverged":
                        index = 30
                    f = json.loads(base64.b64decode(e[index]["raw_base64"]))
                    if mutate == "rank_fullrow_diverged":
                        f["host_cpu_block_ids"] = [9, 11]
                    if mutate == "wrong_projection_dest":
                        f["destination_block_ids"] = [8]
                    if mutate == "wrong_row":
                        f["uploaded_rows"][0]["blocks"] = [9, 99]
                    if mutate == "wrong_epoch":
                        f["process"]["pid"] = 999
                    if mutate == "readback_after_effect":
                        f["metadata_effect_monotonic_ns"] = 4
                    e[index]["raw_base64"] = base64.b64encode(
                        json.dumps(f).encode()
                    ).decode()
                with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                    verify(e)


if __name__ == "__main__":
    unittest.main()
