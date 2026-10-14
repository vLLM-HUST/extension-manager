"""Real torch CPU tensor/pinned patch exercise; requires an existing torch install."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from . import witness


def main():
    import torch

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).with_name("source")
    binding = json.loads((source / "source-binding.json").read_text())
    import hashlib

    results = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for item in binding["source_files"]:
            p = root / item["path"]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes((source / item["snapshot"]).read_bytes())
        subprocess.run(
            ["git", "apply", str(source / "kv-selected-tensor-hook.patch")],
            cwd=root,
            check=True,
            capture_output=True,
        )
        for item in binding["source_files"]:
            assert (
                hashlib.sha256((root / item["path"]).read_bytes()).hexdigest()
                == item["postimage_sha256"]
            )
        # Strip only the candidate import and inject this exact hash-bound module.
        path = root / "src/vllm_ascend_kvcompress/methods/triattention/cache.py"
        raw = path.read_text().replace("from ... import native_tensor_witness", "")
        env = {"native_tensor_witness": witness, "__name__": "_pinned_cache_cpu"}
        exec(compile(raw, str(path), "exec"), env)
        records = []
        witness.register_candidate_sink(records.append)
        for noncontiguous in [False, True]:
            # Real f16 Torch tensors; gapped page stride exercises the actual fallback.
            backing = (
                torch.arange(12 * 128 * 2 * 4, dtype=torch.float32)
                .to(torch.float16)
                .reshape(12, 128, 2, 4)
            )
            k = (
                (backing[::2] if noncontiguous else backing[:6]).clone()
                if not noncontiguous
                else backing[::2]
            )
            v = (k + torch.tensor(0.5, dtype=torch.float16)).clone()
            if noncontiguous:
                v_back = torch.zeros_like(backing)
                v_back[::2].copy_(v)
                v = v_back[::2]
            keep = torch.tensor([0, 127, 128], dtype=torch.long)
            source_blocks = torch.tensor([0, 1], dtype=torch.long)
            dest_blocks = torch.tensor([3], dtype=torch.long)
            source_slots = env["token_slots"](source_blocks, keep, 128)
            dest_slots = env["token_slots"](dest_blocks, torch.arange(3), 128)
            kw = torch.empty((3, 2, 4), dtype=torch.float16)
            vw = torch.empty_like(kw)
            fact_binding = {
                "runtime_request_id": "CPU-source-only",
                "layer_name": "CPU-layer.0",
                "layer_index": 0,
                "expected_layer_indices": [0],
                "rank": 0,
                "tensor_parallel_size": 1,
                "physical_num_tokens": 129,
                "semantic_num_tokens": 129,
                "source_blocks": [0, 1],
                "destination_blocks": [3],
                "block_size": 128,
                "keep_indices": keep,
            }
            env["materialize_token_slots"](
                k, v, source_slots, dest_slots, kw, vw, witness_binding=fact_binding
            )
            assert witness.verify(records[-1])["selected_KV_bytes_match"]
            results.append(
                {
                    "actual_pinned_cache_function": True,
                    "noncontiguous_pages": noncontiguous,
                    "passed": True,
                }
            )
            # Make the actual gather wrong, then copy that same wrong workspace.
            original = env["_gather_slots"]

            def bad_gather(cache, slots, out=None, original=original):
                result = original(cache, slots, out)
                if out is not None:
                    out.zero_()
                return result

            env["_gather_slots"] = bad_gather
            try:
                env["materialize_token_slots"](
                    k, v, source_slots, dest_slots, kw, vw, witness_binding=fact_binding
                )
                raise AssertionError("same wrong gather/write accepted")
            except ValueError as error:
                assert "workspace differs" in str(error)
                results.append(
                    {
                        "wrong_gather_then_same_wrong_copy_rejected": True,
                        "noncontiguous_pages": noncontiguous,
                    }
                )
            env["_gather_slots"] = original
            original_write = env["_write_slots"]

            def bad_write(cache, slots, values, original_write=original_write):
                original_write(cache, slots, values)
                cache[0].zero_()  # Illicit source mutation after a private write.

            env["_write_slots"] = bad_write
            try:
                env["materialize_token_slots"](
                    k, v, source_slots, dest_slots, kw, vw, witness_binding=fact_binding
                )
                raise AssertionError("source mutation accepted")
            except ValueError as error:
                assert "source cache changed" in str(error)
                results.append(
                    {
                        "actual_write_source_mutation_rejected": True,
                        "noncontiguous_pages": noncontiguous,
                    }
                )
            env["_write_slots"] = original_write

        # A local sink failure propagates out of the real patched materialization.
        # A returned True remains ignored, never an authenticated ACK.
        def fail_sink(fact):
            raise RuntimeError("CPU-candidate-sink-failure")

        witness._sink = fail_sink
        try:
            env["materialize_token_slots"](
                k, v, source_slots, dest_slots, kw, vw, witness_binding=fact_binding
            )
            raise AssertionError("sink failure swallowed")
        except RuntimeError as error:
            assert str(error) == "CPU-candidate-sink-failure"
            results.append({"actual_callback_failure_propagated": True})
    output = {
        "classification": "CPU_SOURCE_CANDIDATE_ONLY",
        "torch_version": torch.__version__,
        "candidate_module_sha256": hashlib.sha256(
            Path(witness.__file__).read_bytes()
        ).hexdigest(),
        "source_binding_sha256": hashlib.sha256(
            (source / "source-binding.json").read_bytes()
        ).hexdigest(),
        "executed_pinned_postimage_sha256": binding["source_files"][0][
            "postimage_sha256"
        ],
        "results": results,
        "formal_registration": False,
        "GPU_tested": False,
        "attention_consumption": None,
        "full_model_quality": None,
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps(output))


if __name__ == "__main__":
    main()
