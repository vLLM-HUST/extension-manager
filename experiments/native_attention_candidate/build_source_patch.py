"""Reproducible opt-in Host/Ascend source patch, with exact byte preconditions."""

from __future__ import annotations

import argparse
import difflib
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parent


def once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("exact unique source contact missing")
    return text.replace(before, after)


def sources():
    inventory = json.loads((ROOT / "source/binding.json").read_bytes())
    result = {}
    for item in inventory["source_files"]:
        raw = gzip.decompress((ROOT / "source" / item["snapshot"]).read_bytes())
        if hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("native source preimage changed")
        result[item["path"]] = raw.decode()
    return result


def patched():
    old = sources()
    new = dict(old)
    path = "vllm_ascend/worker/model_runner_v1.py"
    new[path] = once(
        old[path],
        "                self._sanitize_placeholder_input_ids_for_forward(\n",
        "                from"
        " vllm.plugins.native_attention_operator_observer"
        " import bind_actual_input_batch\n"
        "                bind_actual_input_batch(self, attn_metadata,"
        " eager=cudagraph_mode == CUDAGraphMode.NONE)\n\n"
        "                self._sanitize_placeholder_input_ids_for_forward(\n",
    )
    path = "vllm_ascend/attention/attention_v1.py"
    new[path] = once(
        old[path],
        "        torch_npu._npu_paged_attention(\n            query=query,",
        "        from vllm.plugins.native_attention_operator_observer"
        " import observe_native_call\n"
        "        observe_native_call(\n"
        "            'torch_npu._npu_paged_attention',"
        " torch_npu._npu_paged_attention, dict(\n            query=query,",
    )
    new[path] = once(
        new[path],
        "            out=output,\n        )\n        return output\n\n  "
        "  def _forward_encoder_attention",
        "            out=output,\n            ), metadata=attn_metadata,"
        " layer_name=self._layer_name,\n"
        "        )\n        return output\n\n    def _forward_encoder_attention",
    )
    new[path] = once(
        new[path],
        "                    head_size=self.head_size,\n                "
        "    scale=self.scale,\n                    key_cache=self.key_cache,",
        "                    head_size=self.head_size,\n                "
        "    native_layer_name=self._layer_name,\n"
        "                    scale=self.scale,\n                   "
        " key_cache=self.key_cache,",
    )
    path = "vllm_ascend/device/device_op.py"
    # Only A2 final cached FIA is instrumented. A5's separate implementation
    # consumes the opt-in keyword but emits no witness (explicit unsupported).
    marker = "        is_prefill_no_cache: bool,\n        **kwargs,"
    if old[path].count(marker) != 2:
        raise ValueError("A2/A5 exact native signatures changed")
    new[path] = old[path].replace(
        marker,
        "        is_prefill_no_cache: bool,\n        native_layer_name:"
        " str | None = None,\n        **kwargs,",
    )
    new[path] = new[path].replace(
        "        return torch_npu.npu_fused_infer_attention_score(\n    "
        "        query=query,\n"
        "            key=key,\n"
        "            value=value,\n"
        "            num_key_value_heads=num_key_value_heads,\n"
        "            num_heads=num_heads,\n"
        "            scale=scale,\n"
        "            **kwargs,\n"
        "        )",
        "        from vllm.plugins.native_attention_operator_observer"
        " import observe_native_call\n"
        "        return observe_native_call(\n"
        "            'torch_npu.npu_fused_infer_attention_score',\n"
        "            torch_npu.npu_fused_infer_attention_score, dict(\n"
        "            query=query, key=key, value=value,\n"
        "            num_key_value_heads=num_key_value_heads, num_heads=num_heads,\n"
        "            scale=scale, **kwargs,\n"
        "            ), metadata=attn_metadata, layer_name=native_layer_name,\n"
        "        )",
        1,
    )
    # Historical c435 construction stays pinned independently of evolving live
    # runtime wrappers. This snapshot has the exact original guarded bytes.
    bootstrap = ROOT / "source/tensor-artifact-bootstrap-c435.py"
    host_path = "vllm/plugins/native_tensor_artifact_bootstrap.py"
    old[host_path] = bootstrap.read_text()
    if hashlib.sha256(bootstrap.read_bytes()).hexdigest() != (
        "85b9a5226980fa92c1fea9357c72c831b943a851c23922ef1d4cb8ff26053211"
    ):
        raise ValueError("c435 source-owned tensor bootstrap preimage changed")
    new[host_path] = once(
        old[host_path],
        "    inode, digest = (info.st_dev, info.st_ino), native.sha(raw)\n",
        "    if os.environ.get('ECPA_NATIVE_ATTENTION_OPERATOR_OBSERVER') == '1':\n"
        "        import torch\n        import torch_npu\n"
        "        from .native_block_table_observer import emit_native_fact, _scope\n"
        "        from .native_attention_operator_observer import"
        " register_source_candidate\n"
        "        register_source_candidate(lambda fact:"
        " emit_native_fact(lambda: fact),\n"
        "            scope=lambda: _scope('worker'),"
        " current_stream=torch.npu.current_stream,\n"
        "            get_format=torch_npu.get_npu_format)\n"
        "    inode, digest = (info.st_dev, info.st_ino), native.sha(raw)\n",
    )
    new[host_path] = once(
        new[host_path],
        "        return transport.publish_candidate(\n",
        "        ack = transport.publish_candidate(\n",
    )
    new[host_path] = once(
        new[host_path],
        "\n    return callback\n",
        "        if is_runtime:\n"
        "            from .native_attention_operator_observer import"
        " remember_acknowledged_materialization\n"
        "            remember_acknowledged_materialization(published, ack)\n"
        "        return ack\n\n    return callback\n",
    )
    old["vllm/plugins/native_attention_operator_observer.py"] = ""
    new["vllm/plugins/native_attention_operator_observer.py"] = (
        ROOT / "operator_observer.py"
    ).read_text()
    return old, new


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    old, new = patched()
    args.output.mkdir(parents=True, exist_ok=False)
    for repository, prefix in (("host", "vllm/"), ("ascend", "vllm_ascend/")):
        diff = ""
        for path in sorted(new):
            if not path.startswith(prefix) or old[path] == new[path]:
                continue
            compile(new[path], path, "exec")
            diff += "".join(
                difflib.unified_diff(
                    old[path].splitlines(True),
                    new[path].splitlines(True),
                    fromfile="a/" + path if old[path] else "/dev/null",
                    tofile="b/" + path,
                )
            )
        (args.output / (repository + ".patch")).write_text(diff)
    manifest = {
        "schema": "ecpa-native-attention-candidate-patch-manifest/v1",
        "classification": "CPU_SOURCE_CANDIDATE_ONLY",
        "Host_base_commit": "c4350611e3f1b74e92e24287b1988600154ccba3",
        "Ascend_base_commit": "fcbb827af84f793939bf03d01a1dfe0338a0164c",
        "source_files": [
            {
                "path": p,
                "preimage_sha256": hashlib.sha256(old[p].encode()).hexdigest()
                if old[p]
                else None,
                "postimage_sha256": hashlib.sha256(new[p].encode()).hexdigest(),
            }
            for p in new
            if new[p] != old[p]
        ],
        "GPU_qualification": None,
        "attention_consumption": None,
        "full_model_quality": None,
        "formal_registration": False,
        "registered_attention_receiver": False,
    }
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
