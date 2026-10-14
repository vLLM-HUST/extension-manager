"""Reproduce installable patches from exact archived source bytes, never live trees."""

from __future__ import annotations

import difflib
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent
SOURCE = ROOT / "source"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    output = ROOT / "artifact-source"
    output.mkdir(exist_ok=True)
    binding = json.loads((SOURCE / "source-binding.json").read_text())
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        for item in binding["source_files"]:
            raw = (SOURCE / item["snapshot"]).read_bytes()
            if digest(raw) != item["preimage_sha256"]:
                raise ValueError("original source snapshot changed")
            path = tmp / item["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        subprocess.run(
            ["git", "apply", str(SOURCE / "kv-selected-tensor-hook.patch")],
            cwd=tmp,
            check=True,
            capture_output=True,
        )
        cache_path, method_path = [item["path"] for item in binding["source_files"]]
        cache = (tmp / cache_path).read_text()
        method = (tmp / method_path).read_text()
        method = method.replace(
            "        from ... import native_tensor_witness\n",
            """        from ... import native_tensor_witness
        from vllm.plugins.native_tensor_artifact_bootstrap import ensure_registered

        if not native_tensor_witness.enabled():
            ensure_registered(native_tensor_witness.register_candidate_sink)
""",
            1,
        )
        method = method.replace(
            "                witness_binding = {",
            """                if request.plan is None:
                    raise RuntimeError("actual source CompressionRequest.plan required")
                plan = request.plan
                witness_binding = {""",
            1,
        )
        method = method.replace(
            '                    "runtime_request_id": request.request_id,',
            """                    "runtime_request_id": request.request_id,
                    "compression_plan": {
                        "semantic_anchor": plan.semantic_anchor,
                        "physical_anchor": plan.physical_anchor,
                        "source_block_ids": list(plan.source_block_ids),
                        "destination_block_ids": list(plan.destination_block_ids),
                    },
                    "cache_blocks_per_scheduler_block": (
                        len(request.source_block_ids_device)
                        // len(plan.source_block_ids)
                    ),""",
            1,
        )
        replacements = {
            cache_path: cache,
            method_path: method,
            "src/vllm_ascend_kvcompress/native_tensor_witness.py": (
                ROOT / "witness.py"
            ).read_text(),
        }
        manifest = {
            "schema": "ecpa-selected-KV-private-artifact-source-patch/v1",
            "Host_base_commit": binding["Host_base_commit"],
            "KV_base_commit": binding["KV_base_commit"],
            "Ascend_base_commit": binding["Ascend_base_commit"],
            "classification": "CPU_SOURCE_CANDIDATE_ONLY",
            "formal_registration": False,
            "GPU_qualification": None,
            "attention_consumption": None,
            "KV_files": [],
            "Host_new_files": [],
        }
        patch = []
        originals = {
            item["path"]: (SOURCE / item["snapshot"]).read_text()
            for item in binding["source_files"]
        }
        for path, new in replacements.items():
            old = originals.get(path, "")
            patch.extend(
                difflib.unified_diff(
                    old.splitlines(True),
                    new.splitlines(True),
                    fromfile="a/" + path if old else "/dev/null",
                    tofile="b/" + path,
                )
            )
            manifest["KV_files"].append(
                {
                    "path": path,
                    "preimage_sha256": digest(old.encode()) if old else None,
                    "postimage_sha256": digest(new.encode()),
                }
            )
        (output / "kv-private-tensor-artifact.patch").write_text("".join(patch))
        host_patch = []
        for src, name in [
            ("artifact_transport.py", "native_tensor_artifact_transport.py"),
            ("artifact_bootstrap.py", "native_tensor_artifact_bootstrap.py"),
            ("witness.py", "native_tensor_witness.py"),
        ]:
            raw = (ROOT / src).read_text()
            path = "vllm/plugins/" + name
            host_patch.extend(
                difflib.unified_diff(
                    [], raw.splitlines(True), fromfile="/dev/null", tofile="b/" + path
                )
            )
            manifest["Host_new_files"].append(
                {"path": path, "source": src, "sha256": digest(raw.encode())}
            )
        (output / "host-private-tensor-artifact.patch").write_text("".join(host_patch))
        # Existing native collector/observer/bootstrap bytes remain a separately
        # version-bound dependency; clock-policy changes are not silently copied.
        from experiments.exposure_gate import native_semantic_collector

        manifest["Host_existing_collector_sha256"] = digest(
            Path(native_semantic_collector.__file__).read_bytes()
        )
        manifest["KV_plan_source_sha256"] = digest(
            (output / "transaction.py.snapshot").read_bytes()
        )
        manifest["patch_sha256"] = {
            p.name: digest(p.read_bytes()) for p in output.glob("*.patch")
        }
        (output / "binding.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
