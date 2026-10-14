"""Emit a Host-only fresh-source fix; never mutate an existing runtime source."""

from __future__ import annotations

import argparse
import difflib
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parent
PREIMAGE = "bb11fd7d71026fee0bc94bf329f762f3b5de56b6f5528dba96ffc908fc549c1f"
HOST_BASE = "a222df060a364a4cce88f39b583f50ea87ef2749"
MODULE = "vllm/plugins/native_attention_operator_observer.py"
VENDOR_SOURCE_SHA256 = (
    "8abe7bea6817f25d2360aee783afae16fe7fe2aaa46a04e7b7b865e7f2039488"
)


def source_pair():
    before = gzip.decompress(
        (ROOT / "source/observer-197-vendor-format-preimage.py.gz").read_bytes()
    )
    if hashlib.sha256(before).hexdigest() != PREIMAGE:
        raise ValueError("immutable197 observer preimage differs")
    after = (ROOT / "operator_observer.py").read_bytes()
    compile(after, MODULE, "exec")
    return before, after


def emit(output):
    before, after = source_pair()
    output.mkdir(parents=True, exist_ok=False)
    patch = "".join(
        difflib.unified_diff(
            before.decode().splitlines(True),
            after.decode().splitlines(True),
            fromfile="a/" + MODULE,
            tofile="b/" + MODULE,
        )
    )
    (output / "host.patch").write_text(patch)
    manifest = dict(
        schema="ecpa-native-attention-vendor-format-source-fix/v1",
        Host_base_commit=HOST_BASE,
        module=MODULE,
        preimage_sha256=PREIMAGE,
        postimage_sha256=hashlib.sha256(after).hexdigest(),
        patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
        required_vendor_source_files=[
            {
                "path": "torch_npu/npu/_format.py",
                "sha256": VENDOR_SOURCE_SHA256,
            }
        ],
        known_format_codes_are_layout_support=False,
        rejection_diagnostic_scope="bounded-log-only-not-durable-ACK-or-OP-receipt",
        Ascend_source_changed=False,
        native_ELF_rebuild_required=False,
        fresh_Host_commit_wheel_install_source_audit_required=True,
        fresh_recipe_source_context_nonce_cohort_required=True,
        classification="CPU_SOURCE_CANDIDATE_ONLY",
        formal_registration=False,
        NPU_result=None,
        attention_consumption=None,
        full_model_quality=None,
    )
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(emit(args.output), sort_keys=True))


if __name__ == "__main__":
    main()
