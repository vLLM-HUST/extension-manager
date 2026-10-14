"""Emit a Host-only fresh-source fix; never mutate an existing runtime source."""

from __future__ import annotations

import argparse
import difflib
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parent
PREIMAGE = "4e90663b028526d16a938b85f520e32f73eb5d62d2e87dfea78a28ad554a5d8a"
HOST_BASE = "b02672dba79d2446d4da889bc436f12226ed6dba"
MODULE = "vllm/plugins/native_attention_operator_observer.py"


def source_pair():
    before = gzip.decompress(
        (ROOT / "source/observer-195-shared-metadata-preimage.py.gz").read_bytes()
    )
    if hashlib.sha256(before).hexdigest() != PREIMAGE:
        raise ValueError("immutable195 observer preimage differs")
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
        schema="ecpa-native-attention-shared-metadata-source-fix/v1",
        Host_base_commit=HOST_BASE,
        module=MODULE,
        preimage_sha256=PREIMAGE,
        postimage_sha256=hashlib.sha256(after).hexdigest(),
        patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
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
