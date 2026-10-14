"""Actual Torch CPU logical bytes audit; no NPU/operator/quality qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from . import operator_observer as observer


def run():
    import torch

    cases = {}
    for dtype in [torch.float16, torch.bfloat16]:
        for gap in [False, True]:
            storage = (
                torch.arange(12 * 128 * 2, dtype=torch.float32).remainder(31).to(dtype)
            )
            cache = torch.as_strided(
                storage, (6, 128, 1, 2), (512 if gap else 256, 2, 2, 1)
            )
            reference = {
                "shape": list(cache.shape),
                "stride": list(cache.stride()),
                "dtype": str(cache.dtype),
            }
            fact = {
                "cache_views": {"K": {"after": reference}},
                "keep_indices": list(range(128)),
                "destination_blocks": [3],
                "block_size": 128,
            }
            # Independent scalar binary16 encoding for exactly representable
            # integer samples; no Torch block-export routine supplies reference.
            raw = b"".join(
                struct.pack("<e", float(cache[3, index, 0, dim]))
                if dtype == torch.float16
                else struct.pack("<f", float(cache[3, index, 0, dim]))[2:]
                for index in range(128)
                for dim in range(2)
            )
            expected = hashlib.sha256(raw).hexdigest()
            observer.require(
                observer.read_destination_prefix(cache, fact, "K") == expected,
                "CPU reader differs from scalar byte reference",
            )
            observer.require(
                observer.read_destination_prefix(cache.view(6, 128, 2), fact, "K")
                == expected,
                "exact flatten differs",
            )
            cache[4, 0, 0, 0] += 1
            observer.require(
                observer.read_destination_prefix(cache, fact, "K") == expected,
                "append block entered selected prefix",
            )
            cache[3, 0, 0, 0] += 1
            observer.require(
                observer.read_destination_prefix(cache, fact, "K") != expected,
                "destination mutation was not observed",
            )
            for unsupported in (cache.transpose(1, 2), cache.float()):
                try:
                    observer.read_destination_prefix(unsupported, fact, "K")
                except ValueError:
                    pass
                else:
                    raise ValueError("unsupported layout/dtype accepted")
            cases[str(dtype) + ("-pagegap" if gap else "-contiguous")] = dict(
                actual_reader_equals_independent_binary16=True,
                exact_flatten_same=True,
                append_block_excluded=True,
                destination_mutation_detected=True,
                unsupported_transpose_rejected=True,
                dtype_mismatch_rejected=True,
            )
    return dict(
        classification="ACTUAL_TORCH_CPU_SOURCE_BYTE_READER_AUDIT",
        torch_version=torch.__version__,
        operator_source_sha256=observer.sha(Path(observer.__file__).read_bytes()),
        cases=cases,
        NPU_started=False,
        formal_result=False,
        attention_consumption=None,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(run(), indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
