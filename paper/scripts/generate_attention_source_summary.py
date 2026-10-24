"""Derive bounded paper counts from the complete independently replayed R4 corpus."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.benchmark_inputs import new_output, resolve_original  # noqa: E402


def derive(root):
    sys.path.insert(0, str(root))
    from experiments.formal_campaign import (
        verify_attention_source_drained_observation as verifier,
    )
    from scripts.benchmark_inputs import resolve_original

    package = resolve_original(
        root
        / (
            "experiments/formal_campaign/artifacts/"
            "attention-source-drained-observation-20261014-r4"
        )
    )
    manifest = json.loads((package / "manifest.json").read_bytes())
    source = root / manifest["late_packaging"]["portable_verifier_path"]
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if (
        manifest["archive_sha256"]
        != "69101ef1e478831ef2fde16df51baa4a23c5fe32b4488b9d3334e8fad4688d41"
        or digest != manifest["late_packaging"]["portable_verifier_sha256"]
    ):
        raise ValueError("R4 paper source/archive identity differs")
    files = verifier.load_archive(package / "manifest.json", package)
    observed = verifier.inspect(files)
    rows = [
        json.loads(line) for line in files["runtime/run/native-raw.jsonl"].splitlines()
    ]
    closed = [row for row in rows if row["kind"] == "attention.worker.drained"]
    ranks = {
        json.loads(base64.b64decode(row["raw_base64"], validate=True))["process"][
            "ordinal"
        ]
        for row in closed
    }
    if (
        observed["formal_result"] is not False
        or observed["formal_H3_starts"] != 0
        or observed["formal_H4_starts"] != 0
        or observed["full_model_quality"] is not None
        or observed["performance_result"] is not None
        or ranks != {0, 1}
    ):
        raise ValueError("R4 paper finite scope differs")
    return {
        "schema": "ecpa-paper-finite-attention-source-drain-summary/v1",
        "archive_sha256": manifest["archive_sha256"],
        "verifier_sha256": digest,
        "whole_unfiltered_records": len(rows),
        "source_close_records": len(closed),
        "operator_receipt_count": observed["operator_receipt_count"],
        "tensor_receipt_count": observed["tensor_receipt_count"],
        "model_task_passed": observed["model_task_passed"],
        "formal_result": False,
        "formal_H3_starts": 0,
        "formal_H4_starts": 0,
        "numerical_attention_correctness": None,
        "full_model_quality": None,
        "performance_result": None,
    }


def render(summary):
    return "\n".join(
        [
            "% Generated from the complete real R4 archive; finite nonformal evidence.",
            "\\newcommand{\\ECPAAttentionSourceRecords}{"
            + str(summary["whole_unfiltered_records"])
            + "}",
            "\\newcommand{\\ECPAAttentionWorkerClosures}{"
            + str(summary["source_close_records"])
            + "}",
            "\\newcommand{\\ECPAAttentionCompletionReceipts}{"
            + str(summary["operator_receipt_count"])
            + "}",
            "",
        ]
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, help="fresh external output directory")
    args = parser.parse_args()
    if args.check == bool(args.output):
        parser.error("choose --check or --output")
    output = None if args.check else new_output(args.output)
    root = Path(__file__).resolve().parents[2]
    summary = derive(root)
    outputs = {
        root / "paper/generated/attention-source-summary.tex": render(summary),
        root
        / "paper/artifacts/attention-source-drain-r4/source-binding.json": json.dumps(
            summary, sort_keys=True, indent=2
        )
        + "\n",
    }
    for path, text in outputs.items():
        if args.check:
            path = resolve_original(path)
            if not path.is_file() or path.read_text() != text:
                raise ValueError("generated R4 paper output differs")
        else:
            path = output / path.relative_to(root / "paper")
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("x", encoding="utf-8") as stream:
                stream.write(text)
    print(
        json.dumps(
            {
                k: summary[k]
                for k in (
                    "whole_unfiltered_records",
                    "source_close_records",
                    "operator_receipt_count",
                    "formal_result",
                    "formal_H3_starts",
                    "formal_H4_starts",
                )
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
