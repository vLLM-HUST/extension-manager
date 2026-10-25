"""Actual original full8 ownership + full14 model reads + Host tokenizer replay."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import sysconfig
from pathlib import Path

from .conditional_common import canonical, reference, require, sha, write

OWNERSHIP_PATH = Path(
    "/root/ecpa-workspace/management/h3-isolated-host-runtime-candidate-20"
    "261017/runtime_owned_path_mapping.py"
)
OWNERSHIP_SHA = "32900509aa288d1d1a30b2fe2ef54c53d6d55a67b053d83b9d1d81ffd5530449"


def audit_actual(inputs, campaign, workload, phase, output):

    from experiments.native_attention_candidate import live_route_reader as routes

    require(
        sha(OWNERSHIP_PATH.read_bytes()) == OWNERSHIP_SHA,
        "original independently reviewed ownership guard changed",
    )
    spec = importlib.util.spec_from_file_location(
        "conditional_original_owned_runtime", OWNERSHIP_PATH
    )
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    payloads = inputs["whole_runtime_payloads"]

    def normalized(value):
        return value.replace("_", "-").lower()

    expected = {
        normalized(row["distribution"]) for row in inputs["runtime_wheels"].values()
    } | {"torch", "torch-npu", "triton-ascend"}
    require(
        len(payloads) == 8
        and len(expected) == 8
        and {normalized(v["distribution"]) for v in payloads.values()} == expected,
        "all actual eight distributions including both source-owned policies required",
    )
    from vllm_hust_ext.discovery import discover_bundles

    modules = {
        "org.vllm-hust.pipeline-microbatch": "vllm_hust_pipeline_microbatch",
        "org.vllm-hust.bidkv": "bidkv",
    }
    for bundle in discover_bundles(tuple(sorted(modules))):
        source = inputs["runtime_wheels"]["plugin:" + bundle.bundle_id]
        require(
            normalized(source["distribution"]) == normalized(bundle.distribution_name)
            and source["module"] == modules[bundle.bundle_id],
            "policy bundle/source/wheel distribution ownership differs",
        )
    require(
        sys.flags.optimize == 0, "original ownership assertion guard must be active"
    )
    site = Path(sysconfig.get_paths()["purelib"])
    require(
        site.is_relative_to(Path(sys.prefix)),
        "actual private runtime site escapes prefix",
    )
    owned = helper.fresh_runtime_ownership(payloads, site)
    states = {}
    models = routes._model_inventory(inputs["model_files"], states)
    require(
        len(models) == 14
        and "sha256:" + sha(canonical(models))
        == campaign["fixed_identity"]["model_digest"],
        "full original model inventory changed",
    )
    from .analyze import h4_request_payload

    payload = json.loads(h4_request_payload(workload, phase["served_model"]))
    document = dict(
        payload=payload,
        host_arguments=[
            "serve",
            "--disable-ecpa-manager",
            "--enable-entrypoints",
            *phase["host_argv"][4:],
        ],
    )
    command = [
        phase["python"],
        "-B",
        "-m",
        "experiments.formal_campaign.h4_sampled_calibration",
        "--tokenizer-worker",
    ]
    result = subprocess.run(
        command,
        input=canonical(document),
        capture_output=True,
        cwd=phase["cwd"],
        env=phase["environment"],
        timeout=120,
        check=False,
    )
    out = Path(output)
    (out / "actual-tokenizer.stdout").write_bytes(result.stdout)
    (out / "actual-tokenizer.stderr").write_bytes(result.stderr)
    write(
        out / "actual-tokenizer-command.json",
        dict(argv=command, input=document, returncode=result.returncode),
    )
    require(
        result.returncode == 0, "actual Host/CompletionRequest tokenizer replay failed"
    )
    tokens = json.loads(result.stdout)
    require(
        canonical(tokens) + b"\n" == result.stdout
        and len(tokens["input_ids"]) == tokens["prompt_token_count"] == 1195
        and tokens["request_sha256"] == sha(canonical(payload))
        and tokens["input_ids_sha256"] == sha(canonical(tokens["input_ids"]))
        and tokens["input_ids_sha256"] == inputs["prompt_input_ids_sha256"],
        "actual original1195 full token IDs differ",
    )
    for path, state in states.items():
        require(
            routes._state(Path(path).stat()) == state,
            "model/tokenizer changed across actual replay",
        )
    write(out / "actual-tokenizer.json", tokens)
    value = dict(
        schema="ecpa-h4-conditional-full-input-audit/v1",
        model_files=models,
        file_states=states,
        whole8_owned_payload=owned,
        actual_tokenizer=reference(out / "actual-tokenizer.json"),
        original_guard=dict(path=str(OWNERSHIP_PATH), sha256=OWNERSHIP_SHA),
    )
    write(out / "actual-input-audit.json", value)
    return value


def recheck_actual(value):
    from experiments.native_attention_candidate import live_route_reader as routes

    for path, state in value["file_states"].items():
        require(
            routes._state(Path(path).stat()) == state,
            "original model/tokenizer input state changed during actual run",
        )
