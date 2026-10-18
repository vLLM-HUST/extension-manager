"""Derive NEW unqualified bundle manifests from actual future Host build report.

Reads no wheel payload and grants no launch/qualification. Old manifests stay
immutable; candidates must be independently reviewed/published/built, followed
by fresh actual wheel/installed/source and the real unregistered experiment.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(
    "/root/ecpa-workspace/worktrees/ecpa-manager-h3-live-scoped-next/exper"
    "iments/real_mod_composition/artifacts/h2-pipeline-bidkv-oracle-20261013"
)


def checked(path, digest):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest.removeprefix("sha256:"):
        raise ValueError("actual build report changed")
    return json.loads(raw)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host-build-report", type=Path, required=True)
    p.add_argument("--host-build-sha256", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    report = checked(a.host_build_report, a.host_build_sha256)
    if report["exit_code"] != 0 or report["payload_audit_pass"] is not True:
        raise ValueError("actual official Host build required")
    host_commit = report["official_commit"]
    host_tree = report.get("tree", report.get("source_tree"))
    if not isinstance(host_tree, str) or len(host_tree) != 40 or len(host_commit) != 40:
        raise ValueError("actual official source commit/tree required")
    wheels = report["wheels"]
    if len(wheels) != 1 or not wheels[0]["version"].startswith("0.31."):
        raise ValueError("one actual Host0.31 artifact required")
    os.umask(0o077)
    a.output.mkdir(mode=0o700, exist_ok=False)
    a.output.chmod(0o700)
    campaign = json.loads((ROOT / "campaign.json").read_bytes())
    for name, leaf in [
        ("pipeline_microbatch", "pipeline-manifest.json"),
        ("bidkv", "bidkv-manifest.json"),
    ]:
        raw = (ROOT / "snapshots" / leaf).read_bytes()
        original = campaign["sources"][name]
        if hashlib.sha256(raw).hexdigest() != original["sha256"].removeprefix(
            "sha256:"
        ):
            raise ValueError("old independent declaration changed")
        value = copy.deepcopy(json.loads(raw))
        value["extension_version"] += ".dev1"
        value["schema_version"] = "0.3-experimental"
        if name == "pipeline_microbatch":
            value["resource_claims"] = [
                dict(
                    resource="vllm.scheduler.batch-admission-policy",
                    scope="vllm-process",
                    mode="exclusive",
                )
            ]
        value["host"]["version_range"] = "==" + wheels[0]["version"]
        # No broad >=0.31,<0.32 assertion; original protocols/components/claims
        # remain unchanged and are independently checked by the future adapter.
        value.setdefault("activation", {}).setdefault("additional_config", {})[
            "_manager_runtime_qualification"
        ] = dict(
            domain="new-H4-conditional-scheduler-PP2-TP1",
            host_commit=host_commit,
            host_tree=host_tree,
            model=a.model,
            pipeline_parallel_size=2,
            tensor_parallel_size=1,
            max_num_seqs=1,
            warmup_requests=16,
            measured_requests=256,
            selected_requests=32,
        )
        with (a.output / (name + "-unqualified-manifest.json")).open("x") as out:
            json.dump(value, out, sort_keys=True, indent=2)
            out.write("\n")
    with (a.output / "declaration-only.json").open("x") as out:
        json.dump(
            dict(
                actual_Host_report=dict(
                    path=str(a.host_build_report), sha256=a.host_build_sha256
                ),
                prior_oracle_is_historical_only=True,
                runtime_qualification=None,
                deployment_receipt=None,
                published_or_installed=False,
                formal_result=False,
            ),
            out,
            indent=2,
        )


if __name__ == "__main__":
    main()
