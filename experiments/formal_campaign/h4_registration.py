#!/usr/bin/env python3
"""Issue an H4 deployment receipt after live merged-source verification.

This transition authorizes a deployment; it never executes a model server and
never turns prelaunch evidence into an H4 measurement.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from jsonschema import Draft7Validator

HERE = Path(__file__).resolve().parent
ARMS = ("vanilla-vllm-entry-points", "manual-integration", "ecpa")
PHASES = ("discovery", "validation", "planning", "rendering", "evidence_setup")
PROTOCOL_FILES = {
    "analyze.py": "experiments/formal_campaign/analyze.py",
    "h4-deployment-receipt.schema.json": (
        "experiments/formal_campaign/h4-deployment-receipt.schema.json"
    ),
    "h4-raw-artifact.schema.json": (
        "experiments/formal_campaign/h4-raw-artifact.schema.json"
    ),
    "protocol.json": "experiments/formal_campaign/protocol.json",
    "record.schema.json": "experiments/formal_campaign/record.schema.json",
    "run_h4.py": "experiments/formal_campaign/run_h4.py",
}


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load_object(raw: bytes, label: str) -> dict[str, Any]:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def validate_campaign(campaign: dict[str, Any], campaign_path: Path) -> bytes:
    schema = json.loads((HERE / "h4-campaign.schema.json").read_text())
    Draft7Validator(schema).validate(campaign)
    if tuple(row["id"] for row in campaign["arms"]) != ARMS:
        raise ValueError("campaign arms must retain the frozen order")
    schedule = [row["order"] for row in campaign["schedule"]]
    if any(tuple(sorted(row)) != tuple(sorted(ARMS)) for row in schedule):
        raise ValueError("each schedule row must contain every arm exactly once")
    if any(
        len({schedule[row][column] for row in range(3)}) != 3 for column in range(3)
    ):
        raise ValueError("campaign schedule must be a balanced Latin square")
    if campaign["planned_starts"] != len(ARMS) * len(schedule):
        raise ValueError("planned start count differs from the frozen schedule")
    workload_path = (campaign_path.parent / campaign["workload"]["path"]).resolve()
    if not workload_path.is_relative_to(campaign_path.parent.resolve()):
        raise ValueError("workload escapes the campaign directory")
    workload_raw = workload_path.read_bytes()
    if digest(workload_raw) != campaign["workload"]["sha256"]:
        raise ValueError("workload digest differs from the campaign")
    workload = load_object(workload_raw, "workload")
    required = {
        "prompt",
        "max_tokens",
        "warmup_requests",
        "measured_requests",
        "min_successful_measured_requests",
        "concurrency",
        "request_timeout_seconds",
        "success_status",
        "require_nonempty_completion",
    }
    if required - workload.keys():
        raise ValueError("workload lacks required measurement fields")
    if (
        not 0
        < workload["min_successful_measured_requests"]
        <= workload["measured_requests"]
    ):
        raise ValueError("workload success count is impossible")
    return workload_raw


def validate_launch_spec(launch: dict[str, Any]) -> None:
    schema = json.loads((HERE / "h4-launch-spec.schema.json").read_text())
    Draft7Validator(schema).validate(launch)
    served_models: set[str] = set()
    for arm in ARMS:
        definition = launch["arms"][arm]
        served_models.add(definition["served_model"])
        if (
            set(definition.get("unset_environment", []))
            & definition["environment"].keys()
        ):
            raise ValueError(f"{arm} assigns and unsets the same environment variable")
        if set(definition["phase_commands"]) - set(PHASES):
            raise ValueError(f"{arm} has an unknown prelaunch phase")
    if len(served_models) != 1:
        raise ValueError("all H4 arms must use the same served model")
    for key in ("health_url", "endpoint_url"):
        parsed = urlparse(launch[key])
        if parsed.hostname != launch["host"] or parsed.port != launch["port"]:
            raise ValueError(f"{key} differs from the declared host/port")


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True
    ).stdout


def _repository_name(remote_url: str) -> str:
    value = remote_url.removesuffix(".git")
    if ":" in value and "://" not in value:
        value = value.split(":", 1)[1]
    else:
        value = urlparse(value).path
    return value.strip("/")


def observe_merged_source(
    repo: Path, remote: str, expected_repository: str, candidate_commit: str
) -> dict[str, Any]:
    remote_url = _git(repo, "remote", "get-url", remote).decode().strip()
    if _repository_name(remote_url) != expected_repository:
        raise ValueError(f"remote is not {expected_repository}")
    _git(repo, "fetch", "--quiet", remote, "refs/heads/main")
    main_commit = _git(repo, "rev-parse", "FETCH_HEAD").decode().strip()
    try:
        _git(repo, "cat-file", "-e", f"{candidate_commit}^{{commit}}")
    except subprocess.CalledProcessError as exc:
        raise ValueError("candidate commit is not repository-reachable") from exc
    merged = (
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "merge-base",
                "--is-ancestor",
                candidate_commit,
                main_commit,
            ],
            check=False,
        ).returncode
        == 0
    )
    if not merged:
        raise ValueError("candidate commit is not merged to remote main")
    return {
        "repository": expected_repository,
        "remote": remote_url,
        "candidate_commit": candidate_commit,
        "main_commit": main_commit,
    }


def _verify_protocol_binding(campaign: dict[str, Any], manager_repo: Path) -> None:
    binding = campaign.get("protocol_binding")
    if not isinstance(binding, dict) or set(binding) != set(PROTOCOL_FILES) | {
        "manager_commit"
    }:
        raise ValueError("campaign lacks the exact formal protocol binding")
    commit = campaign["fixed_identity"]["manager_commit"]
    if binding["manager_commit"] != commit:
        raise ValueError("protocol binding manager commit differs")
    for label, relative in PROTOCOL_FILES.items():
        try:
            raw = _git(manager_repo, "show", f"{commit}:{relative}")
        except subprocess.CalledProcessError as exc:
            raise ValueError(
                f"protocol artifact is absent at manager commit: {label}"
            ) from exc
        if digest(raw) != binding[label]:
            raise ValueError(f"protocol artifact digest differs: {label}")


def build_receipt(
    *,
    campaign_raw: bytes,
    campaign_path: Path,
    launch_raw: bytes,
    manager_repo: Path,
    manager_source: dict[str, Any],
    host_source: dict[str, Any],
) -> dict[str, Any]:
    campaign = load_object(campaign_raw, "campaign")
    launch = load_object(launch_raw, "launch spec")
    validate_campaign(campaign, campaign_path)
    validate_launch_spec(launch)
    fixed = campaign["fixed_identity"]
    if manager_source["candidate_commit"] != fixed["manager_commit"]:
        raise ValueError("manager source observation differs from campaign")
    if host_source["candidate_commit"] != fixed["host_commit"]:
        raise ValueError("Host source observation differs from campaign")
    _verify_protocol_binding(campaign, manager_repo)
    host_admission = {
        "schema": "ecpa-host-source-admission/v1",
        **host_source,
        "candidate_reachable": True,
        "candidate_merged_to_main": True,
    }
    receipt = {
        "schema": "ecpa-h4-deployment-receipt/v1",
        "registration_state": "registered",
        "admissible": True,
        "evidence_mode": "formal-real",
        "campaign_sha256": digest(campaign_raw),
        "launch_spec_sha256": digest(launch_raw),
        "host_source_admission_sha256": digest(canonical(host_admission)),
        "host_source_admission": host_admission,
        "campaign_id": campaign["campaign_id"],
        "cell_id": campaign["cell_id"],
        "arm_command_digests": {
            arm: digest(canonical(launch["arms"][arm])) for arm in ARMS
        },
        "manager_commit": fixed["manager_commit"],
        "host_commit": fixed["host_commit"],
        "accelerator_commit": fixed["accelerator_commit"],
        "plugin_commits": {
            name: item["commit"] for name, item in fixed["plugins"].items()
        },
        "model_digest": fixed["model_digest"],
        "workload_digest": campaign["workload"]["sha256"],
        "hardware": fixed["hardware"],
        "topology": fixed["topology"],
        "issuer": {
            "kind": "ecpa-h4-registration-transition/v1",
            "manager_repository": manager_source["repository"],
            "manager_remote": manager_source["remote"],
            "host_repository": host_source["repository"],
            "host_remote": host_source["remote"],
            "manager_main_commit": manager_source["main_commit"],
            "host_main_commit": host_source["main_commit"],
        },
    }
    schema = json.loads((HERE / "h4-deployment-receipt.schema.json").read_text())
    Draft7Validator(schema).validate(receipt)
    return receipt


def atomic_write_new(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if path.exists():
            raise FileExistsError(f"refusing to replace existing receipt: {path}")
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(canonical(value) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--launch-spec", type=Path, required=True)
    parser.add_argument("--manager-repo", type=Path, required=True)
    parser.add_argument("--manager-remote", default="origin")
    parser.add_argument("--host-repo", type=Path, required=True)
    parser.add_argument("--host-remote", default="origin")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    campaign_raw = args.campaign.read_bytes()
    campaign = load_object(campaign_raw, "campaign")
    fixed = campaign.get("fixed_identity", {})
    manager_source = observe_merged_source(
        args.manager_repo,
        args.manager_remote,
        "vLLM-HUST/extension-manager",
        fixed.get("manager_commit", ""),
    )
    host_source = observe_merged_source(
        args.host_repo,
        args.host_remote,
        "vLLM-HUST/vllm-hust",
        fixed.get("host_commit", ""),
    )
    receipt = build_receipt(
        campaign_raw=campaign_raw,
        campaign_path=args.campaign,
        launch_raw=args.launch_spec.read_bytes(),
        manager_repo=args.manager_repo,
        manager_source=manager_source,
        host_source=host_source,
    )
    atomic_write_new(args.output, receipt)
    print(
        json.dumps(
            {
                "receipt": str(args.output),
                "sha256": digest(args.output.read_bytes()),
                "registration_state": "registered",
                "admissible": True,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
