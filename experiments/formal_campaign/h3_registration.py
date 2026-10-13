#!/usr/bin/env python3
"""Issue one H3 deployment receipt from merged sources and reviewed authority."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from jsonschema import Draft7Validator

HERE = Path(__file__).resolve().parent
ARMS = ("vanilla-vllm-entry-points", "manual-integration", "ecpa")
PROTOCOL_FILES = {
    name: f"experiments/formal_campaign/{name}"
    for name in (
        "analyze.py",
        "h3_phase_barrier.py",
        "h3_authority_chain.py",
        "h3_native_prepare.py",
        "h3-authority-registration.schema.json",
        "h3-campaign.schema.json",
        "h3-deployment-receipt.schema.json",
        "h3-raw-artifact.schema.json",
        "h3_registration.py",
        "protocol.json",
        "record.schema.json",
        "run_h3.py",
    )
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


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True
    ).stdout


def _repository_name(remote_url: str) -> str:
    value = remote_url.removesuffix(".git")
    value = (
        value.split(":", 1)[1]
        if ":" in value and "://" not in value
        else urlparse(value).path
    )
    return value.strip("/")


def observe_merged_source(
    repo: Path, remote: str, repository: str, candidate: str
) -> dict[str, str]:
    remote_url = _git(repo, "remote", "get-url", remote).decode().strip()
    if _repository_name(remote_url) != repository:
        raise ValueError(f"remote is not {repository}")
    _git(repo, "fetch", "--quiet", remote, "refs/heads/main")
    main = _git(repo, "rev-parse", "FETCH_HEAD").decode().strip()
    try:
        _git(repo, "cat-file", "-e", f"{candidate}^{{commit}}")
    except subprocess.CalledProcessError as exc:
        raise ValueError("candidate commit is not repository-reachable") from exc
    merged = (
        subprocess.run(
            ["git", "-C", str(repo), "merge-base", "--is-ancestor", candidate, main],
            check=False,
        ).returncode
        == 0
    )
    if not merged:
        raise ValueError("candidate commit is not merged to remote main")
    return {
        "repository": repository,
        "remote": remote_url,
        "candidate_commit": candidate,
        "main_commit": main,
    }


def command_digest(argv: list[str]) -> str:
    return digest(canonical({"argv": argv}))


def _validate_campaign(campaign: dict[str, Any]) -> None:
    Draft7Validator(
        json.loads((HERE / "h3-campaign.schema.json").read_text())
    ).validate(campaign)
    if tuple(row["id"] for row in campaign["arms"]) != ARMS:
        raise ValueError("campaign arms must retain the frozen order")
    if "prepare" in campaign["cell_id"]:
        for arm in campaign["arms"]:
            if "phase_barrier" not in arm:
                raise ValueError(
                    "prepare campaign must retain every arm support declaration"
                )
            phase = arm["phase_barrier"]
            if phase["support"] == "supported" and arm["id"] != "ecpa":
                raise ValueError(
                    "baseline requires its own native protocol; ECPA adapter forbidden"
                )
    fixed = campaign["fixed_identity"]
    required = {
        "manager_commit",
        "host_commit",
        "accelerator_commit",
        "plugin_commits",
        "model_digest",
        "workload_digest",
        "hardware",
        "topology",
    }
    if required - fixed.keys():
        raise ValueError("campaign lacks exact stack identity")
    health = urlparse(campaign["probe"]["health_url"])
    request = urlparse(campaign["probe"]["request_url"])
    if health.hostname != "127.0.0.1" or (health.hostname, health.port) != (
        request.hostname,
        request.port,
    ):
        raise ValueError("H3 probes must share one loopback authority endpoint")


def _validate_authority(
    authority: dict[str, Any],
    campaign: dict[str, Any],
    campaign_sha: str,
    manager_repo: Path,
) -> None:
    Draft7Validator(
        json.loads((HERE / "h3-authority-registration.schema.json").read_text())
    ).validate(authority)
    if authority["campaign_sha256"] != campaign_sha:
        raise ValueError("authority registration is not bound to campaign")
    probe = campaign["probe"]
    if authority["state_command_digest"] != command_digest(probe["state_command"]):
        raise ValueError("authority state command differs from campaign")
    if authority["cleanup_command_digest"] != command_digest(probe["cleanup_command"]):
        raise ValueError("authority cleanup command differs from campaign")
    endpoint = urlparse(authority["authority_endpoint"])
    request = urlparse(probe["request_url"])
    if (endpoint.hostname, endpoint.port) != (request.hostname, request.port):
        raise ValueError("authority endpoint differs from campaign")
    expected = {
        (f"{campaign['cell_id']}-r{rep}-{arm}", arm, rep)
        for rep in range(1, 4)
        for arm in ARMS
    }
    observed = {
        (row["start_id"], row["arm"], row["repetition"]) for row in authority["starts"]
    }
    if observed != expected or len(observed) != 9:
        raise ValueError("authority registration does not cover nine unique starts")
    proxy_source = (
        manager_repo / "experiments/exposure_gate/loopback_traffic.py"
    ).resolve()
    source_sha = digest(proxy_source.read_bytes())
    for row in authority["starts"]:
        registration = row["proxy_registration"]
        if digest(canonical(registration)) != row["proxy_registration_sha256"]:
            raise ValueError(f"proxy registration digest differs: {row['start_id']}")
        if (
            registration["proxy_source_sha256"] != source_sha
            or registration["public_port"] != request.port
        ):
            raise ValueError(f"proxy source or endpoint differs: {row['start_id']}")
        run_dir = Path(row["run_directory"])
        source = proxy_source
        argv = [
            str(Path(sys.executable).resolve()),
            str(source),
            "--socket",
            str(run_dir / "authority.sock"),
            "--journal",
            str(run_dir / "authority-journal.jsonl"),
            "--listen-port",
            str(registration["public_port"]),
            "--predecessor-port",
            str(registration["predecessor_port"]),
            "--candidate-port",
            str(registration["backend_port"]),
            "--predecessor-snapshot",
            '{"generation":0}',
            "--grant-holder",
            registration["grant_holder"],
            "--grant-token",
            str(registration["grant_token"]),
            "--grant-expires-at",
            str(registration["grant_expires_at"]),
            "--observer-config",
            str(run_dir / "formal-proxy-authorization.json"),
        ]
        if command_digest(argv) != registration["proxy_command_digest"]:
            raise ValueError(f"proxy command differs: {row['start_id']}")
    subject = {key: value for key, value in authority.items() if key != "review"}
    if authority["review"]["subject_sha256"] != digest(canonical(subject)):
        raise ValueError("authority review subject digest differs")


def _verify_protocol_binding(campaign: dict[str, Any], manager_repo: Path) -> None:
    binding = campaign.get("protocol_binding")
    if not isinstance(binding, dict) or set(binding) != set(PROTOCOL_FILES) | {
        "manager_commit"
    }:
        raise ValueError("campaign lacks exact formal protocol binding")
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
    authority_raw: bytes,
    manager_repo: Path,
    manager_source: dict[str, str],
    host_source: dict[str, str],
) -> dict[str, Any]:
    campaign = load_object(campaign_raw, "campaign")
    authority = load_object(authority_raw, "authority registration")
    _validate_campaign(campaign)
    campaign_sha = digest(campaign_raw)
    _validate_authority(authority, campaign, campaign_sha, manager_repo)
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
        "schema": "ecpa-h3-deployment-receipt/v2",
        "registration_state": "registered",
        "admissible": True,
        "evidence_mode": "formal-real",
        "campaign_sha256": campaign_sha,
        "authority_registration_sha256": digest(authority_raw),
        "host_source_admission_sha256": digest(canonical(host_admission)),
        "host_source_admission": host_admission,
        "campaign_id": campaign["campaign_id"],
        "cell_id": campaign["cell_id"],
        "arm_command_digests": {
            row["id"]: command_digest(row["launch_command"]) for row in campaign["arms"]
        },
        "fault_command_digest": digest(canonical(campaign["fault"])),
        "state_command_digest": command_digest(campaign["probe"]["state_command"]),
        "cleanup_command_digest": command_digest(campaign["probe"]["cleanup_command"]),
        **{
            key: fixed[key]
            for key in (
                "manager_commit",
                "host_commit",
                "accelerator_commit",
                "plugin_commits",
                "model_digest",
                "workload_digest",
                "hardware",
                "topology",
            )
        },
        "authority": {
            "kind": "host-plus-independent-loopback-proxy",
            "parent_process_registration": True,
            "exposure_gate": True,
            "endpoint": authority["authority_endpoint"],
            "start_proxy_registration_digests": {
                row["start_id"]: row["proxy_registration_sha256"]
                for row in authority["starts"]
            },
        },
        "issuer": {
            "kind": "ecpa-h3-registration-transition/v1",
            "manager_repository": manager_source["repository"],
            "manager_remote": manager_source["remote"],
            "host_repository": host_source["repository"],
            "host_remote": host_source["remote"],
            "manager_main_commit": manager_source["main_commit"],
            "host_main_commit": host_source["main_commit"],
        },
    }
    Draft7Validator(
        json.loads((HERE / "h3-deployment-receipt.schema.json").read_text())
    ).validate(receipt)
    return receipt


def atomic_write_new(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_suffix(path.suffix + ".lock").open("a+b") as lock:
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
    parser.add_argument("--authority-registration", type=Path, required=True)
    parser.add_argument("--manager-repo", type=Path, required=True)
    parser.add_argument("--manager-remote", default="origin")
    parser.add_argument("--host-repo", type=Path, required=True)
    parser.add_argument("--host-remote", default="origin")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    campaign_raw = args.campaign.read_bytes()
    campaign = load_object(campaign_raw, "campaign")
    fixed = campaign.get("fixed_identity", {})
    manager = observe_merged_source(
        args.manager_repo,
        args.manager_remote,
        "vLLM-HUST/extension-manager",
        fixed.get("manager_commit", ""),
    )
    host = observe_merged_source(
        args.host_repo,
        args.host_remote,
        "vLLM-HUST/vllm-hust",
        fixed.get("host_commit", ""),
    )
    receipt = build_receipt(
        campaign_raw=campaign_raw,
        authority_raw=args.authority_registration.read_bytes(),
        manager_repo=args.manager_repo,
        manager_source=manager,
        host_source=host,
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
