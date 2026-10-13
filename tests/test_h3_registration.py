from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "experiments/formal_campaign/h3_registration.py"


def load_registration():
    spec = importlib.util.spec_from_file_location("h3_registration_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fixture(module, tmp_path: Path):
    cell = "manager-crash-after-prepare"
    identity = {
        "manager_commit": "1" * 40,
        "host_commit": "2" * 40,
        "accelerator_commit": "3" * 40,
        "plugin_commits": {"mod": "4" * 40},
        "model_digest": "sha256:" + "5" * 64,
        "workload_digest": "sha256:" + "6" * 64,
        "hardware": "2x Ascend 910B2",
        "topology": "TP2",
    }
    arms = [
        {
            "id": arm,
            "launch_command": ["launch", arm],
            "fault_target_pid_file": f"/{arm}.pid",
        }
        for arm in module.ARMS
    ]
    campaign = {
        "schema": "ecpa-h3-exact-stack-cell-campaign/v1",
        "campaign_id": "H3-transactional-recovery-v1",
        "cell_id": cell,
        "evidence_class": "formal-real",
        "arms": arms,
        "fixed_identity": identity,
        "protocol_binding": {
            "manager_commit": identity["manager_commit"],
            **{name: "sha256:" + "7" * 64 for name in module.PROTOCOL_FILES},
        },
        "fault": {
            "id": "kill-manager",
            "signal": "SIGKILL",
            "target_role": "manager",
            "target_exit_timeout_s": 5,
        },
        "objective": {
            "max_recovery_ms": 1000,
            "max_lost_requests": 0,
            "max_duplicated_requests": 0,
            "max_operator_actions": 0,
            "expected_final_route": "predecessor",
            "allowed_rollback_classifications": ["automatic-restoration"],
        },
        "probe": {
            "health_url": "http://127.0.0.1:8187/health",
            "request_url": "http://127.0.0.1:8187/request",
            "request_count": 1,
            "state_command": ["state"],
            "cleanup_command": ["cleanup"],
            "ready_timeout_s": 5,
            "request_timeout_s": 5,
        },
    }
    campaign_raw = json.dumps(campaign, sort_keys=True).encode() + b"\n"
    proxy_source = ROOT / "experiments/exposure_gate/loopback_traffic.py"
    source_sha = module.digest(proxy_source.read_bytes())
    starts = []
    for rep in range(1, 4):
        for arm in module.ARMS:
            start_id = f"{cell}-r{rep}-{arm}"
            run_dir = (tmp_path / start_id).resolve()
            proxy = {
                "schema": "ecpa-formal-proxy-registration/v1",
                "evidence_class": "formal-real",
                "authority": "independent-loopback-proxy",
                "proxy_command_digest": "",
                "review_receipt_sha256": "sha256:" + "8" * 64,
                "reviewer_kind": "automated-independent",
                "proxy_source_sha256": source_sha,
                "public_port": 8187,
                "backend_port": 18187,
                "predecessor_port": 28187,
                "grant_holder": "runner",
                "grant_token": rep,
                "grant_expires_at": 4102444800,
            }
            argv = [
                str(Path(sys.executable).resolve()),
                str(proxy_source.resolve()),
                "--socket",
                str(run_dir / "authority.sock"),
                "--journal",
                str(run_dir / "authority-journal.jsonl"),
                "--listen-port",
                "8187",
                "--predecessor-port",
                "28187",
                "--candidate-port",
                "18187",
                "--predecessor-snapshot",
                '{"generation":0}',
                "--grant-holder",
                "runner",
                "--grant-token",
                str(rep),
                "--grant-expires-at",
                "4102444800",
                "--observer-config",
                str(run_dir / "formal-proxy-authorization.json"),
            ]
            proxy["proxy_command_digest"] = module.command_digest(argv)
            starts.append(
                {
                    "start_id": start_id,
                    "arm": arm,
                    "repetition": rep,
                    "run_directory": str(run_dir),
                    "proxy_registration": proxy,
                    "proxy_registration_sha256": module.digest(module.canonical(proxy)),
                }
            )
    authority = {
        "schema": "ecpa-h3-authority-registration/v1",
        "registration_state": "reviewed",
        "evidence_class": "formal-real",
        "campaign_sha256": module.digest(campaign_raw),
        "authority_endpoint": "http://127.0.0.1:8187/request",
        "state_command_digest": module.command_digest(["state"]),
        "cleanup_command_digest": module.command_digest(["cleanup"]),
        "starts": starts,
    }
    authority["review"] = {
        "reviewer_kind": "automated-independent",
        "verdict": "APPROVED",
        "subject_sha256": module.digest(module.canonical(authority)),
    }
    return campaign_raw, module.canonical(authority) + b"\n", identity


def source(repository: str, candidate: str) -> dict[str, str]:
    return {
        "repository": repository,
        "remote": f"https://github.com/{repository}.git",
        "candidate_commit": candidate,
        "main_commit": candidate,
    }


def test_build_receipt_binds_commands_authority_and_merged_sources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = load_registration()
    campaign_raw, authority_raw, identity = fixture(module, tmp_path)
    monkeypatch.setattr(module, "_verify_protocol_binding", lambda *_: None)
    receipt = module.build_receipt(
        campaign_raw=campaign_raw,
        authority_raw=authority_raw,
        manager_repo=ROOT,
        manager_source=source(
            "vLLM-HUST/extension-manager", identity["manager_commit"]
        ),
        host_source=source("vLLM-HUST/vllm-hust", identity["host_commit"]),
    )
    assert receipt["schema"] == "ecpa-h3-deployment-receipt/v2"
    assert receipt["authority_registration_sha256"] == module.digest(authority_raw)
    assert len(receipt["authority"]["start_proxy_registration_digests"]) == 9


def test_authority_registration_rejects_replay_or_command_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = load_registration()
    campaign_raw, authority_raw, identity = fixture(module, tmp_path)
    monkeypatch.setattr(module, "_verify_protocol_binding", lambda *_: None)
    authority = json.loads(authority_raw)
    authority["starts"][0]["start_id"] = authority["starts"][1]["start_id"]
    authority["review"]["subject_sha256"] = module.digest(
        module.canonical({k: v for k, v in authority.items() if k != "review"})
    )
    with pytest.raises(ValueError, match="nine unique starts"):
        module.build_receipt(
            campaign_raw=campaign_raw,
            authority_raw=module.canonical(authority) + b"\n",
            manager_repo=ROOT,
            manager_source=source(
                "vLLM-HUST/extension-manager", identity["manager_commit"]
            ),
            host_source=source("vLLM-HUST/vllm-hust", identity["host_commit"]),
        )


def test_live_source_observation_rejects_unmerged_commit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = load_registration()
    candidate = "1" * 40

    def fake_git(repo: Path, *args: str) -> bytes:
        if args == ("remote", "get-url", "origin"):
            return b"https://github.com/vLLM-HUST/vllm-hust.git\n"
        if args[:2] == ("fetch", "--quiet"):
            return b""
        if args == ("rev-parse", "FETCH_HEAD"):
            return ("2" * 40 + "\n").encode()
        if args == ("cat-file", "-e", f"{candidate}^{{commit}}"):
            return b""
        raise AssertionError(args)

    monkeypatch.setattr(module, "_git", fake_git)

    class Result:
        returncode = 1

    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: Result())
    with pytest.raises(ValueError, match="not merged to remote main"):
        module.observe_merged_source(
            tmp_path, "origin", "vLLM-HUST/vllm-hust", candidate
        )


def test_atomic_issuer_refuses_receipt_replacement(tmp_path: Path) -> None:
    module = load_registration()
    output = tmp_path / "receipt.json"
    module.atomic_write_new(output, {"first": True})
    with pytest.raises(FileExistsError, match="refusing to replace"):
        module.atomic_write_new(output, {"second": True})
    assert json.loads(output.read_text()) == {"first": True}
