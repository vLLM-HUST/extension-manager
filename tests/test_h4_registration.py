from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "experiments/formal_campaign/h4_registration.py"
REFREEZE = Path("/root/ecpa-h4-formal-refreeze-20261013")


def external_refreeze_available() -> bool:
    try:
        return REFREEZE.is_dir()
    except OSError:
        return False


def load_registration():
    spec = importlib.util.spec_from_file_location("h4_registration", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def source(repository: str, remote: str, candidate: str, main: str) -> dict[str, str]:
    return {
        "repository": repository,
        "remote": remote,
        "candidate_commit": candidate,
        "main_commit": main,
    }


@pytest.mark.skipif(
    not external_refreeze_available(), reason="exact H4 refreeze is external"
)
def test_exact_refreeze_can_only_build_receipt_from_merged_source_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = load_registration()
    campaign_path = REFREEZE / "campaign.json"
    campaign_raw = campaign_path.read_bytes()
    campaign = json.loads(campaign_raw)
    fixed = campaign["fixed_identity"]
    monkeypatch.setattr(registration, "_verify_protocol_binding", lambda *_: None)
    manager = source(
        "vLLM-HUST/extension-manager",
        "https://github.com/vLLM-HUST/extension-manager.git",
        fixed["manager_commit"],
        fixed["manager_commit"],
    )
    host = source(
        "vLLM-HUST/vllm-hust",
        "https://github.com/vLLM-HUST/vllm-hust.git",
        fixed["host_commit"],
        fixed["host_commit"],
    )
    receipt = registration.build_receipt(
        campaign_raw=campaign_raw,
        campaign_path=campaign_path,
        launch_raw=(REFREEZE / "launch-spec.json").read_bytes(),
        manager_repo=ROOT,
        manager_source=manager,
        host_source=host,
    )
    assert receipt["registration_state"] == "registered"
    assert receipt["admissible"] is True
    assert receipt["host_source_admission"]["candidate_merged_to_main"] is True
    assert receipt["host_source_admission_sha256"] == registration.digest(
        registration.canonical(receipt["host_source_admission"])
    )

    host["candidate_commit"] = "f" * 40
    with pytest.raises(ValueError, match="Host source observation differs"):
        registration.build_receipt(
            campaign_raw=campaign_raw,
            campaign_path=campaign_path,
            launch_raw=(REFREEZE / "launch-spec.json").read_bytes(),
            manager_repo=ROOT,
            manager_source=manager,
            host_source=host,
        )


def test_atomic_transition_refuses_to_replace_receipt(tmp_path: Path) -> None:
    registration = load_registration()
    output = tmp_path / "receipt.json"
    registration.atomic_write_new(output, {"value": 1})
    with pytest.raises(FileExistsError, match="refusing to replace"):
        registration.atomic_write_new(output, {"value": 2})
    assert json.loads(output.read_text()) == {"value": 1}


def test_live_source_observation_fails_closed_when_commit_is_not_merged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    registration = load_registration()
    candidate = "1" * 40
    main = "2" * 40

    def fake_git(repo: Path, *args: str) -> bytes:
        if args == ("remote", "get-url", "origin"):
            return b"https://github.com/vLLM-HUST/vllm-hust.git\n"
        if args[:2] == ("fetch", "--quiet"):
            return b""
        if args == ("rev-parse", "FETCH_HEAD"):
            return (main + "\n").encode()
        if args == ("cat-file", "-e", f"{candidate}^{{commit}}"):
            return b""
        raise AssertionError(args)

    monkeypatch.setattr(registration, "_git", fake_git)

    class Result:
        returncode = 1

    monkeypatch.setattr(registration.subprocess, "run", lambda *a, **k: Result())
    with pytest.raises(ValueError, match="not merged to remote main"):
        registration.observe_merged_source(
            tmp_path, "origin", "vLLM-HUST/vllm-hust", candidate
        )
