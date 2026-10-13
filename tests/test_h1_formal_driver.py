from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path("experiments/false_effective").resolve()
sys.path.insert(0, str(ROOT))

import h1_formal_driver as driver  # noqa: E402
from harness import LATIN_SQUARE, canonical  # noqa: E402


def _schedule():
    return tuple(
        {
            "start": (repetition - 1) * 3 + order,
            "repetition": repetition,
            "arm_order": order,
            "arm": arm,
        }
        for repetition, row in enumerate(LATIN_SQUARE, 1)
        for order, arm in enumerate(row, 1)
    )


def _campaign(tmp_path: Path):
    event = tmp_path / "events"
    quarantine = tmp_path / "quarantine"
    event.mkdir(mode=0o700)
    quarantine.mkdir(mode=0o700)
    workspace = {
        "event_dir": str(event),
        "event_directory_identity": {
            "device": event.stat().st_dev,
            "inode": event.stat().st_ino,
        },
        "quarantine_dir": str(quarantine),
        "quarantine_directory_identity": {
            "device": quarantine.stat().st_dev,
            "inode": quarantine.stat().st_ino,
        },
    }
    arms = {}
    classes = {
        "vanilla-vllm-entry-points": "VanillaVLLMAdapter",
        "manual-integration": "ManualIntegrationAdapter",
        "ecpa": "ECPAAdapter",
    }
    for arm, adapter in classes.items():
        arms[arm] = {
            "workspace": workspace,
            "runner_arguments": {
                "adapter": adapter,
                "adapter_verification_id": f"registered-{arm}",
                "executable": "/bin/true",
                "arguments": [],
                "observer_executable": "/bin/true",
                "observer_arguments": [],
                "manager_executable": "/bin/true" if arm == "ecpa" else None,
                "execution_plan_path": "/plan.json",
                "host_event_dir": str(event),
                "timeout_s": 1,
            },
            "lifecycle_fact_commands": {
                phase: {"executable": "/bin/true", "arguments": [phase]}
                for phase in (
                    "service-ready",
                    "workload-complete",
                    "fault-injected",
                    "observer-captured",
                    "service-shutdown",
                )
            },
        }
    return driver.Campaign(
        study={},
        deployment={},
        registry={},
        matrix={},
        candidate={"environment": {"ECPA_TEST_FROZEN": "1"}, "declared_identity": {}},
        scenario={"id": "partial-worker-coverage"},
        protocol={},
        schedule=_schedule(),
        arms=arms,
    )


def test_current_registered_files_validate_for_launch():
    campaign = driver.validate_registration()
    assert campaign.study["status"] == "admitted"
    assert campaign.study["admissible"] is True
    assert campaign.deployment["registration_state"] == "registered"
    assert set(campaign.arms) == set(campaign.study["arms"])
    assert len(campaign.schedule) == 9


def test_explicit_pre_admission_fixture_cannot_launch(tmp_path):
    study_path = tmp_path / "first-formal-real-study.json"
    deployment_path = tmp_path / "first-formal-real-deployment.json"
    registry_path = tmp_path / "verified-adapters.json"
    matrix_path = tmp_path / "claims-to-experiment-matrix.json"
    for source, target in (
        (driver.STUDY_PATH, study_path),
        (driver.DEPLOYMENT_PATH, deployment_path),
        (driver.REGISTRY_PATH, registry_path),
        (driver.MATRIX_PATH, matrix_path),
    ):
        shutil.copy2(source, target)
    study = json.loads(study_path.read_text())
    study["status"] = "pre-admission"
    study["admissible"] = False
    study_path.write_bytes(canonical(study) + b"\n")

    with pytest.raises(ValueError, match="not admitted"):
        driver.validate_registration(
            study_path=study_path,
            deployment_path=deployment_path,
            registry_path=registry_path,
            matrix_path=matrix_path,
        )


def test_workspace_cleanup_preserves_directory_inodes_and_rejects_unknown(tmp_path):
    campaign = _campaign(tmp_path)
    arm = campaign.arms["ecpa"]
    event = Path(arm["workspace"]["event_dir"])
    quarantine = Path(arm["workspace"]["quarantine_dir"])
    identities = (event.stat().st_ino, quarantine.stat().st_ino)
    (event / ("a" * 64 + ".jsonl")).write_text("event\n")
    plan = event / (".ecpa-plan-" + "b" * 32)
    plan.mkdir()
    (plan / "plan.json").write_text("{}\n")
    plan.chmod(0o500)
    (quarantine / ("c" * 64 + ".jsonl")).write_text("event\n")
    (quarantine / ("ecpa-" + "d" * 64 + ".finalized.json")).write_text("{}\n")
    driver.clear_launch_workspace(arm)
    assert not list(event.iterdir())
    assert not list(quarantine.iterdir())
    assert identities == (event.stat().st_ino, quarantine.stat().st_ino)

    (event / "unrecognized.txt").write_text("retain")
    with pytest.raises(ValueError, match="unexpected campaign artifact"):
        driver.clear_launch_workspace(arm)
    assert (event / "unrecognized.txt").read_text() == "retain"


def test_driver_resumes_prefix_runs_latin_order_and_retains_failures(
    tmp_path, monkeypatch
):
    campaign = _campaign(tmp_path)
    monkeypatch.setattr(
        driver, "validate_registration", lambda *_args, **_kwargs: campaign
    )
    prior = [
        {
            "start_id": f"prior-{index}",
            "status": "complete",
            "arm": row["arm"],
        }
        for index, row in enumerate(campaign.schedule[:2], 1)
    ]
    monkeypatch.setattr(
        driver, "_load_existing_records", lambda *_args, **_kwargs: list(prior)
    )
    monkeypatch.setattr(driver, "clear_launch_workspace", lambda _arm: None)
    called = []
    published = []

    def fake_start(
        _root, scenario, _protocol, adapter, repetition, arm_order, **kwargs
    ):
        called.append((repetition, arm_order, adapter.arm, kwargs))
        position = len(called) + 2
        status = "failed" if position == 4 else "complete"
        record = {
            "start_id": f"start-{position}",
            "status": status,
            "arm": adapter.arm,
        }
        path = tmp_path / "output" / "starts" / record["start_id"]
        path.mkdir(parents=True)
        (path / "record.json").write_bytes(canonical(record) + b"\n")
        return record

    def fake_publish(_root, records):
        published.append([dict(row) for row in records])
        return _root / "formal-record-index.json"

    records = driver.run_campaign(
        tmp_path / "output", run_start=fake_start, publish=fake_publish
    )
    assert [(r, o, arm) for r, o, arm, _ in called] == [
        (row["repetition"], row["arm_order"], row["arm"])
        for row in campaign.schedule[2:]
    ]
    assert len(records) == 9
    assert records[3]["status"] == "failed"
    assert json.loads(
        (tmp_path / "output/starts/start-4/record.json").read_text()
    )["status"] == "failed"
    assert [len(rows) for rows in published] == list(range(2, 10))
    assert all(
        set(call[3]["lifecycle_fact_commands"])
        == {
            "service-ready",
            "workload-complete",
            "fault-injected",
            "observer-captured",
            "service-shutdown",
        }
        for call in called
    )


def test_interrupted_start_directory_is_retained_and_blocks_resume(tmp_path):
    campaign = _campaign(tmp_path)
    root = tmp_path / "output"
    interrupted = root / "starts/partial-worker-coverage-r1-vanilla-vllm-entry-points"
    interrupted.mkdir(parents=True)
    marker = interrupted / "stderr.bin"
    marker.write_bytes(b"failure")
    with pytest.raises(ValueError, match="interrupted start is retained"):
        driver._load_existing_records(root, campaign)
    assert marker.read_bytes() == b"failure"
