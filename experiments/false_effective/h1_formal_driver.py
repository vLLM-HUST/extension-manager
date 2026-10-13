"""Resumable production driver for the registered H1 nine-start campaign."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

import runner  # noqa: E402
from formal_registration_candidate import validate_candidate  # noqa: E402
from harness import LATIN_SQUARE, canonical, validate_record  # noqa: E402
from jsonschema import Draft7Validator  # noqa: E402

STUDY_PATH = HERE / "first-formal-real-study.json"
DEPLOYMENT_PATH = HERE / "first-formal-real-deployment.json"
REGISTRY_PATH = HERE / "verified-adapters.json"
STUDY_SCHEMA_PATH = HERE / "first-formal-real-study.schema.json"
DEPLOYMENT_SCHEMA_PATH = HERE / "first-formal-real-deployment.schema.json"
RAW_RECORD_SCHEMA_PATH = HERE / "raw-record.schema.json"
PROTOCOL_PATH = HERE / "protocol.json"
SCENARIOS_PATH = HERE / "scenarios.json"
MATRIX_PATH = HERE.parents[1] / "docs/research/claims-to-experiment-matrix.json"
MATRIX_SCHEMA_PATH = (
    HERE.parents[1] / "docs/research/claims-to-experiment-matrix.schema.json"
)
DEFAULT_CANDIDATE_PATH = (
    HERE
    / "deployment-candidates"
    / "h1-formal-registration-commands-reviewed-20261013.json"
)

_JOURNAL = re.compile(r"[0-9a-f]{64}\.jsonl\Z")
_SOURCE_FENCE = re.compile(r"\.ecpa-quarantine-[0-9a-f]{64}\.fence\Z")
_PLAN_DIRECTORY = re.compile(r"\.ecpa-plan-[0-9a-f]{32}\Z")
_TRANSACTION = re.compile(
    r"ecpa-[0-9a-f]{64}\.(?:intent|applied|finalized|restored|blocked)\.json\Z"
)
_ALLOWED_LOCK = ".ecpa-quarantine.lock"


@dataclass(frozen=True)
class Campaign:
    study: dict[str, Any]
    deployment: dict[str, Any]
    registry: dict[str, Any]
    matrix: dict[str, Any]
    candidate: dict[str, Any]
    scenario: dict[str, Any]
    protocol: dict[str, Any]
    schedule: tuple[dict[str, Any], ...]
    arms: dict[str, dict[str, Any]]


def _read_canonical(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if raw != canonical(value) + b"\n":
        raise ValueError(f"registration input is not canonical: {path}")
    return value


def _read_document(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"registration input is not an object: {path}")
    return value


def _sha256_hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _schedule(study: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    expected = [list(row) for row in LATIN_SQUARE]
    if study.get("schedule") != expected:
        raise ValueError("official H1 schedule differs from the frozen Latin square")
    return tuple(
        {
            "start": (repetition - 1) * 3 + arm_order,
            "repetition": repetition,
            "arm_order": arm_order,
            "arm": arm,
        }
        for repetition, row in enumerate(expected, 1)
        for arm_order, arm in enumerate(row, 1)
    )


def validate_registration(
    candidate_path: Path = DEFAULT_CANDIDATE_PATH,
    *,
    study_path: Path = STUDY_PATH,
    deployment_path: Path = DEPLOYMENT_PATH,
    registry_path: Path = REGISTRY_PATH,
    matrix_path: Path = MATRIX_PATH,
) -> Campaign:
    """Validate the complete official gate before any launch-side mutation."""
    study = _read_document(study_path)
    deployment = _read_document(deployment_path)
    registry = _read_document(registry_path)
    matrix = _read_document(matrix_path)
    candidate = _read_canonical(candidate_path)
    Draft7Validator(json.loads(STUDY_SCHEMA_PATH.read_text())).validate(study)
    Draft7Validator(json.loads(DEPLOYMENT_SCHEMA_PATH.read_text())).validate(deployment)
    Draft7Validator(json.loads(MATRIX_SCHEMA_PATH.read_text())).validate(matrix)
    validate_candidate(candidate, live=False)
    schedule = _schedule(study)
    if (
        study.get("status") not in {"admitted", "running"}
        or study.get("admissible") is not True
        or study.get("blockers") != []
        or study.get("planned_starts") != 9
        or deployment.get("registration_state") != "registered"
        or deployment.get("admissible") is not True
        or deployment.get("blockers") != []
        or not all(deployment.get("reviews", {}).values())
        or not isinstance(deployment.get("producer_admission_receipt"), dict)
    ):
        raise ValueError("official H1 registration is not admitted and unblocked")
    if deployment.get("study_id") != study.get("study_id"):
        raise ValueError("deployment registration is bound to another study")
    matrix_experiment = next(
        (
            row
            for row in matrix.get("experiments", [])
            if row.get("id") == study.get("experiment_id")
        ),
        None,
    )
    if matrix_experiment is None or matrix_experiment.get("status") != "admitted":
        raise ValueError("research matrix does not mirror H1 admission")
    if (
        matrix_experiment.get("scenarios") != [study.get("scenario")]
        or matrix_experiment.get("arms") != study.get("arms")
        or matrix_experiment.get("repetitions") != study.get("repetitions")
    ):
        raise ValueError("research matrix H1 design differs from the admitted study")
    if deployment.get("bindings", {}).get("study_sha256") != _sha256_hex(study_path):
        raise ValueError("deployment registration has a stale study binding")
    if deployment.get("bindings", {}).get("protocol_sha256") != _sha256_hex(
        PROTOCOL_PATH
    ):
        raise ValueError("deployment registration has a stale protocol binding")
    entries = registry.get("adapters")
    if registry.get("schema") != "ecpa-formal-adapter-registry/v2" or not isinstance(
        entries, list
    ):
        raise ValueError("official adapter registry is malformed")
    registry_by_id = {entry.get("id"): entry for entry in entries}
    if len(registry_by_id) != 3 or None in registry_by_id:
        raise ValueError("official adapter registry must contain exactly three IDs")
    candidate_arms = {row["arm"]: row for row in candidate["arms"]}
    registered_arms = deployment.get("arm_registrations")
    if [row.get("arm") for row in registered_arms] != list(study["arms"]):
        raise ValueError("deployment arm order differs from the registered study")
    arms: dict[str, dict[str, Any]] = {}
    for row in registered_arms:
        arm = row["arm"]
        registration = row.get("registration")
        if not isinstance(registration, dict):
            raise ValueError(f"official arm is unregistered: {arm}")
        registry_id = registration.get("registry_id")
        candidate_arm = candidate_arms.get(arm)
        if (
            candidate_arm is None
            or registry_id not in registry_by_id
            or candidate_arm["runner_arguments"]["adapter_verification_id"]
            != registry_id
            or candidate_arm["registry_candidate"]["id"] != registry_id
        ):
            raise ValueError(
                f"official arm ID differs from the reviewed candidate: {arm}"
            )
        registry_digest = "sha256:" + hashlib.sha256(
            canonical(registry_by_id[registry_id])
        ).hexdigest()
        recorded_digest = registration.get("registry_entry_sha256")
        accepted_digests = {registry_digest, registry_digest.removeprefix("sha256:")}
        if recorded_digest not in accepted_digests:
            raise ValueError(f"official registry entry digest is stale: {registry_id}")
        arms[arm] = candidate_arm
    expected_sources = {
        "service-ready",
        "workload-complete",
        "fault-injected",
        "observer-captured",
        "service-shutdown",
    }
    source_rows = deployment.get("source_registrations")
    if {row.get("phase") for row in source_rows} != expected_sources or any(
        not isinstance(row.get("registration"), dict) for row in source_rows
    ):
        raise ValueError("official five-source registration is incomplete")
    registered_ids = set(registry_by_id)
    for row in source_rows:
        if set(row["registration"].get("registry_ids", [])) != registered_ids:
            raise ValueError(
                "lifecycle source registration does not bind all three arms"
            )
    scenarios = json.loads(SCENARIOS_PATH.read_text())["scenarios"]
    scenario = next(
        (row for row in scenarios if row.get("id") == study.get("scenario")), None
    )
    if scenario is None:
        raise ValueError("registered H1 scenario is unavailable")
    return Campaign(
        study=study,
        deployment=deployment,
        registry=registry,
        matrix=matrix,
        candidate=candidate,
        scenario=scenario,
        protocol=json.loads(PROTOCOL_PATH.read_text()),
        schedule=schedule,
        arms=arms,
    )


def _directory_identity(path: Path) -> tuple[int, int]:
    if not path.is_absolute() or path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError(f"campaign directory is not canonical: {path}")
    metadata = path.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError(f"campaign directory is not private and owned: {path}")
    return metadata.st_dev, metadata.st_ino


def _clear_directory(path: Path, expected: tuple[int, int], *, event: bool) -> None:
    """Remove only recognized prior-run artifacts without replacing the root."""
    if _directory_identity(path) != expected:
        raise ValueError(f"campaign directory identity changed: {path}")
    entries = list(path.iterdir())
    for child in entries:
        if child.is_symlink():
            raise ValueError(f"refusing to clear symlink campaign artifact: {child}")
        if event and child.is_dir() and _PLAN_DIRECTORY.fullmatch(child.name):
            children = list(child.iterdir())
            if (
                len(children) != 1
                or children[0].name != "plan.json"
                or not children[0].is_file()
                or children[0].is_symlink()
            ):
                raise ValueError(f"unexpected frozen Plan directory content: {child}")
            child.chmod(0o700)
            children[0].unlink()
            child.rmdir()
            continue
        allowed = (
            child.is_file()
            and not child.is_symlink()
            and (
                child.name == _ALLOWED_LOCK
                or (event and bool(_JOURNAL.fullmatch(child.name)))
                or (event and bool(_SOURCE_FENCE.fullmatch(child.name)))
                or (not event and bool(_JOURNAL.fullmatch(child.name)))
                or (not event and bool(_TRANSACTION.fullmatch(child.name)))
            )
        )
        if not allowed:
            raise ValueError(f"unexpected campaign artifact blocks cleanup: {child}")
        child.unlink()
    directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    if _directory_identity(path) != expected or any(path.iterdir()):
        raise ValueError(f"campaign directory cleanup was not stable: {path}")


def clear_launch_workspace(arm: dict[str, Any]) -> None:
    workspace = arm["workspace"]
    for name, event in (("event", True), ("quarantine", False)):
        path = Path(workspace[f"{name}_dir"])
        identity = workspace[f"{name}_directory_identity"]
        _clear_directory(
            path,
            (identity["device"], identity["inode"]),
            event=event,
        )


def _load_existing_records(root: Path, campaign: Campaign) -> list[dict[str, Any]]:
    schema = json.loads(RAW_RECORD_SCHEMA_PATH.read_text())
    records: list[dict[str, Any]] = []
    saw_gap = False
    for position in campaign.schedule:
        start_id = (
            f"{campaign.scenario['id']}-r{position['repetition']}-{position['arm']}"
        )
        run_dir = root / "starts" / start_id
        record_path = run_dir / "record.json"
        if not run_dir.exists():
            saw_gap = True
            continue
        if not record_path.is_file() or record_path.is_symlink():
            raise ValueError(
                f"interrupted start is retained and blocks resume: {start_id}"
            )
        if saw_gap:
            raise ValueError(
                "formal start records are not a contiguous schedule prefix"
            )
        record = _read_canonical(record_path)
        if (
            record.get("start_id") != start_id
            or record.get("repetition") != position["repetition"]
            or record.get("arm_order") != position["arm_order"]
            or record.get("arm") != position["arm"]
            or record.get("evidence_class") != "formal-real"
        ):
            raise ValueError(f"formal start differs from frozen schedule: {start_id}")
        validate_record(
            record,
            root,
            scenario=campaign.scenario,
            protocol=campaign.protocol,
            schema=schema,
        )
        records.append(record)
    return records


def _adapter(name: str) -> runner.FormalArmAdapter:
    return {
        "VanillaVLLMAdapter": runner.VanillaVLLMAdapter,
        "ManualIntegrationAdapter": runner.ManualIntegrationAdapter,
        "ECPAAdapter": runner.ECPAAdapter,
    }[name]()


def _lifecycle_commands(arm: dict[str, Any]) -> dict[str, tuple[str, list[str]]]:
    commands = arm["lifecycle_fact_commands"]
    return {
        phase: (fingerprint["executable"], list(fingerprint["arguments"]))
        for phase, fingerprint in commands.items()
    }


def run_campaign(
    root: Path,
    candidate_path: Path = DEFAULT_CANDIDATE_PATH,
    *,
    run_start: Callable[..., dict[str, Any]] | None = None,
    publish: Callable[[Path, list[dict[str, Any]]], Path] | None = None,
) -> list[dict[str, Any]]:
    """Run each not-yet-attempted schedule position exactly once."""
    campaign = validate_registration(candidate_path)
    root = root.absolute()
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if _directory_identity(root) != (root.stat().st_dev, root.stat().st_ino):
        raise AssertionError("campaign root identity check is inconsistent")
    # ``run_formal_start`` is the repository's external, registry-pinned runner.
    # Keeping this indirection local preserves the source digest in the already
    # issued automated review receipt.
    start_fn = run_start or runner.run_formal_start
    publish_fn = publish or runner.write_formal_manifest
    lock_path = root / ".h1-driver.lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        records = _load_existing_records(root, campaign)
        if records:
            publish_fn(root, records)
        for position in campaign.schedule[len(records) :]:
            arm = campaign.arms[position["arm"]]
            clear_launch_workspace(arm)
            arguments = arm["runner_arguments"]
            proxy_registrations = arguments.get("formal_proxy_registrations")
            proxy_registration = None
            if proxy_registrations is not None:
                if not isinstance(proxy_registrations, dict):
                    raise ValueError("formal proxy registrations are malformed")
                start_id = (
                    f"{campaign.scenario['id']}-r{position['repetition']}-"
                    f"{position['arm']}"
                )
                proxy_registration = proxy_registrations.get(start_id)
                if proxy_registration is None:
                    raise ValueError(
                        f"formal proxy registration is missing for {start_id}"
                    )
            os.environ.update(campaign.candidate["environment"])
            record = start_fn(
                root,
                campaign.scenario,
                campaign.protocol,
                _adapter(arguments["adapter"]),
                position["repetition"],
                position["arm_order"],
                executable=arguments["executable"],
                arguments=list(arguments["arguments"]),
                observer_executable=arguments["observer_executable"],
                observer_arguments=list(arguments["observer_arguments"]),
                identity=campaign.candidate["declared_identity"],
                timeout_s=arguments["timeout_s"],
                adapter_verification_id=arguments["adapter_verification_id"],
                manager_executable=arguments["manager_executable"],
                execution_plan_path=arguments["execution_plan_path"],
                host_event_dir=arguments["host_event_dir"],
                lifecycle_fact_commands=_lifecycle_commands(arm),
                formal_proxy_registration=proxy_registration,
            )
            records.append(record)
            publish_fn(root, records)
        return records
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "run"))
    parser.add_argument("--candidate", type=Path, default=DEFAULT_CANDIDATE_PATH)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "check":
        campaign = validate_registration(args.candidate)
        print(
            json.dumps(
                {
                    "admissible": True,
                    "registered_arm_ids": [
                        campaign.arms[row["arm"]]["runner_arguments"][
                            "adapter_verification_id"
                        ]
                        for row in campaign.schedule[:3]
                    ],
                    "planned_starts": len(campaign.schedule),
                },
                sort_keys=True,
            )
        )
        return
    if args.output is None:
        parser.error("run requires --output")
    records = run_campaign(args.output, args.candidate)
    print(json.dumps({"attempted_starts": len(records)}, sort_keys=True))


if __name__ == "__main__":
    main()
