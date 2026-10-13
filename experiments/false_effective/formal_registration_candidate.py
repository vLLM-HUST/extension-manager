"""Build and validate the deployment-bound H1 command registration candidate.

The output of this module is deliberately not the trusted adapter registry.  It
contains machine-derived command fingerprints and activation-probe receipts for
review, while leaving every independent admission assertion unset.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import stat
from pathlib import Path
from typing import Any

from harness import (
    FORMAL_HOST_OBSERVABLES,
    FORMAL_LIFECYCLE_FACT_SCHEMA_PATH,
    FORMAL_LIFECYCLE_FACT_SOURCES,
    FORMAL_LIFECYCLE_FACT_TRANSPORT,
    canonical,
    digest_bytes,
    digest_file,
)
from jsonschema import Draft7Validator
from runner import (
    ECPA_FORMAL_ACTIVATION_OPTIONS,
    ECPAAdapter,
    ManualIntegrationAdapter,
    VanillaVLLMAdapter,
    command_fingerprint,
    command_fingerprint_for_launch,
    run_activation_probe,
    run_ecpa_activation_probe,
)

HERE = Path(__file__).resolve().parent
CANDIDATE_ROOT = HERE / "deployment-candidates"
STUDY_PATH = HERE / "first-formal-real-study.json"
DEPLOYMENT_PATH = HERE / "first-formal-real-deployment.json"
REGISTRY_PATH = HERE / "verified-adapters.json"
SCHEMA_PATH = HERE / "h1-formal-registration-candidate.schema.json"
INPUTS = {
    "plan": CANDIDATE_ROOT / "h1-kv-materialization-plan.json",
    "workload": CANDIDATE_ROOT / "h1-qwen2.5-7b-workload.json",
    "fault": CANDIDATE_ROOT / "h1-partial-worker-coverage-fault.json",
}
SCHEMA = "ecpa-h1-formal-registration-candidate/v1"
CLASSIFICATION = "deployment-bound-non-admitting-command-candidate"
EXPERIMENT_MANAGER_COMMIT = "9f075f8e70da574fb90bdd392cf7c7e424c75972"
EXPERIMENT_MANAGER_TREE = "91ebc43a7a82bbc561ad3ed9f94bd02ac72c2a12"
EXPERIMENT_MANAGER_NOTE = (
    "binary used by the frozen H1 experiment stack; repository main may advance"
)
ARMS = (
    ("vanilla-vllm-entry-points", "vanilla", 8187),
    ("manual-integration", "manual", 8187),
    ("ecpa", "ecpa", 8187),
)
ENTRY_POINT = {
    "group": "vllm.general_plugins",
    "name": "kv_materialization",
    "value": "vllm_kv_materialization.plugin:register_plugin",
}
FIXED_ENVIRONMENT = {
    "HF_HUB_OFFLINE": "1",
    "OMP_NUM_THREADS": "1",
    "TRANSFORMERS_OFFLINE": "1",
    "VLLM_PLUGINS": (
        "ascend,ascend_kv_connector,ascend_model,ascend_model_loader,kv_materialization"
    ),
    "VLLM_WORKER_MULTIPROC_METHOD": "spawn",
    "VLLM_WORKER_SHUTDOWN_TIMEOUT_SECONDS": "12",
}
MACHINE_BLOCKERS = (
    "runtime-and-mod-candidates-not-repository-reachable",
    "exact-runtime-accelerator-support-matrix-unqualified",
)
INDEPENDENT_BLOCKERS = (
    "producer-admission-receipt-not-issued",
    "commands-not-independently-reviewed",
    "activation-paths-not-independently-reviewed",
    "observer-independence-not-independently-reviewed",
    "artifact-retention-not-independently-reviewed",
)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _load_canonical(path: Path) -> dict[str, Any]:
    value = _load(path)
    if path.read_bytes() != canonical(value) + b"\n":
        raise ValueError(f"candidate input is not canonical: {path}")
    return value


def _private_directory(path: Path, *, empty: bool) -> tuple[int, int]:
    if path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path:
        raise ValueError(f"candidate directory is not canonical: {path}")
    metadata = path.stat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError(f"candidate directory is not private and owned: {path}")
    if empty and any(path.iterdir()):
        raise ValueError(f"candidate launch directory is not empty: {path}")
    return metadata.st_dev, metadata.st_ino


def _write_input(destination: Path, source: Path) -> None:
    raw = source.read_bytes()
    if destination.exists():
        if destination.is_symlink() or destination.read_bytes() != raw:
            raise ValueError(
                f"candidate input differs from repository bytes: {destination}"
            )
        return
    destination.write_bytes(raw)
    destination.chmod(0o400)


def prepare_workspace(workspace: Path) -> dict[str, Path]:
    """Create stable private directories without deleting prior evidence."""
    workspace = workspace.absolute()
    workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private_directory(workspace, empty=False)
    inputs = workspace / "inputs"
    inputs.mkdir(mode=0o700, exist_ok=True)
    _private_directory(inputs, empty=False)
    prepared = {}
    for name, source in INPUTS.items():
        destination = inputs / source.name
        _write_input(destination, source)
        prepared[name] = destination.resolve(strict=True)
    shared = workspace / "shared"
    shared.mkdir(mode=0o700, exist_ok=True)
    _private_directory(shared, empty=False)
    for name in ("events", "quarantine"):
        directory = shared / name
        directory.mkdir(mode=0o700, exist_ok=True)
        _private_directory(directory, empty=True)
    return prepared


def _fingerprint(executable: Path, arguments: list[str]) -> dict[str, Any]:
    return command_fingerprint_for_launch(str(executable), arguments)


def _activation_probe(
    adapter: VanillaVLLMAdapter | ManualIntegrationAdapter | ECPAAdapter,
    executable: Path,
    arguments: list[str],
    *,
    execute: bool,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if isinstance(adapter, ECPAAdapter):
        prefix = executable.read_text().splitlines()[0]
        if not prefix.startswith("#!"):
            raise ValueError("manager console script lacks a direct shebang")
        interpreter = prefix[2:]
        fingerprint = command_fingerprint(
            interpreter,
            [str(executable), "formal-run", "--ecpa-formal-activation-probe"],
        )
        entry = {
            "activation_probe": {
                "command_digest": fingerprint["digest"],
                "required_options": sorted(ECPA_FORMAL_ACTIVATION_OPTIONS),
                "timeout_s": 30,
            }
        }
        observation = (
            run_ecpa_activation_probe(entry, adapter, str(executable))
            if execute
            else None
        )
        return fingerprint, observation
    probe_arguments = [
        *arguments,
        *adapter.activation_arguments,
        "--ecpa-formal-activation-probe",
    ]
    fingerprint = _fingerprint(executable, probe_arguments)
    entry = {
        "activation_probe": {
            "command_digest": fingerprint["digest"],
            "required_options": sorted(adapter.activation_arguments),
            "timeout_s": 30,
        }
    }
    observation = (
        run_activation_probe(entry, adapter, str(executable), arguments)
        if execute
        else None
    )
    return fingerprint, observation


def _serve_arguments(port: int) -> list[str]:
    return [
        "serve",
        "/models/Qwen2.5-7B-Instruct",
        "--served-model-name",
        "ecpa-h1",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--tensor-parallel-size",
        "2",
        "--enforce-eager",
        "--max-model-len",
        "2048",
        "--gpu-memory-utilization",
        "0.7",
        "--shutdown-timeout",
        "20",
    ]


def _source_commands(
    source: Path,
    *,
    port: int,
    event_dir: Path,
    quarantine_dir: Path,
    workload: Path,
    fault: Path,
) -> dict[str, dict[str, Any]]:
    event_device, event_inode = _private_directory(event_dir, empty=True)
    quarantine_device, quarantine_inode = _private_directory(quarantine_dir, empty=True)
    raw = {
        "service-ready": [
            "readiness-http",
            "--url",
            f"http://127.0.0.1:{port}/health",
            "--status",
            "200",
            "--timeout",
            "2",
            "--startup-timeout",
            "600",
            "--poll-interval",
            "1",
        ],
        "workload-complete": [
            "workload-http",
            "--url",
            f"http://127.0.0.1:{port}/v1/completions",
            "--request",
            str(workload),
            "--request-sha256",
            digest_file(workload),
            "--timeout",
            "60",
        ],
        "fault-injected": [
            "partial-coverage-quarantine",
            "--event-dir",
            str(event_dir),
            "--device",
            str(event_device),
            "--inode",
            str(event_inode),
            "--quarantine-dir",
            str(quarantine_dir),
            "--quarantine-device",
            str(quarantine_device),
            "--quarantine-inode",
            str(quarantine_inode),
            "--descriptor",
            str(fault),
            "--descriptor-sha256",
            digest_file(fault),
        ],
        "observer-captured": [
            "journal-capture",
            "--event-dir",
            str(event_dir),
            "--device",
            str(event_device),
            "--inode",
            str(event_inode),
        ],
        "service-shutdown": ["shutdown-process", "--timeout", "45"],
    }
    return {phase: _fingerprint(source, raw[phase]) for phase in sorted(raw)}


def _observer(observer: Path, event_dir: Path) -> dict[str, Any]:
    device, inode = _private_directory(event_dir, empty=True)
    return _fingerprint(
        observer,
        [
            "--event-dir",
            str(event_dir),
            "--device",
            str(device),
            "--inode",
            str(inode),
            "--entry-point-group",
            ENTRY_POINT["group"],
            "--entry-point-name",
            ENTRY_POINT["name"],
            "--entry-point-value",
            ENTRY_POINT["value"],
        ],
    )


def _adapter(slug: str):
    return {
        "vanilla": VanillaVLLMAdapter,
        "manual": ManualIntegrationAdapter,
        "ecpa": ECPAAdapter,
    }[slug]()


def _declared_identity() -> dict[str, Any]:
    machine = _load(CANDIDATE_ROOT / "h1-machine-frozen-inputs-20261013.json")
    return {
        "model": copy.deepcopy(machine["model"]),
        "dataset": "fixed-single-request-no-external-dataset",
        "workload": copy.deepcopy(machine["workload"]),
        "software": copy.deepcopy(machine["sources"]),
        "observer": "vllm_hust_ext.formal_host_observer@manager-9f075f8e",
        "plugin_commits": {
            "kv_materialization": machine["sources"]["mod"]["commit"],
            "vllm_ascend": machine["sources"]["accelerator_plugin"]["commit"],
        },
        "topology": machine["hardware"]["topology"],
        "fault_plan": "partial-worker-coverage/worker-0-evidence-quarantine",
        "fault": copy.deepcopy(machine["fault"]),
        "warm_state": machine["hardware"]["warm_state"],
        "container_digest": machine["container"]["image_id"],
        "environment_digest": machine["installed_environment"]["digest"],
        "gpu": "none",
        "npu": {
            "device_family": machine["hardware"]["device_family"],
            "physical_device_ids": machine["hardware"]["physical_device_ids"],
            "runtime_logical_device_ids": machine["hardware"][
                "runtime_logical_device_ids"
            ],
        },
        "driver": machine["installed_environment"]["versions"]["ascend_driver"],
        "required_process_slots": [
            {
                "host": machine["fault"]["path"]
                and _load(CANDIDATE_ROOT / machine["fault"]["path"])["target"]["host"],
                "role": "worker",
                "ordinal": ordinal,
            }
            for ordinal in (0, 1)
        ],
    }


def build_candidate(
    workspace: Path,
    venv: Path,
    *,
    execute_probes: bool,
) -> dict[str, Any]:
    workspace = workspace.absolute()
    inputs = prepare_workspace(workspace)
    venv = venv.absolute()
    binaries = {
        "baseline": venv / "bin/vllm-kv-materialization-serve",
        "manager": venv / "bin/vllm-hust-ext",
        "python": venv / "bin/python",
        "observer": venv / "bin/ecpa-formal-observer",
        "source": venv / "bin/ecpa-formal-source",
    }
    for name, path in binaries.items():
        if not path.is_file():
            raise ValueError(f"candidate {name} executable is unavailable: {path}")
    study = _load(STUDY_PATH)
    arms = []
    for arm, slug, port in ARMS:
        adapter = _adapter(slug)
        shared_root = (workspace / "shared").resolve(strict=True)
        event_dir = (shared_root / "events").resolve(strict=True)
        quarantine_dir = (shared_root / "quarantine").resolve(strict=True)
        arguments = _serve_arguments(port)
        commands: dict[str, Any] = {}
        if isinstance(adapter, ECPAAdapter):
            target_arguments = ["-m", "vllm.entrypoints.cli.main", *arguments]
            commands["manager"] = _fingerprint(binaries["manager"], [])
            commands["target"] = _fingerprint(binaries["python"], target_arguments)
            launch_executable = binaries["python"]
            launch_arguments = target_arguments
            probe, probe_observation = _activation_probe(
                adapter, binaries["manager"], [], execute=execute_probes
            )
        else:
            final_arguments = [*arguments, *adapter.activation_arguments]
            commands["sut"] = _fingerprint(binaries["baseline"], final_arguments)
            launch_executable = binaries["baseline"]
            launch_arguments = arguments
            probe, probe_observation = _activation_probe(
                adapter,
                binaries["baseline"],
                arguments,
                execute=execute_probes,
            )
        commands["observer"] = _observer(binaries["observer"], event_dir)
        commands["activation_probe"] = probe
        lifecycle = _source_commands(
            binaries["source"],
            port=port,
            event_dir=event_dir,
            quarantine_dir=quarantine_dir,
            workload=inputs["workload"],
            fault=inputs["fault"],
        )
        registry_candidate = {
            "id": f"h1-910b2-tp2-{slug}-candidate-v1",
            "arm": arm,
            "admission": None,
            "activation_contract": adapter.activation_contract,
            "evidence_owner": "vllm-hust-host",
            "evidence_channel": "host-owned-event-stream",
            "host_event_schema": "ecpa-host-runtime-evidence/v1",
            "lifecycle_fact_schema": "ecpa-formal-lifecycle-fact/v1",
            "lifecycle_fact_schema_digest": digest_file(
                FORMAL_LIFECYCLE_FACT_SCHEMA_PATH
            ),
            "lifecycle_fact_sources": FORMAL_LIFECYCLE_FACT_SOURCES,
            "lifecycle_fact_transport": FORMAL_LIFECYCLE_FACT_TRANSPORT,
            "required_observables": sorted(FORMAL_HOST_OBSERVABLES),
            "activation_probe": {
                "command_digest": probe["digest"],
                "required_options": (
                    sorted(ECPA_FORMAL_ACTIVATION_OPTIONS)
                    if isinstance(adapter, ECPAAdapter)
                    else sorted(adapter.activation_arguments)
                ),
                "timeout_s": 30,
            },
            "lifecycle_fact_command_digests": {
                phase: fingerprint["digest"] for phase, fingerprint in lifecycle.items()
            },
            "scenario_bindings": {
                "partial-worker-coverage": {
                    "descriptor_sha256": digest_file(inputs["fault"]),
                    "entry_point": ENTRY_POINT,
                    "fault_source_subcommand": "partial-coverage-quarantine",
                }
            },
            "observer_command_digest": commands["observer"]["digest"],
        }
        if isinstance(adapter, ECPAAdapter):
            registry_candidate.update(
                {
                    "manager_command_digest": commands["manager"]["digest"],
                    "target_command_digest": commands["target"]["digest"],
                }
            )
        else:
            registry_candidate["sut_command_digest"] = commands["sut"]["digest"]
        arms.append(
            {
                "arm": arm,
                "activation_contract": adapter.activation_contract,
                "port": port,
                "workspace": {
                    "event_dir": str(event_dir),
                    "event_directory_identity": dict(
                        zip(
                            ("device", "inode"),
                            _private_directory(event_dir, empty=True),
                            strict=True,
                        )
                    ),
                    "quarantine_dir": str(quarantine_dir),
                    "quarantine_directory_identity": dict(
                        zip(
                            ("device", "inode"),
                            _private_directory(quarantine_dir, empty=True),
                            strict=True,
                        )
                    ),
                    "reuse_rule": (
                        "same directories and inodes for all three repetitions; "
                        "must be empty before each runner call"
                    ),
                },
                "commands": commands,
                "lifecycle_fact_commands": lifecycle,
                "activation_probe_observation": probe_observation,
                "runner_arguments": {
                    "adapter": type(adapter).__name__,
                    "adapter_verification_id": registry_candidate["id"],
                    "executable": str(launch_executable),
                    "arguments": launch_arguments,
                    "observer_executable": str(binaries["observer"]),
                    "observer_arguments": commands["observer"]["arguments"][1:],
                    "manager_executable": (
                        str(binaries["manager"])
                        if isinstance(adapter, ECPAAdapter)
                        else None
                    ),
                    "execution_plan_path": str(inputs["plan"]),
                    "host_event_dir": str(event_dir),
                    "timeout_s": 660,
                },
                "registry_candidate": registry_candidate,
            }
        )
    schedule = [
        {
            "start": repetition * len(order) + arm_order,
            "repetition": repetition + 1,
            "arm_order": arm_order,
            "arm": arm,
        }
        for repetition, order in enumerate(study["schedule"])
        for arm_order, arm in enumerate(order, 1)
    ]
    candidate = {
        "schema": SCHEMA,
        "classification": CLASSIFICATION,
        "registration_state": "candidate-only",
        "admissible": False,
        "formal_h1_starts": 0,
        "experiment_manager_identity": {
            "commit": EXPERIMENT_MANAGER_COMMIT,
            "tree": EXPERIMENT_MANAGER_TREE,
            "note": EXPERIMENT_MANAGER_NOTE,
        },
        "workspace": str(workspace),
        "inputs": {
            name: {"path": str(path), "sha256": digest_file(path)}
            for name, path in inputs.items()
        },
        "environment": FIXED_ENVIRONMENT,
        "declared_identity": _declared_identity(),
        "schedule": schedule,
        "arms": arms,
        "machine_checks": {
            "three_arms_complete": True,
            "five_sources_per_arm_complete": True,
            "nine_start_schedule_complete": True,
            "activation_probes_executed": execute_probes,
        },
        "independent_reviews": {
            "commands": None,
            "activation_paths": None,
            "observer_independence": None,
            "artifact_retention": None,
        },
        "remaining_blockers": [*MACHINE_BLOCKERS, *INDEPENDENT_BLOCKERS],
        "non_claims": [
            "This candidate does not modify verified-adapters.json.",
            "Activation-probe receipts prove parser admission only.",
            (
                "The three prior TP2 preflights remain unregistered and formal H1 "
                "remains 0/9."
            ),
            "Machine-derived command digests do not substitute for independent review.",
        ],
    }
    validate_candidate(candidate, live=True)
    return candidate


def _validate_fingerprint(value: Any, *, live: bool) -> None:
    if not isinstance(value, dict) or "digest" not in value:
        raise ValueError("candidate command fingerprint is incomplete")
    core = {key: item for key, item in value.items() if key != "digest"}
    if value["digest"] != digest_bytes(canonical(core)):
        raise ValueError("candidate command fingerprint digest is stale")
    if live and command_fingerprint(value["executable"], value["arguments"]) != value:
        raise ValueError("candidate command fingerprint differs from live files")


def validate_candidate(value: dict[str, Any], *, live: bool) -> None:
    Draft7Validator(_load(SCHEMA_PATH)).validate(value)
    if (
        value.get("schema") != SCHEMA
        or value.get("classification") != CLASSIFICATION
        or value.get("registration_state") != "candidate-only"
        or value.get("admissible") is not False
        or value.get("formal_h1_starts") != 0
    ):
        raise ValueError("H1 command candidate was promoted beyond machine facts")
    if value.get("experiment_manager_identity") != {
        "commit": EXPERIMENT_MANAGER_COMMIT,
        "tree": EXPERIMENT_MANAGER_TREE,
        "note": EXPERIMENT_MANAGER_NOTE,
    }:
        raise ValueError("H1 experiment manager identity drifted")
    if set(value.get("independent_reviews", {}).values()) != {None}:
        raise ValueError("independent review cannot be machine asserted")
    arms = value.get("arms")
    if not isinstance(arms, list) or [row.get("arm") for row in arms] != [
        item[0] for item in ARMS
    ]:
        raise ValueError("candidate does not contain the exact three arms")
    source_digests_by_phase: dict[str, set[str]] = {
        phase: set() for phase in FORMAL_LIFECYCLE_FACT_SOURCES
    }
    expected_subcommands = {
        "service-ready": "readiness-http",
        "workload-complete": "workload-http",
        "fault-injected": "partial-coverage-quarantine",
        "observer-captured": "journal-capture",
        "service-shutdown": "shutdown-process",
    }
    for row in arms:
        sources = row.get("lifecycle_fact_commands")
        if not isinstance(sources, dict) or set(sources) != set(
            FORMAL_LIFECYCLE_FACT_SOURCES
        ):
            raise ValueError("candidate does not contain the exact five sources")
        registry = row.get("registry_candidate", {})
        if registry.get("admission") is not None:
            raise ValueError("candidate must not manufacture producer admission")
        if registry.get("lifecycle_fact_sources") != FORMAL_LIFECYCLE_FACT_SOURCES:
            raise ValueError("candidate lifecycle source roles drifted")
        if registry.get("arm") != row["arm"]:
            raise ValueError("candidate registry arm drifted")
        if (
            registry.get("observer_command_digest")
            != row["commands"]["observer"]["digest"]
        ):
            raise ValueError("candidate observer registration digest drifted")
        if (
            registry.get("activation_probe", {}).get("command_digest")
            != row["commands"]["activation_probe"]["digest"]
        ):
            raise ValueError("candidate activation probe registration digest drifted")
        registered_sources = registry.get("lifecycle_fact_command_digests")
        if registered_sources != {
            phase: fingerprint["digest"] for phase, fingerprint in sources.items()
        }:
            raise ValueError("candidate lifecycle source registration digest drifted")
        if row["arm"] == "ecpa":
            if (
                registry.get("manager_command_digest")
                != row["commands"]["manager"]["digest"]
                or registry.get("target_command_digest")
                != row["commands"]["target"]["digest"]
            ):
                raise ValueError(
                    "candidate managed command registration digest drifted"
                )
        elif registry.get("sut_command_digest") != row["commands"]["sut"]["digest"]:
            raise ValueError("candidate baseline command registration digest drifted")
        for fingerprint in [*row["commands"].values(), *sources.values()]:
            _validate_fingerprint(fingerprint, live=live)
        probe = row.get("activation_probe_observation")
        if value["machine_checks"]["activation_probes_executed"]:
            expected_receipt = {
                "schema": "ecpa-activation-probe/v1",
                "activation_contract": row["activation_contract"],
                "accepted_options": registry["activation_probe"]["required_options"],
            }
            if (
                not isinstance(probe, dict)
                or probe.get("exit_code") != 0
                or probe.get("receipt") != expected_receipt
                or probe.get("command") != row["commands"]["activation_probe"]
            ):
                raise ValueError("candidate activation probe is not exact")
        elif probe is not None:
            raise ValueError("unexecuted activation probe has an observation")
        digests = [fingerprint["digest"] for fingerprint in sources.values()]
        if len(digests) != 5 or len(set(digests)) != 5:
            raise ValueError("lifecycle source processes are not independently pinned")
        for phase, fingerprint in sources.items():
            arguments = fingerprint["arguments"]
            if (
                len(arguments) < 2
                or Path(arguments[0]).name != "ecpa-formal-source"
                or arguments[1] != expected_subcommands[phase]
            ):
                raise ValueError("candidate lifecycle source subcommand drifted")
            source_digests_by_phase[phase].add(fingerprint["digest"])
        if live:
            for directory in ("event", "quarantine"):
                path = Path(row["workspace"][f"{directory}_dir"])
                actual = dict(
                    zip(
                        ("device", "inode"),
                        _private_directory(path, empty=True),
                        strict=True,
                    )
                )
                if actual != row["workspace"][f"{directory}_directory_identity"]:
                    raise ValueError("candidate directory identity drifted")
    if any(len(digests) != 1 for digests in source_digests_by_phase.values()):
        raise ValueError("source commands differ across comparison arms")
    schedule = value.get("schedule")
    if (
        not isinstance(schedule, list)
        or len(schedule) != 9
        or [row.get("start") for row in schedule] != list(range(1, 10))
        or sorted(row.get("arm") for row in schedule)
        != sorted([arm for arm, _, _ in ARMS] * 3)
    ):
        raise ValueError("candidate nine-start schedule drifted")
    if set(value.get("remaining_blockers", [])) != set(
        (*MACHINE_BLOCKERS, *INDEPENDENT_BLOCKERS)
    ):
        raise ValueError("candidate blocker boundary drifted")
    if live:
        if _load_canonical(REGISTRY_PATH) != {
            "adapters": [],
            "schema": "ecpa-formal-adapter-registry/v2",
        }:
            raise ValueError(
                "official registry changed while candidate is non-admitting"
            )
        deployment = _load(DEPLOYMENT_PATH)
        if (
            deployment.get("registration_state") != "unregistered"
            or deployment.get("admissible") is not False
        ):
            raise ValueError("official deployment was promoted without admission")


def transition_dry_run(value: dict[str, Any], *, live: bool) -> dict[str, Any]:
    """Describe the all-or-nothing official write set without changing it."""
    validate_candidate(value, live=live)
    paths = (STUDY_PATH, DEPLOYMENT_PATH, REGISTRY_PATH)
    before = {str(path.relative_to(HERE)): digest_file(path) for path in paths}
    unsatisfied = list(value["remaining_blockers"])
    return {
        "schema": "ecpa-h1-registration-transition-dry-run/v1",
        "candidate_schema": value["schema"],
        "candidate_digest": digest_bytes(canonical(value) + b"\n"),
        "ready": not unsatisfied,
        "official_files_mutated": False,
        "atomic_write_set": list(before),
        "official_file_digests_before": before,
        "machine_preconditions": copy.deepcopy(value["machine_checks"]),
        "unsatisfied_preconditions": unsatisfied,
        "partial_transition_allowed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--workspace", type=Path, required=True)
    build.add_argument("--venv", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--execute-probes", action="store_true")
    check = subparsers.add_parser("check")
    check.add_argument("candidate", type=Path)
    check.add_argument("--live", action="store_true")
    transition = subparsers.add_parser("transition-dry-run")
    transition.add_argument("candidate", type=Path)
    transition.add_argument("--output", type=Path, required=True)
    transition.add_argument("--live", action="store_true")
    args = parser.parse_args()
    if args.command == "build":
        candidate = build_candidate(
            args.workspace, args.venv, execute_probes=args.execute_probes
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical(candidate) + b"\n")
    elif args.command == "check":
        candidate = _load_canonical(args.candidate)
        validate_candidate(candidate, live=args.live)
    else:
        candidate = _load_canonical(args.candidate)
        report = transition_dry_run(candidate, live=args.live)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical(report) + b"\n")


if __name__ == "__main__":
    main()
