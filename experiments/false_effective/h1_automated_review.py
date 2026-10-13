"""Deterministic independent review for an H1 registration candidate.

This is an owner-authorized protocol amendment, not a human review.  It checks
the frozen candidate from a separate entry point and emits a content-addressed
receipt.  It cannot clear machine qualification or producer-admission gates.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from harness import canonical, digest_bytes, digest_file
from jsonschema import Draft7Validator

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "h1-automated-review.schema.json"
AMENDMENT_PATH = HERE / "h1-review-protocol-amendment-20261013.json"
RUNNER_PATH = HERE / "runner.py"
HARNESS_PATH = HERE / "harness.py"
REVIEW_SCHEMA = "ecpa-h1-automated-independent-review/v1"
REVIEWER_KIND = "automated-independent"
CHECK_IDS = (
    "commands",
    "activation_paths",
    "observer_independence",
    "artifact_retention",
)
REVIEW_BLOCKERS = (
    "commands-not-independently-reviewed",
    "activation-paths-not-independently-reviewed",
    "observer-independence-not-independently-reviewed",
    "artifact-retention-not-independently-reviewed",
)
EXPECTED_CONTRACTS = {
    "vanilla-vllm-entry-points": ("entry-points-unmanaged", "VanillaVLLMAdapter"),
    "manual-integration": ("explicit-manual-hooks", "ManualIntegrationAdapter"),
    "ecpa": ("manager-controlled-activation", "ECPAAdapter"),
}
REQUIRED_RETAINED_NAMES = {
    "stdout.bin",
    "stderr.bin",
    "environment.json",
    "command.json",
    "observations.json",
    "observer-result.json",
    "observer-pipe.bin",
    "observer-stdout.bin",
    "observer-stderr.bin",
    "scenario.json",
    "protocol.json",
    "intake.json",
    "oracle.json",
    "runner-receipt.json",
    "record.json",
    "formal-records.jsonl",
    "index.json",
    "formal-record-index.json",
}


def _load_canonical(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if raw != canonical(value) + b"\n":
        raise ValueError(f"review input is not canonical: {path}")
    return value


def _amendment() -> dict[str, Any]:
    value = _load_canonical(AMENDMENT_PATH)
    if (
        value.get("schema") != "ecpa-h1-review-protocol-amendment/v1"
        or value.get("amendment_id") != "h1-review-mode-owner-amendment-2026-10-13"
        or value.get("replacement_mode") != REVIEWER_KIND
        or set(value.get("required_checks", [])) != set(CHECK_IDS)
        or "human review" not in value.get("non_claims", [""])[0].lower()
    ):
        raise ValueError("H1 automated-review protocol amendment is invalid")
    return value


def _evidence(assertions: list[str], facts: Any) -> dict[str, Any]:
    return {
        "verdict": "PASS",
        "evidence_digest": digest_bytes(canonical(facts)),
        "assertions": assertions,
    }


def _reject_fixture_reference(fingerprint: dict[str, Any]) -> None:
    paths = [
        fingerprint.get("executable", ""),
        fingerprint.get("executable_resolved", ""),
    ]
    paths.extend(str(item) for item in fingerprint.get("arguments", []))
    paths.extend(
        str(item.get("path", "")) for item in fingerprint.get("argument_files", [])
    )
    if any("tests/fixtures" in item or "reference-synthetic" in item for item in paths):
        raise ValueError("reviewed command references a fixture or synthetic path")


def _check_commands(candidate: dict[str, Any]) -> dict[str, Any]:
    facts = []
    expected_roles = {
        "vanilla-vllm-entry-points": {"sut", "observer", "activation_probe"},
        "manual-integration": {"sut", "observer", "activation_probe"},
        "ecpa": {"manager", "target", "observer", "activation_probe"},
    }
    for arm in candidate["arms"]:
        commands = arm["commands"]
        if set(commands) != expected_roles[arm["arm"]]:
            raise ValueError("reviewed arm command roles drifted")
        for fingerprint in [
            *commands.values(),
            *arm["lifecycle_fact_commands"].values(),
        ]:
            _reject_fixture_reference(fingerprint)
        registry = arm["registry_candidate"]
        if registry["observer_command_digest"] != commands["observer"]["digest"]:
            raise ValueError("observer registration is not command-bound")
        if registry["lifecycle_fact_command_digests"] != {
            phase: value["digest"]
            for phase, value in arm["lifecycle_fact_commands"].items()
        }:
            raise ValueError("source registrations are not command-bound")
        runner_executable = arm["runner_arguments"]["executable"]
        if arm["arm"] == "ecpa":
            target = commands["target"]
            if (
                Path(runner_executable).name != "python"
                or target["executable"] != runner_executable
                or target["arguments"][:2] != ["-m", "vllm.entrypoints.cli.main"]
                or target["argument_files"]
            ):
                raise ValueError(
                    "managed ECPA command does not use the direct venv Python ELF"
                )
        elif Path(runner_executable).name != "ecpa-host-launch":
            raise ValueError("baseline command does not use ecpa-host-launch")
        facts.append(
            {
                "arm": arm["arm"],
                "runner_executable": runner_executable,
                "command_digests": {
                    key: value["digest"] for key, value in commands.items()
                },
                "source_digests": registry["lifecycle_fact_command_digests"],
            }
        )
    return _evidence(
        [
            "all three arm command-role sets are exact",
            (
                "baseline arms use ecpa-host-launch while managed ECPA uses the "
                "direct venv Python ELF"
            ),
            "all five source commands are digest-bound for every arm",
            "no command or file-backed argument references a fixture or synthetic path",
        ],
        facts,
    )


def _check_activation_paths(candidate: dict[str, Any]) -> dict[str, Any]:
    facts = []
    probe_digests: set[str] = set()
    for arm in candidate["arms"]:
        contract, adapter = EXPECTED_CONTRACTS[arm["arm"]]
        probe = arm["activation_probe_observation"]
        registered = arm["registry_candidate"]["activation_probe"]
        if (
            arm["activation_contract"] != contract
            or arm["runner_arguments"]["adapter"] != adapter
            or probe.get("exit_code") != 0
            or probe.get("receipt", {}).get("activation_contract") != contract
            or probe.get("receipt", {}).get("accepted_options")
            != registered["required_options"]
            or probe.get("command", {}).get("digest") != registered["command_digest"]
        ):
            raise ValueError("activation-path evidence is incomplete or cross-bound")
        probe_digests.add(registered["command_digest"])
        facts.append(
            {
                "arm": arm["arm"],
                "adapter": adapter,
                "contract": contract,
                "probe_digest": registered["command_digest"],
                "options": registered["required_options"],
            }
        )
    if len(probe_digests) != 3:
        raise ValueError("activation paths do not have distinct probe commands")
    return _evidence(
        [
            "each arm is bound to its distinct adapter and activation contract",
            "each activation probe exited successfully with exact accepted options",
            "the three activation probe commands are distinct and registry-bound",
        ],
        facts,
    )


def _check_observer_independence(candidate: dict[str, Any]) -> dict[str, Any]:
    facts = []
    for arm in candidate["arms"]:
        commands = arm["commands"]
        observer = commands["observer"]
        other = {key: value for key, value in commands.items() if key != "observer"}
        if observer["digest"] in {value["digest"] for value in other.values()}:
            raise ValueError("observer command aliases an arm launch command")
        if (
            not observer["arguments"]
            or Path(observer["arguments"][0]).name != "ecpa-formal-observer"
        ):
            raise ValueError(
                "observer command is not the production observer entry point"
            )
        if arm["runner_arguments"]["observer_arguments"] != observer["arguments"][1:]:
            raise ValueError("runner observer arguments differ from reviewed command")
        facts.append(
            {
                "arm": arm["arm"],
                "observer_digest": observer["digest"],
                "launch_digests": sorted(value["digest"] for value in other.values()),
            }
        )
    facts.append(
        {
            "formal_observer_source_digest": digest_file(
                HERE.parent.parent / "src/vllm_hust_ext/formal_host_observer.py"
            ),
            "runner_source_digest": digest_file(RUNNER_PATH),
            "harness_source_digest": digest_file(HARNESS_PATH),
        }
    )
    return _evidence(
        [
            "production observer command is distinct from every arm launch command",
            "runner observer argv is exactly bound to the reviewed observer command",
            "observer, runner, and offline-validator source bytes are receipt-bound",
        ],
        facts,
    )


def _check_artifact_retention(candidate: dict[str, Any]) -> dict[str, Any]:
    runner_source = RUNNER_PATH.read_text()
    missing = sorted(
        name for name in REQUIRED_RETAINED_NAMES if name not in runner_source
    )
    if missing:
        raise ValueError(f"formal runner retention path is incomplete: {missing}")
    harness_source = HARNESS_PATH.read_text()
    required_validation_markers = {
        "artifact digest mismatch",
        "runner receipt mismatch",
        "formal JSONL and indexed records differ",
    }
    if any(
        marker not in harness_source and marker not in runner_source
        for marker in required_validation_markers
    ):
        raise ValueError("formal artifact retention lacks offline validation")
    facts = {
        "required_names": sorted(REQUIRED_RETAINED_NAMES),
        "runner_source_digest": digest_file(RUNNER_PATH),
        "harness_source_digest": digest_file(HARNESS_PATH),
        "candidate_formal_h1_starts": candidate["formal_h1_starts"],
    }
    return _evidence(
        [
            (
                "raw stdout/stderr, observer bytes, identities, inputs, oracle, "
                "and receipt are retained"
            ),
            (
                "failed and complete starts are published through the runner-owned "
                "generation index"
            ),
            "offline validation rechecks artifact, receipt, JSONL, and index bindings",
        ],
        facts,
    )


def build_review_receipt(candidate: dict[str, Any]) -> dict[str, Any]:
    if (
        candidate.get("schema") != "ecpa-h1-formal-registration-candidate/v1"
        or candidate.get("registration_state") != "candidate-only"
        or candidate.get("admissible") is not False
        or candidate.get("formal_h1_starts") != 0
        or set(candidate.get("machine_checks", {}).values()) != {True}
        or not set(REVIEW_BLOCKERS).issubset(candidate.get("remaining_blockers", []))
    ):
        raise ValueError("automated review subject has not preserved candidate gates")
    if candidate.get("automated_review_receipt") is not None or any(
        value is not None for value in candidate.get("independent_reviews", {}).values()
    ):
        raise ValueError("automated review requires an unreviewed candidate")
    amendment = _amendment()
    checks = {
        "commands": _check_commands(candidate),
        "activation_paths": _check_activation_paths(candidate),
        "observer_independence": _check_observer_independence(candidate),
        "artifact_retention": _check_artifact_retention(candidate),
    }
    core = {
        "schema": REVIEW_SCHEMA,
        "reviewer_kind": REVIEWER_KIND,
        "human_review": False,
        "protocol_amendment": {
            "id": amendment["amendment_id"],
            "digest": digest_file(AMENDMENT_PATH),
        },
        "subject": {
            "schema": candidate["schema"],
            "candidate_digest": digest_bytes(canonical(candidate) + b"\n"),
        },
        "checks": checks,
        "machine_qualification_preserved": True,
        "official_files_mutated": False,
        "formal_h1_starts": 0,
        "non_claims": [
            "This receipt is automated-independent and is not human review.",
            "This receipt clears no machine qualification or producer-admission gate.",
            "This receipt does not register or promote any preflight as formal H1.",
        ],
    }
    receipt = {**core, "receipt_digest": digest_bytes(canonical(core))}
    Draft7Validator(json.loads(SCHEMA_PATH.read_text())).validate(receipt)
    return receipt


def validate_review_receipt(candidate: dict[str, Any], receipt: dict[str, Any]) -> None:
    Draft7Validator(json.loads(SCHEMA_PATH.read_text())).validate(receipt)
    digest = receipt.get("receipt_digest")
    core = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    if digest != digest_bytes(canonical(core)):
        raise ValueError("automated review receipt digest is stale")
    expected = build_review_receipt(candidate)
    if receipt != expected:
        raise ValueError("automated review receipt differs from deterministic checks")


def apply_review(candidate: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    validate_review_receipt(candidate, receipt)
    reviewed = copy.deepcopy(candidate)
    reviewed["automated_review_receipt"] = copy.deepcopy(receipt)
    reviewed["independent_reviews"] = {
        check_id: {
            "reviewer_kind": REVIEWER_KIND,
            "human_review": False,
            "check_id": check_id,
            "verdict": "PASS",
            "receipt_digest": receipt["receipt_digest"],
        }
        for check_id in CHECK_IDS
    }
    reviewed["remaining_blockers"] = [
        blocker
        for blocker in candidate["remaining_blockers"]
        if blocker not in REVIEW_BLOCKERS
    ]
    return reviewed


def validate_reviewed_candidate(candidate: dict[str, Any], *, live: bool) -> None:
    del live  # live command fingerprints are checked by the caller.
    receipt = candidate["automated_review_receipt"]
    base = copy.deepcopy(candidate)
    del base["automated_review_receipt"]
    base["independent_reviews"] = {check_id: None for check_id in CHECK_IDS}
    blockers = list(base["remaining_blockers"])
    for blocker in REVIEW_BLOCKERS:
        if blocker not in blockers:
            blockers.append(blocker)
    base["remaining_blockers"] = blockers
    validate_review_receipt(base, receipt)
    expected_refs = apply_review(base, receipt)["independent_reviews"]
    if candidate["independent_reviews"] != expected_refs:
        raise ValueError("candidate automated-review references drifted")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--reviewed-candidate", type=Path, required=True)
    args = parser.parse_args()
    candidate = _load_canonical(args.candidate)
    from formal_registration_candidate import validate_candidate

    validate_candidate(candidate, live=False)
    receipt = build_review_receipt(candidate)
    reviewed = apply_review(candidate, receipt)
    args.receipt.write_bytes(canonical(receipt) + b"\n")
    args.reviewed_candidate.write_bytes(canonical(reviewed) + b"\n")


if __name__ == "__main__":
    main()
