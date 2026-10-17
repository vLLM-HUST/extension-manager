"""Original nine-slot sampled queue: real runner -> root witness -> full intake.

No retries/replacements, no lifecycle promotion, no test/qualification shortcut.
Each original raw run remains intact if independent intake rejects it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from .h4_sampled_registration import checked, validate_inputs
from .run_h4_sampled import write_new


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("campaign", "launch-spec", "deployment-receipt", "output"):
        p.add_argument("--" + key, type=Path, required=True)
    p.add_argument(
        "--artifact-root",
        type=Path,
        help=(
            "Default: common ancestor of the exact packet, "
            "original runs and queue output"
        ),
    )
    a = p.parse_args()
    if os.geteuid() != 0:
        raise ValueError("independent root queue required")
    os.umask(63)
    a.output.mkdir(mode=448, exist_ok=False)
    campaign, _, _, native = validate_inputs(a.campaign, a.launch_spec)
    if a.artifact_root is None:
        a.artifact_root = Path(
            os.path.commonpath(
                [
                    str(path.absolute())
                    for path in (
                        a.campaign,
                        a.launch_spec,
                        a.deployment_receipt,
                        a.output,
                        *(Path(start["run_directory"]) for start in native["starts"]),
                    )
                ]
            )
        )
    rows = []
    error = None
    try:
        for index, start in enumerate(native["starts"], 1):
            phase = json.loads(checked(start["phase"]))
            if sys.executable != phase["argv"][0]:
                raise ValueError("exact selected runtime interpreter required")
            out = a.output / f"start-{index:02d}"
            out.mkdir(mode=448)
            env_path = out / "actual-frozen-phase-environment.json"
            write_new(env_path, phase["environment"])
            command = [
                sys.executable,
                "-m",
                "experiments.formal_campaign.h4_sampled_root_observer",
                "--campaign",
                str(a.campaign),
                "--launch-spec",
                str(a.launch_spec),
                "--deployment-receipt",
                str(a.deployment_receipt),
                "--start-id",
                start["start_id"],
                "--python",
                sys.executable,
                "--sdk",
                phase["cwd"],
                "--environment",
                str(env_path),
                "--output",
                str(out / "root-observation"),
            ]
            write_new(out / "root-observer-command.json", command)
            with (
                (out / "root-observer.stdout").open("xb") as stdout,
                (out / "root-observer.stderr").open("xb") as stderr,
            ):
                result = subprocess.run(
                    command,
                    cwd=phase["cwd"],
                    env=phase["environment"],
                    stdout=stdout,
                    stderr=stderr,
                    check=False,
                )
            if result.returncode:
                raise ValueError(
                    "independent root observation/release failed; stop original queue"
                )
            root = out / "root-observation/independent-root-terminal.json"
            root_sha = hashlib.sha256(root.read_bytes()).hexdigest()
            command = [
                sys.executable,
                "-m",
                "experiments.formal_campaign.h4_sampled_record_bridge",
                "--campaign",
                str(a.campaign),
                "--launch-spec",
                str(a.launch_spec),
                "--deployment-receipt",
                str(a.deployment_receipt),
                "--start-id",
                start["start_id"],
                "--root-cleanup",
                str(root),
                "--root-cleanup-sha256",
                root_sha,
                "--output",
                str(out / "formal-record"),
                "--artifact-root",
                str(a.artifact_root),
            ]
            write_new(out / "independent-intake-command.json", command)
            with (
                (out / "intake.stdout").open("xb") as stdout,
                (out / "intake.stderr").open("xb") as stderr,
            ):
                result = subprocess.run(
                    command,
                    cwd=phase["cwd"],
                    env=phase["environment"],
                    stdout=stdout,
                    stderr=stderr,
                    check=False,
                )
            if result.returncode:
                raise ValueError(
                    "independent full sampled intake rejected; original run unmodified"
                )
            observation = json.loads(
                (out / "formal-record/independent-start-observation.json").read_bytes()
            )
            if observation.get("formal_start_validated") is not True:
                raise ValueError("source-owned start not admitted")
            rows.append(
                dict(
                    index=index,
                    start_id=start["start_id"],
                    independent_observation=str(
                        out / "formal-record/independent-start-observation.json"
                    ),
                    record=str(out / "formal-record/record.json"),
                    record_sha256=hashlib.sha256(
                        (out / "formal-record/record.json").read_bytes()
                    ).hexdigest(),
                    formal_start_validated=True,
                    performance_eligible=observation["performance_eligible"],
                    status=observation["status"],
                    coverage=observation["coverage"],
                    observed_failure=observation["observed_failure"],
                )
            )
    except Exception as exc:
        error = repr(exc)
    finally:
        with (a.output / "records.jsonl").open("xb") as ledger:
            for row in rows:
                raw = Path(row["record"]).read_bytes()
                if hashlib.sha256(raw).hexdigest() != row["record_sha256"]:
                    raise ValueError(
                        "verified slot record changed before queue ledger write"
                    )
                ledger.write(raw + b"\n")
            ledger.flush()
            os.fsync(ledger.fileno())
        write_new(
            a.output / "queue-terminal.json",
            dict(
                schema="ecpa-h4-original-sampled-nine-root-queue/v1",
                original_cell=campaign["cell_id"],
                original_planned_starts=9,
                rows=rows,
                error=error,
                formal_result=False,
                H4_hypothesis_claim=False,
                original36_target_unchanged=True,
            ),
        )
    return 2 if error else 0


if __name__ == "__main__":
    raise SystemExit(main())
