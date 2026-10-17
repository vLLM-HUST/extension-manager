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
    a = p.parse_args()
    if os.geteuid() != 0:
        raise ValueError("independent root queue required")
    os.umask(0o077)
    a.output.mkdir(mode=0o700, exist_ok=False)
    campaign, _, _, native = validate_inputs(a.campaign, a.launch_spec)
    rows = []
    error = None
    try:
        for index, start in enumerate(native["starts"], 1):
            phase = json.loads(checked(start["phase"]))
            if sys.executable != phase["argv"][0]:
                raise ValueError("exact selected runtime interpreter required")
            out = a.output / f"start-{index:02d}"
            out.mkdir(mode=0o700)
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
                    "actual observer/source run failed; original streams retained"
                )
            root = out / "root-observation/independent-root-terminal.json"
            root_sha = hashlib.sha256(root.read_bytes()).hexdigest()
            command = [
                sys.executable,
                "-m",
                "experiments.formal_campaign.h4_sampled_intake",
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
                str(out / "independent-start-observation.json"),
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
                (out / "independent-start-observation.json").read_bytes()
            )
            if observation.get("formal_start_validated") is not True:
                raise ValueError("source-owned start not admitted")
            rows.append(
                dict(
                    index=index,
                    start_id=start["start_id"],
                    independent_observation=str(
                        out / "independent-start-observation.json"
                    ),
                    formal_start_validated=True,
                    performance_eligible=observation["performance_eligible"],
                )
            )
    except Exception as exc:
        error = repr(exc)
    finally:
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
