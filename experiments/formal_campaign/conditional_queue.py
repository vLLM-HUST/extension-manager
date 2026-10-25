"""Actual no-retry original Latin9 queue. Release is independently re-read."""

from __future__ import annotations

import argparse
import subprocess
import time
from pathlib import Path

from .conditional_common import load, private_directory, reference, require, write
from .conditional_record_bridge import export
from .conditional_registration import validate_inputs


def run(receipt_ref, output, artifact_root):
    receipt = load(receipt_ref)
    campaign, launch, _, inputs = validate_inputs(
        receipt["campaign"], receipt["launch"]
    )
    require(
        campaign["execution_domain"] == "registered-original-starts",
        "only original registered cohort can run nine",
    )
    output = private_directory(output)
    records = []
    write(
        output / "queue-invocation.json",
        dict(
            receipt=receipt_ref,
            campaign=receipt["campaign"],
            launch=receipt["launch"],
            original_start_ids=[s["start_id"] for s in inputs["starts"]],
            retries=0,
        ),
    )
    for index, start in enumerate(inputs["starts"], 1):
        phase = load(start["phase"])
        slot = private_directory(output / f"{index:02d}")
        env_path = slot / "environment.json"
        write(env_path, phase["environment"])
        argv = [
            phase["python"],
            "-B",
            "-m",
            "experiments.formal_campaign.conditional_root_observer",
            "--campaign",
            receipt["campaign"]["path"],
            "--launch-spec",
            receipt["launch"]["path"],
            "--receipt",
            receipt_ref["path"],
            "--start-id",
            start["start_id"],
            "--python",
            phase["python"],
            "--sdk",
            phase["cwd"],
            "--environment",
            str(env_path),
            "--output",
            str(slot / "root"),
        ]
        write(
            slot / "command.json",
            dict(
                argv=argv,
                cwd=phase["cwd"],
                environment=reference(env_path),
                before_wall_ns=time.time_ns(),
            ),
        )
        with (slot / "stdout").open("xb") as out, (slot / "stderr").open("xb") as err:
            child = subprocess.Popen(
                argv, cwd=phase["cwd"], env=phase["environment"], stdout=out, stderr=err
            )
            # No timeout signalling or guessed cleanup: observer must retain the
            # actual product epoch through original producer cleanup to release.
            rc = child.wait()
        write(
            slot / "terminal.json",
            dict(pid=child.pid, returncode=rc, after_wall_ns=time.time_ns()),
        )
        require(rc == 0, "independent observer failed; stop without retry/replacement")
        record = export(
            receipt["campaign"]["path"],
            receipt["launch"]["path"],
            receipt_ref["path"],
            start["start_id"],
            reference(slot / "root/independent-root-terminal.json"),
            slot / "record",
            artifact_root,
        )
        require(
            all(
                record["cleanup"][k] is True
                for k in ("processes_reclaimed", "ports_reclaimed", "devices_reclaimed")
            ),
            "unreleased start cannot advance",
        )
        records.append(reference(slot / "record/record.json"))
        write(
            output / f"progress-{index:02d}.json",
            dict(
                completed=index,
                original_start_id=start["start_id"],
                status=record["status"],
                records=records,
            ),
        )
    require(len(records) == 9, "original nine incomplete")
    # This report counts one exact new cohort only. Original36 analysis across
    # all four cells remains a separate original protocol operation.
    write(
        output / "cohort-report.json",
        dict(
            schema="ecpa-h4-conditional-original-nine-report/v1",
            fixed_identity=campaign["fixed_identity"],
            cell_id=campaign["cell_id"],
            records=records,
            all_cleanup_verified=True,
            H4_hypothesis_claim=False,
            original36_complete=False,
        ),
    )
    return records


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--receipt", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--artifact-root", type=Path, required=True)
    a = p.parse_args()
    run(reference(a.receipt), a.output, a.artifact_root)


if __name__ == "__main__":
    main()
