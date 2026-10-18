"""Actual future qualification -> original two conditional Latin9 cells.

No execution occurs during source preparation. Root must explicitly invoke this
entry in a newly built/installed/source-admitted conditional runtime window.
"""

from __future__ import annotations

import argparse
import subprocess
import time
from pathlib import Path

from .conditional_common import (
    load,
    private_directory,
    reference,
    require,
    write,
)
from .conditional_prepare import assemble
from .conditional_qualification import freeze
from .conditional_queue import run
from .conditional_registration import issue


def execute(actual_ref, output):
    import os

    require(os.geteuid() == 0, "actual independent root execution required")
    output = private_directory(output)
    actual = load(actual_ref)
    write(
        output / "entry-input.json",
        dict(
            actual=actual_ref,
            started_wall_ns=time.time_ns(),
            retries=0,
            formal_result=False,
        ),
    )
    bootstrap = output / "qualification-packet"
    campaign_ref, launch_ref = assemble(
        actual_ref, bootstrap, "conditional-resource-pair.sampled-invocation"
    )
    commands = load(reference(bootstrap / "commands.json"))
    campaign = load(campaign_ref)
    inputs = load(campaign["conditional_inputs"])
    start = next(
        s for s in inputs["starts"] if s["start_id"] == commands["qualification_start"]
    )
    phase = load(start["phase"])
    argv = commands["observe_qualification"]
    require(not (output / "qualification.stdout").exists(), "no retry")
    write(
        output / "qualification-command.json",
        dict(
            argv=argv,
            cwd=phase["cwd"],
            phase=start["phase"],
            before_wall_ns=time.time_ns(),
        ),
    )
    with (
        (output / "qualification.stdout").open("xb") as out,
        (output / "qualification.stderr").open("xb") as err,
    ):
        child = subprocess.Popen(
            argv, cwd=phase["cwd"], env=phase["environment"], stdout=out, stderr=err
        )
        rc = child.wait()
    write(
        output / "qualification-terminal.json",
        dict(pid=child.pid, returncode=rc, after_wall_ns=time.time_ns()),
    )
    require(
        rc == 0,
        "actual independent qualification observer failed; keep raw records and stop",
    )
    report_path = bootstrap / "actual-qualification.json"
    freeze(
        campaign_ref,
        launch_ref,
        start["start_id"],
        start["run_directory"],
        reference(bootstrap / "qualification-root/independent-root-terminal.json"),
        report_path,
    )
    qualification_ref = reference(report_path)
    reports = []
    for label in ("lifecycle-only", "sampled-invocation"):
        cell = "conditional-resource-pair." + label
        packet = output / label
        c, cell_launch = assemble(
            actual_ref, packet, cell, qualification_ref=qualification_ref
        )
        receipt_path = packet / "receipt.json"
        issue(c, cell_launch, receipt_path)
        # No manual ready/review flag or second admission substitute exists
        # between the real dual issuer and the original actual nine starts.
        run(reference(receipt_path), packet / "nine", Path("/"))
        reports.append(reference(packet / "nine/cohort-report.json"))
    write(
        output / "conditional-two-cell-report.json",
        dict(
            schema="ecpa-h4-original-conditional-two-cell-execution/v1",
            actual_inputs=actual_ref,
            fixed_identity=actual["fixed_identity"],
            qualification=qualification_ref,
            cell_reports=reports,
            original_conditional_starts=18,
            original36_complete=False,
            H4_hypothesis_claim=False,
        ),
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--actual-inputs", type=Path, required=True)
    p.add_argument("--actual-inputs-sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    execute(
        dict(path=str(a.actual_inputs.resolve()), sha256=a.actual_inputs_sha256),
        a.output,
    )


if __name__ == "__main__":
    main()
