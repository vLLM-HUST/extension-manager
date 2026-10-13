from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_process_carrier_oracle_and_predictions_are_portable() -> None:
    scripts = (
        ROOT / "experiments/real_mod_composition/verify_h2_process_carrier_oracle.py",
        ROOT
        / "experiments/real_mod_composition/verify_h2_process_carrier_predictions.py",
    )
    for script in scripts:
        completed = subprocess.run(
            [sys.executable, str(script)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.startswith("PASS ")
