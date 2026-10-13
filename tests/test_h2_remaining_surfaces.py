from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_remaining_surface_oracle_and_prediction_are_portable() -> None:
    scripts = (
        ROOT
        / "experiments/real_mod_composition/verify_h2_remaining_surfaces_oracle.py",
        ROOT
        / "experiments/real_mod_composition/verify_h2_remaining_surface_prediction.py",
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
