from __future__ import annotations

import os
import shutil
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


def test_remaining_surface_verifiers_do_not_require_git(
    tmp_path: Path,
) -> None:
    portable = tmp_path / "portable"
    artifact_rel = Path(
        "experiments/real_mod_composition/artifacts/"
        "h2-remaining-surfaces-oracle-20261013"
    )
    scripts = (
        "verify_h2_remaining_surfaces_oracle.py",
        "verify_h2_remaining_surface_prediction.py",
    )
    shutil.copytree(ROOT / "src", portable / "src")
    shutil.copytree(ROOT / artifact_rel, portable / artifact_rel)
    script_dir = portable / "experiments/real_mod_composition"
    for name in scripts:
        shutil.copy2(ROOT / "experiments/real_mod_composition" / name, script_dir)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(portable / "src")
    for name in scripts:
        completed = subprocess.run(
            [sys.executable, str(script_dir / name)],
            cwd=portable,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.startswith("PASS ")
