from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "experiments/real_mod_composition/verify_h2_scheduler_pair.py"
ARTIFACT = Path(
    "experiments/real_mod_composition/artifacts/h2-pipeline-bidkv-oracle-20261013"
)


def run_verifier(root: Path, script: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    return subprocess.run(
        [sys.executable, str(script)],
        cwd=root,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def test_scheduler_pair_oracle_precedes_matching_prediction() -> None:
    completed = run_verifier(ROOT, SCRIPT)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("PASS:")


def test_scheduler_pair_verifier_is_portable_without_git(tmp_path: Path) -> None:
    portable = tmp_path / "portable"
    shutil.copytree(ROOT / "src", portable / "src")
    shutil.copytree(ROOT / ARTIFACT, portable / ARTIFACT)
    target = portable / "experiments/real_mod_composition"
    target.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SCRIPT, target / SCRIPT.name)
    completed = run_verifier(portable, target / SCRIPT.name)
    assert completed.returncode == 0, completed.stderr


def test_scheduler_pair_verifier_rejects_oracle_rewrite(tmp_path: Path) -> None:
    portable = tmp_path / "portable"
    shutil.copytree(ROOT / "src", portable / "src")
    shutil.copytree(ROOT / ARTIFACT, portable / ARTIFACT)
    target = portable / "experiments/real_mod_composition"
    target.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SCRIPT, target / SCRIPT.name)
    oracle = portable / ARTIFACT / "oracle.json"
    oracle.write_text(
        oracle.read_text().replace('"decision": "admit"', '"decision": "reject"')
    )
    completed = run_verifier(portable, target / SCRIPT.name)
    assert completed.returncode != 0
    assert "oracle digest" in completed.stderr
