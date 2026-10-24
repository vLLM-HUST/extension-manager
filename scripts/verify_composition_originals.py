"""Export checked inputs and run unchanged, self-hashed oracle verifiers."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.benchmark_inputs import original_path  # noqa: E402

PREFIX = "experiments/real_mod_composition"
PACKAGES = {
    "process-carrier": (
        "verify_h2_process_carrier_oracle.py",
        "h2-process-carrier-oracle-20261013",
        "h2-real-source-augmentation-20261013",
    ),
    "remaining-surfaces": (
        "verify_h2_remaining_surfaces_oracle.py",
        "h2-remaining-surfaces-oracle-20261013",
    ),
}


def export(kind: str, destination: Path) -> Path:
    script, *packages = PACKAGES[kind]
    receipt = json.loads(
        original_path(
            ROOT, f"{PREFIX}/artifacts/{packages[0]}/review-receipt.json"
        ).read_text()
    )
    source = ROOT / PREFIX / script
    if hashlib.sha256(source.read_bytes()).hexdigest() != receipt["verifier_sha256"]:
        raise ValueError("Frozen verifier checksum mismatch")
    for package in packages:
        relative = f"{PREFIX}/artifacts/{package}"
        shutil.copytree(original_path(ROOT, relative), destination / relative)
    target = destination / PREFIX / script
    shutil.copyfile(source, target)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=PACKAGES)
    args, remaining = parser.parse_known_args()
    with tempfile.TemporaryDirectory(prefix="composition-originals-") as directory:
        target = export(args.kind, Path(directory))
        return subprocess.run(
            [sys.executable, str(target), *remaining], cwd=directory, check=False
        ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
