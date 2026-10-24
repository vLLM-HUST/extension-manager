"""Resolve migrated inputs externally; preserve isolated negative-test roots."""

import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def original_path(root: Path, relative: str) -> Path:
    if root.resolve() != ROOT:
        return root / relative
    config = json.loads((ROOT / "BENCHMARK_ORIGINALS.json").read_text())
    hashes = config.get("migrated_sha256", {})
    selected = {
        name: sha
        for name, sha in hashes.items()
        if name == relative or name.startswith(relative.rstrip("/") + "/")
    }
    if not selected:
        return root / relative
    value = os.environ.get("VLLM_HUST_BENCHMARK_ORIGINALS")
    if not value:
        raise ValueError("Download originals and set VLLM_HUST_BENCHMARK_ORIGINALS")
    external = Path(value).resolve()
    if external == ROOT or ROOT in external.parents:
        raise ValueError("Originals must be outside the source checkout")
    path = (external / relative).resolve()
    if external not in path.parents:
        raise ValueError("Unsafe original input path")
    for name, expected in selected.items():
        member = (external / name).resolve()
        if external not in member.parents:
            raise ValueError("Unsafe original input path")
        if hashlib.sha256(member.read_bytes()).hexdigest() != expected:
            raise ValueError("Original input checksum mismatch")
    if relative not in selected:
        actual = {
            p.relative_to(external).as_posix() for p in path.rglob("*") if p.is_file()
        }
        if actual != set(selected):
            raise ValueError("Unexpected original directory member")
    return path


def resolve_original(path: Path) -> Path:
    """Resolve read-only repository inputs, leaving caller-owned fixtures alone."""
    # Classify the requested source path before following symlinks. A local
    # symlink must not bypass the canonical external hash check.
    absolute = Path(os.path.abspath(path))
    if ROOT not in absolute.parents:
        return path
    return original_path(ROOT, absolute.relative_to(ROOT).as_posix())


def new_output(path: Path) -> Path:
    """Validate a fresh output outside source and immutable input trees."""
    target = path.resolve()
    roots = [ROOT]
    external = os.environ.get("VLLM_HUST_BENCHMARK_ORIGINALS")
    if external:
        roots.append(Path(external).resolve())
    if (
        path.is_symlink()
        or target.exists()
        or any(
            target == root or root in target.parents or target in root.parents
            for root in roots
        )
    ):
        raise ValueError("Output must be new and outside source and originals")
    return target


def output_argument(*, directory: bool = False) -> Path:
    """Reserve a fresh explicit output before a builder/collector does work."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    target = new_output(parser.parse_args().output)
    if directory:
        target.mkdir(parents=True, exist_ok=False)
    else:
        # The caller writes with exclusive creation after collection succeeds.
        target.parent.mkdir(parents=True, exist_ok=True)
    return target


if __name__ == "__main__":
    config = json.loads((ROOT / "BENCHMARK_ORIGINALS.json").read_text())
    for relative in config["migrated_sha256"]:
        original_path(ROOT, relative)
    print(f"Verified {len(config['migrated_sha256'])} migrated inputs")
