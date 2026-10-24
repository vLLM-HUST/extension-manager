"""Build from verified archived projections into a fresh external directory."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

PAPER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PAPER.parent))
from scripts.benchmark_inputs import new_output, resolve_original  # noqa: E402


def prepare(output: Path) -> Path:
    output = new_output(output)
    source = (PAPER / "main.tex").read_text()
    inputs = [
        Path(name) for name in re.findall(r"\\input\{(generated/[^}]+\.tex)\}", source)
    ]
    if any(path.is_absolute() or ".." in path.parts for path in inputs):
        raise ValueError("unsafe paper input")
    # Resolve/check every input before creating output. Never fall back to a
    # source-tree projection when a canonical archived input is unavailable.
    resolved = [(path, resolve_original(PAPER / path)) for path in inputs]
    output.mkdir(parents=True, exist_ok=False)
    for path in (Path("main.tex"), Path("references.bib"), Path("usenix2019_v3.sty")):
        shutil.copyfile(PAPER / path, output / path)
    for path, original in resolved:
        (output / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, output / path)
    return output / "main.tex"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tectonic", default="tectonic")
    args = parser.parse_args()
    new_output(args.output)
    subprocess.run(
        [
            "make",
            "-C",
            str(PAPER),
            f"PYTHON={sys.executable}",
            "check-evidence-summary",
            "check-attention-source-summary",
            "check-research-matrix",
        ],
        check=True,
    )
    main_tex = prepare(args.output)
    subprocess.run(
        [args.tectonic, "--keep-logs", main_tex.name], cwd=main_tex.parent, check=True
    )
    subprocess.run(
        [sys.executable, str(PAPER / "scripts/audit_pdf.py"), "main.pdf"],
        cwd=main_tex.parent,
        check=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
