#!/usr/bin/env python3
"""Render a private anonymity overlay with Tectonic, never in the Git tree.

This is a mechanical first pass. Human authors must review identity by
implication, claims, references, and final formatting before submission.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

PAPER = Path(__file__).resolve().parents[1]
PUBLIC_TITLE = (
    "From Enabled to Effective: Evidence-Bound Activation for LLM Inference Extensions"
)
SAFE_ALIAS = re.compile(r"[A-Za-z][A-Za-z0-9]{3,31}\Z")
SAFE_TITLE = re.compile(r"[A-Za-z0-9 ,:;!?()'\-]{12,180}\Z")


def prepare(output: Path, *, alias: str, title: str) -> Path:
    """Copy and mechanically anonymize the public TeX inputs to a new directory."""
    if not SAFE_ALIAS.fullmatch(alias) or "ecpa" in alias.casefold():
        raise ValueError("alias must be an unpublished alphanumeric name")
    if not SAFE_TITLE.fullmatch(title) or any(
        name in title.casefold()
        for name in ("ecpa", "vllm-hust", PUBLIC_TITLE.casefold())
    ):
        raise ValueError("title must be a new plain-text title")
    output = output.resolve()
    if any((ancestor / ".git").exists() for ancestor in (output, *output.parents)):
        raise ValueError("private output must be outside every Git repository")
    if output.exists():
        raise FileExistsError(output)

    source = (PAPER / "main.tex").read_text(encoding="utf-8")
    old_title = rf"\title{{\Large \bf {PUBLIC_TITLE}}}"
    new_title = rf"\title{{\Large \bf {title}}}"
    if source.count(old_title) != 1:
        raise ValueError("public title changed; review the anonymity transform")
    source = source.replace(old_title, new_title)
    accountability = (
        "% Internal accountability (excluded from the anonymized author line):\n"
        "% ShuhaoZhangTony / 张书豪 is the PI lead and accountable executor. Student\n"
        "% participation is optional and non-blocking.\n"
    )
    if source.count(accountability) != 1:
        raise ValueError("accountability comment changed; review the transform")
    source = source.replace(accountability, "")
    source = re.sub(r"(?<!\\)\bECPA\b", alias, source)
    source = source.replace("vLLM-HUST", "prototype host")
    article = "an" if alias[0].lower() in "aeiou" else "a"
    source = source.replace(f"an {alias}-controlled", f"{article} {alias}-controlled")
    source = source.replace("prototype host host", "prototype host")
    for forbidden in ("vLLM-HUST", "ShuhaoZhangTony", PUBLIC_TITLE):
        if forbidden in source:
            raise ValueError(f"public identifier remains in TeX: {forbidden}")
    output.mkdir(parents=True, exist_ok=False)
    (output / "generated").mkdir()
    (output / "main.tex").write_text(source, encoding="utf-8")
    for name in ("references.bib", "usenix2019_v3.sty"):
        shutil.copyfile(PAPER / name, output / name)
    shutil.copyfile(
        PAPER / "generated/evidence-summary.tex",
        output / "generated/evidence-summary.tex",
    )
    return output / "main.tex"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--alias", required=True)
    parser.add_argument("--title", required=True)
    arguments = parser.parse_args()
    subprocess.run(
        [
            "make",
            "-C",
            str(PAPER),
            f"PYTHON={sys.executable}",
            "check-evidence-summary",
        ],
        check=True,
    )
    try:
        main_tex = prepare(
            arguments.output, alias=arguments.alias, title=arguments.title
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    subprocess.run(
        ["tectonic", "--keep-logs", main_tex.name], cwd=main_tex.parent, check=True
    )
    subprocess.run(
        [
            sys.executable,
            str(PAPER / "scripts/audit_pdf.py"),
            "main.pdf",
            "--anonymous",
        ],
        cwd=main_tex.parent,
        check=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
