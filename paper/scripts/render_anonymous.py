#!/usr/bin/env python3
"""Render a private anonymity overlay with Tectonic, never in the Git tree.

This is a mechanical first pass. Human authors must review identity by
implication, claims, references, and final formatting before submission.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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
    # Rename internal commands too: the private source must not disclose the alias.
    source = source.replace(r"\ECPA", r"\ReviewData")
    source = source.replace("ECPA", alias).replace("ecpa", "review")
    source = source.replace(
        "3e57b2f75cffffd26dda0df4d9bcac890cfe99fc", "host-snapshot-A"
    )
    source = source.replace("3201e133", "incident-snapshot-B")
    source = source.replace("vLLM-HUST", "prototype host")
    article = "an" if alias[0].lower() in "aeiou" else "a"
    source = source.replace(f"an {alias}-controlled", f"{article} {alias}-controlled")
    source = source.replace("prototype host host", "prototype host")
    for forbidden in ("ECPA", "vLLM-HUST", "ShuhaoZhangTony", "张书豪", PUBLIC_TITLE):
        if forbidden in source:
            raise ValueError(f"public identifier remains in TeX: {forbidden}")
    output.mkdir(parents=True, exist_ok=False)
    (output / "generated").mkdir()
    (output / "main.tex").write_text(source, encoding="utf-8")
    for name in ("references.bib", "usenix2019_v3.sty"):
        shutil.copyfile(PAPER / name, output / name)
    generated = (PAPER / "generated/evidence-summary.tex").read_text(encoding="utf-8")
    (output / "generated/evidence-summary.tex").write_text(
        generated.replace("ECPA", "ReviewData"), encoding="utf-8"
    )
    return output / "main.tex"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--alias", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--tectonic", default=os.environ.get("TECTONIC", "tectonic"))
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
        [arguments.tectonic, "--keep-logs", main_tex.name],
        cwd=main_tex.parent,
        check=True,
    )
    audit = subprocess.run(
        [
            sys.executable,
            str(PAPER / "scripts/audit_pdf.py"),
            "main.pdf",
            "--anonymous",
        ],
        cwd=main_tex.parent,
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(audit.stdout)
    result["pdf"] = "main.pdf"
    (main_tex.parent / "pdf-audit.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    # Local provenance only: never include this file in a blind submission.
    names = (
        "main.tex",
        "references.bib",
        "usenix2019_v3.sty",
        "generated/evidence-summary.tex",
        "main.pdf",
        "pdf-audit.json",
    )
    manifest = {
        "schema": "private-anonymous-build-v1",
        "compiler": subprocess.check_output(
            [arguments.tectonic, "--version"], text=True
        ).strip(),
        "builder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "audit_sha256": hashlib.sha256(
            (PAPER / "scripts/audit_pdf.py").read_bytes()
        ).hexdigest(),
        "source_sha256": hashlib.sha256((PAPER / "main.tex").read_bytes()).hexdigest(),
        "files": {
            name: hashlib.sha256((main_tex.parent / name).read_bytes()).hexdigest()
            for name in names
        },
        "claim": "listed identity checks pass; implication anonymity unproven",
        "submission_file": "main.pdf",
    }
    (main_tex.parent / "private-build-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
