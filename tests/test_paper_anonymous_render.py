from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import call

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "paper/scripts/render_anonymous.py"


def load_renderer():
    spec = importlib.util.spec_from_file_location("paper_anonymous_render", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_prepare_keeps_generated_commands_but_removes_public_identity(
    tmp_path: Path,
) -> None:
    renderer = load_renderer()
    output = tmp_path / "private-paper"

    assert (
        renderer.prepare(
            output, alias="ReviewSystem", title="Evidence Bound Inference Extensions"
        )
        == output / "main.tex"
    )

    source = (output / "main.tex").read_text()
    assert "ReviewSystem" in source
    assert "Evidence Bound Inference Extensions" in source
    assert "vLLM-HUST" not in source
    assert "ShuhaoZhangTony" not in source
    assert renderer.PUBLIC_TITLE not in source
    assert "an ReviewSystem-controlled" not in source
    assert "prototype host host" not in source
    assert "ECPA" not in source
    assert r"\ReviewDataWorkshopMods" in source
    assert "3e57b2f75cffffd26dda0df4d9bcac890cfe99fc" not in source
    assert "3201e133" not in source
    assert "ECPA" not in (output / "generated/evidence-summary.tex").read_text()
    assert (output / "generated/evidence-summary.tex").is_file()
    assert (output / "references.bib").is_file()
    assert (output / "usenix2019_v3.sty").is_file()


def test_prepare_rejects_public_or_unsafe_names(tmp_path: Path) -> None:
    renderer = load_renderer()
    for alias, title in (
        ("ECPA", "Evidence Bound Inference Extensions"),
        ("ECPALab", "Evidence Bound Inference Extensions"),
        ("Bad{TeX}", "Evidence Bound Inference Extensions"),
        ("ReviewSystem", renderer.PUBLIC_TITLE),
        ("ReviewSystem", "vLLM-HUST Extension Activation"),
        ("ReviewSystem", r"Input \input{secret}"),
    ):
        with pytest.raises(ValueError):
            renderer.prepare(tmp_path / "invalid", alias=alias, title=title)
    assert not (tmp_path / "invalid").exists()


def test_prepare_refuses_repository_or_existing_output(tmp_path: Path) -> None:
    renderer = load_renderer()
    with pytest.raises(ValueError, match="outside every Git repository"):
        renderer.prepare(
            ROOT / "paper/private",
            alias="ReviewSystem",
            title="Evidence Bound Inference Extensions",
        )
    output = tmp_path / "already-exists"
    output.mkdir()
    with pytest.raises(FileExistsError):
        renderer.prepare(
            output,
            alias="ReviewSystem",
            title="Evidence Bound Inference Extensions",
        )


def test_main_reuses_current_python_for_validation_and_pdf_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    renderer = load_renderer()
    output = tmp_path / "private-paper"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--output",
            str(output),
            "--alias",
            "ReviewSystem",
            "--title",
            "Evidence Bound Inference Extensions",
        ],
    )
    calls = []

    def record_run(command, **kwargs):
        calls.append(call(command, **kwargs))
        if command[0] == "tectonic":
            (output / "main.pdf").write_bytes(b"test PDF")
        return subprocess.CompletedProcess(command, 0, stdout='{"errors": []}')

    monkeypatch.setattr(renderer.subprocess, "run", record_run)
    monkeypatch.setattr(
        renderer.subprocess, "check_output", lambda *args, **kwargs: "tectonic 0.15.0\n"
    )

    assert renderer.main() == 0
    assert calls[0] == call(
        [
            "make",
            "-C",
            str(renderer.PAPER),
            f"PYTHON={sys.executable}",
            "check-evidence-summary",
        ],
        check=True,
    )
    assert calls[-1] == call(
        [
            sys.executable,
            str(renderer.PAPER / "scripts/audit_pdf.py"),
            "main.pdf",
            "--anonymous",
        ],
        cwd=output,
        check=True,
        capture_output=True,
        text=True,
    )
    manifest = json.loads((output / "private-build-manifest.json").read_text())
    assert manifest["submission_file"] == "main.pdf"
    assert len(manifest["files"]["main.pdf"]) == 64
    assert manifest["compiler"] == "tectonic 0.15.0"


def test_alphanumeric_alias_does_not_make_invalid_tex_macros(tmp_path: Path) -> None:
    renderer = load_renderer()
    output = tmp_path / "digits"
    renderer.prepare(
        output, alias="Review123", title="Evidence Bound Inference Extensions"
    )
    source = (output / "main.tex").read_text()
    assert r"\Review123" not in source
    assert r"\ReviewDataWorkshopMods" in source
