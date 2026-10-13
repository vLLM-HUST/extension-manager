from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pymupdf
import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "paper/scripts/audit_pdf.py"


def load_audit():
    spec = importlib.util.spec_from_file_location("paper_pdf_audit", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_reference_boundary_rejects_body_on_page_thirteen() -> None:
    audit = load_audit()
    document = pymupdf.open()
    for _ in range(12):
        document.new_page()
    page = document.new_page()
    page.insert_text((60, 100), "Conclusion")
    page.insert_text((60, 130), "References")
    try:
        assert audit._reference_boundary(document) == (13, 13)
    finally:
        document.close()


def test_reference_boundary_allows_references_at_top_of_page_thirteen() -> None:
    audit = load_audit()
    document = pymupdf.open()
    for _ in range(12):
        document.new_page()
    document.new_page().insert_text((60, 100), "References")
    try:
        assert audit._reference_boundary(document) == (13, 12)
    finally:
        document.close()


def test_missing_or_duplicate_references_fail_closed() -> None:
    audit = load_audit()
    document = pymupdf.open()
    document.new_page()
    with pytest.raises(ValueError, match="exactly one"):
        audit._reference_boundary(document)
    document[0].insert_text((60, 100), "References")
    document.new_page().insert_text((60, 100), "References")
    with pytest.raises(ValueError, match="exactly one"):
        audit._reference_boundary(document)
    document.close()


def test_public_identifier_fails_anonymous_audit(tmp_path: Path) -> None:
    audit = load_audit()
    path = tmp_path / "draft.pdf"
    document = pymupdf.open()
    page = document.new_page(width=612, height=792)
    page.insert_text((60, 100), "ECPA")
    page.insert_text((60, 130), "References")
    page.insert_text((300, 750), "1")
    document.save(path)
    document.close()

    result = audit.audit(path, anonymous=True)
    assert "public identifier remains: ECPA" in result["errors"]


def test_body_on_page_thirteen_fails_pdf_audit(tmp_path: Path) -> None:
    audit = load_audit()
    path = tmp_path / "overlong.pdf"
    document = pymupdf.open()
    for number in range(1, 14):
        page = document.new_page(width=612, height=792)
        page.insert_text((60, 100), "Body text")
        page.insert_text((300, 750), str(number))
    document[-1].insert_text((60, 130), "References")
    document.save(path)
    document.close()

    result = audit.audit(path)
    assert result["last_body_page"] == 13
    assert "body exceeds 12 pages" in result["errors"]


@pytest.mark.parametrize(
    "surface", ["metadata", "xml", "link", "annotation", "author", "attachment"]
)
def test_anonymous_audit_rejects_hidden_identity(tmp_path: Path, surface: str) -> None:
    audit = load_audit()
    path = tmp_path / "hidden.pdf"
    document = pymupdf.open()
    page = document.new_page(width=612, height=792)
    page.insert_text((60, 100), "References")
    page.insert_text((300, 750), "1")
    if surface == "metadata":
        document.set_metadata({"subject": "ECPA"})
    elif surface == "xml":
        document.set_xml_metadata("<metadata>ECPA</metadata>")
    elif surface == "link":
        page.insert_link(
            {
                "kind": pymupdf.LINK_URI,
                "from": pymupdf.Rect(60, 100, 100, 115),
                "uri": "https://github.com/vLLM-HUST/extension-manager",
            }
        )
    elif surface == "annotation":
        page.add_text_annot((60, 150), "ShuhaoZhangTony")
    elif surface == "author":
        document.set_metadata({"author": "An Unlisted Person"})
    else:
        document.embfile_add("private-source.tex", b"identity")
    document.save(path)
    document.close()
    errors = audit.audit(path, anonymous=True)["errors"]
    assert any(
        "identifier" in error or "author field" in error or "embedded files" in error
        for error in errors
    )
