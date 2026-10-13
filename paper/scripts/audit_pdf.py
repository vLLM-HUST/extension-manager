#!/usr/bin/env python3
"""Check the rendered OSDI PDF; this never substitutes for a human review."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

import pymupdf

PUBLIC_IDENTIFIERS = (
    "ECPA",
    "vLLM-HUST",
    "intellistream",
    "ShuhaoZhangTony",
    "From Enabled to Effective",
    "extension-manager",
    "张书豪",
    "3e57b2f75cffffd26dda0df4d9bcac890cfe99fc",
    "3201e133",
)


def _reference_boundary(document: pymupdf.Document) -> tuple[int, int]:
    """Return one-based reference and last body pages, failing on ambiguity."""
    matches: list[tuple[int, str]] = []
    for index, page in enumerate(document):
        lines = page.get_text().splitlines()
        for offset, line in enumerate(lines):
            if line.strip() == "References":
                matches.append((index + 1, "\n".join(lines[:offset])))
    if len(matches) != 1:
        raise ValueError("expected exactly one References heading")
    reference_page, preceding = matches[0]
    preceding = "\n".join(
        line for line in preceding.splitlines() if line.strip() != str(reference_page)
    )
    last_body_page = reference_page if preceding.strip() else reference_page - 1
    return reference_page, last_body_page


def audit(path: Path, *, anonymous: bool = False) -> dict[str, object]:
    errors: list[str] = []
    document = pymupdf.open(path)
    try:
        if not document.is_pdf or document.is_encrypted:
            raise ValueError("input must be an unencrypted PDF")
        reference_page, last_body_page = _reference_boundary(document)
        if last_body_page > 12:
            errors.append("body exceeds 12 pages")
        if not document.page_count:
            errors.append("PDF has no pages")

        all_text: list[str] = []
        body_sizes: list[float] = []
        embedded_fonts: dict[int, bool] = {}
        column_pages = 0
        for number, page in enumerate(document, 1):
            if abs(page.rect.width - 612) > 1 or abs(page.rect.height - 792) > 1:
                errors.append(f"page {number} is not US letter")
            text = page.get_text()
            all_text.append(text)
            footer = [
                block
                for block in page.get_text("blocks")
                if block[4].strip() == str(number) and block[1] > 720
            ]
            if not footer:
                errors.append(f"page {number} has no footer page number")
            for font in page.get_fonts(full=True):
                xref = font[0]
                if xref not in embedded_fonts:
                    embedded_fonts[xref] = bool(document.extract_font(xref)[3])
            if number > last_body_page:
                continue
            left = right = False
            for block in page.get_text("dict")["blocks"]:
                for line in block.get("lines", []):
                    for span in line["spans"]:
                        if 9.7 <= span["size"] <= 10.3:
                            body_sizes.append(span["size"])
                            left |= 48 <= span["bbox"][0] < 260
                            right |= 300 < span["bbox"][0] <= 565
            column_pages += int(left and right)
        if embedded_fonts and not all(embedded_fonts.values()):
            errors.append("one or more PDF fonts are not embedded")
        if not body_sizes or abs(statistics.median(body_sizes) - 10) > 0.3:
            errors.append("body type does not have a 10-point median")
        if last_body_page >= 3 and column_pages < (last_body_page - 1) // 2:
            errors.append("two-column body layout was not detected on enough pages")

        if anonymous:
            searchable = (
                "\n".join(all_text)
                + "\n"
                + json.dumps(document.metadata, sort_keys=True, ensure_ascii=False)
                + "\n"
                + document.get_xml_metadata()
                + "\n"
                + json.dumps(document.get_toc(), ensure_ascii=False)
                + "\n"
                + "\n".join(
                    json.dumps(page.get_links(), ensure_ascii=False, default=str)
                    + "\n"
                    + "\n".join(
                        json.dumps(annotation.info, ensure_ascii=False)
                        for annotation in (page.annots() or [])
                    )
                    for page in document
                )
            )
            if document.embfile_count():
                errors.append("anonymous PDF must not contain embedded files")
            author = (document.metadata.get("author") or "").strip()
            if author and author.casefold() not in (
                "anonymous",
                "anonymous submission",
            ):
                errors.append("anonymous PDF has an identifying author field")
            for identifier in PUBLIC_IDENTIFIERS:
                if identifier.casefold() in searchable.casefold():
                    errors.append(f"public identifier remains: {identifier}")

        return {
            "pdf": str(path),
            "pages": document.page_count,
            "references_page": reference_page,
            "last_body_page": last_body_page,
            "embedded_fonts": len(embedded_fonts),
            "median_body_type_pt": (
                None if not body_sizes else round(statistics.median(body_sizes), 2)
            ),
            "two_column_pages": column_pages,
            "anonymous": anonymous,
            "errors": errors,
            "manual_checks": [
                "12-point leading and the 7-by-9-inch block require visual review",
                "figures and tables require grayscale legibility review",
                "implication-based identity leaks require human review",
            ],
        }
    finally:
        document.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pdf", type=Path)
    parser.add_argument("--anonymous", action="store_true")
    arguments = parser.parse_args()
    try:
        result = audit(arguments.pdf, anonymous=arguments.anonymous)
    except (OSError, ValueError) as exc:
        print(json.dumps({"errors": [str(exc)]}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return int(bool(result["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
