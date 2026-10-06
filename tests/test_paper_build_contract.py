from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_vendored_style_has_explicit_pdftex_and_xetex_paths() -> None:
    style = (ROOT / "paper/usenix2019_v3.sty").read_text()

    assert "\\usepackage{iftex}" in style
    assert "\\usepackage[utf8]{inputenc}" in style
    assert "\\usepackage[kerning,spacing]{microtype}" in style
    assert "\\usepackage{microtype}" in style
    assert "\\usepackage{breakurl}" in style
    assert style.count("\\ifPDFTeX") == 3


def test_makefile_exposes_same_source_tectonic_build() -> None:
    makefile = (ROOT / "paper/Makefile").read_text()

    assert "TECTONIC ?= tectonic" in makefile
    assert "tectonic: main.tex references.bib" in makefile
    assert "$(TECTONIC) --keep-logs main.tex" in makefile


def test_detailed_architecture_preserves_evidence_authority_boundaries() -> None:
    detail_path = ROOT / "docs/design/ecpa-reference-manager-detailed.md"
    detail = detail_path.read_text()
    paper = (ROOT / "paper/main.tex").read_text()
    normalized_paper = " ".join(paper.split())

    assert (detail_path.parent / "../evaluation-plan.md").resolve().is_file()
    assert "ecpa_model.py: Plan.obligations" in detail
    assert "ecpa_model.py: Plan.targets" not in detail
    assert "not runtime_effective" in detail
    assert "reference lease interface; fake binding only" in detail
    assert "return independent effect evidence" not in normalized_paper
    assert "Only the vLLM host path currently feeds" in normalized_paper
    assert "they are not process-owned runtime-effect attestations" in normalized_paper
