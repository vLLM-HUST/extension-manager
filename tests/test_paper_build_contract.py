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


def test_makefile_uses_tectonic_for_every_paper_build() -> None:
    makefile = (ROOT / "paper/Makefile").read_text()

    assert "TECTONIC ?= tectonic" in makefile
    assert "all: main.pdf" in makefile
    assert "main.pdf: main.tex references.bib" in makefile
    assert "tectonic: main.pdf" in makefile
    assert "$(TECTONIC) --keep-logs main.tex" in makefile
    assert "LATEXMK" not in makefile
    assert "pdflatex" not in makefile.lower()


def test_makefile_uses_configurable_python_for_validation_and_audit() -> None:
    makefile = (ROOT / "paper/Makefile").read_text()

    assert "PYTHON ?= python3" in makefile
    assert "\tpython3 " not in makefile
    assert "\t$(PYTHON) scripts/audit_pdf.py main.pdf" in makefile
    assert "\t$(PYTHON) scripts/generate_evidence_summary.py" in makefile
    assert "\t$(PYTHON) ../scripts/validate_research_matrix.py" in makefile
    assert "\t$(PYTHON) scripts/validate_results.py" in makefile


def test_title_states_the_problem_and_solution_without_relying_on_acronym() -> None:
    paper = (ROOT / "paper/main.tex").read_text()

    assert (
        "Making LLM Inference Extensions Compose: Contracts for Interfaces, "
        "Dependencies, and Runtime Effects" in paper
    )
    assert "\\title{\\Large \\bf ECPA:" not in paper


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
    assert "Release \\ECPAReleaseVersion{}" in paper
    assert "Manifest \\ECPAManifestVersion{}" in paper
    assert "Release Qualification Outside the Formal Aggregate" in paper
    assert "one pinned vLLM-HUST/Ascend launch" in normalized_paper
    assert "no real vLLM host" not in normalized_paper
    assert "All runtime and performance quantities remain planned" not in paper
