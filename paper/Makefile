TECTONIC ?= tectonic
PYTHON ?= python3
.PHONY: all main.pdf clean evidence-summary check-evidence-summary check-attention-source-summary check-research-matrix tectonic audit-pdf validate-results
all: tectonic

.PHONY: check-benchmark-originals
check-benchmark-originals:
	$(PYTHON) ../scripts/benchmark_inputs.py

evidence-summary: check-benchmark-originals
	@test -n "$(OUTPUT)" || (echo 'Set OUTPUT to a fresh external file'; exit 1)
	$(PYTHON) scripts/generate_evidence_summary.py --output "$(OUTPUT)"

check-evidence-summary:
	$(PYTHON) scripts/generate_evidence_summary.py --check

check-research-matrix:
	$(PYTHON) ../scripts/validate_research_matrix.py

check-attention-source-summary:
	$(PYTHON) scripts/generate_attention_source_summary.py --check

main.pdf tectonic:
	@test -n "$(OUTPUT)" || (echo 'Set OUTPUT to a fresh external build directory'; exit 1)
	$(PYTHON) scripts/build_paper.py --output "$(OUTPUT)" --tectonic "$(TECTONIC)"

audit-pdf:
	@test -n "$(OUTPUT)" || (echo 'Set OUTPUT to an existing external build directory'; exit 1)
	$(PYTHON) scripts/audit_pdf.py "$(OUTPUT)/main.pdf"

validate-results: check-evidence-summary check-research-matrix
	$(PYTHON) scripts/validate_results.py artifacts/results.example.json

clean:
	$(RM) main.pdf main.log main.blg main.aux main.bcf main.run.xml main.synctex.gz
