PYTHON ?= python3
.DEFAULT_GOAL := validate-results
.PHONY: evidence-summary check-evidence-summary check-attention-source-summary
.PHONY: check-research-matrix validate-results

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

validate-results: check-evidence-summary check-research-matrix
	$(PYTHON) scripts/validate_results.py artifacts/results.example.json
