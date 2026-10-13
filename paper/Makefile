TECTONIC ?= tectonic
PYTHON ?= python3
EVIDENCE_SUMMARY := generated/evidence-summary.tex
EVIDENCE_INPUTS := \
	../docs/corpus/plugin-workshop-metadata.snapshot.json \
	../docs/corpus/workshop-mods.json \
	../docs/corpus/workshop-mods.schema.json \
	../docs/corpus/plugins.json \
	../docs/corpus/plugins.schema.json \
	../docs/corpus/source-snapshots.json \
	../docs/corpus/source-snapshots.schema.json \
	../docs/research/claims-to-experiment-matrix.json \
	../docs/research/claims-to-experiment-matrix.schema.json \
	../docs/release-readiness.json \
	../docs/release-readiness.schema.json \
	../docs/evidence/native-current-npu-qualification-2026-10-11.md \
	../.github/workflows/ci.yml \
	../docs/acceptance-gates.md \
	../docs/design/failure-semantics.md \
	../docs/design/host-plugin-evidence-0.1.md \
	../docs/evaluation-plan.md \
	../docs/evidence/host-contract-maintainer-acceptance-2026-10-10.md \
	../docs/failure-permission-matrix.json \
	../docs/kv-materialization-runbook.md \
	../docs/manifest-0.3.md \
	../docs/qualification-policy.md \
	../docs/support-matrix.md \
	../src/vllm_hust_ext/catalog.py \
	../tests/test_catalog.py \
	../tests/test_failure_permission_matrix.py \
	../experiments/contract_planner/cases.json \
	../experiments/contract_planner/cases.schema.json \
	../experiments/contract_planner/decision.schema.json \
	../experiments/contract_planner/oracle.json \
	../experiments/contract_planner/oracle.schema.json \
	../experiments/contract_planner/evaluate.py \
	../experiments/contract_planner/metrics.schema.json \
	../experiments/contract_planner/results/decisions.jsonl \
	../experiments/contract_planner/results/metrics.json \
	../experiments/false_effective/artifacts/formal-aggregate-summary.json \
	../experiments/false_effective/artifacts/reference-summary.json \
	artifacts/h1-r5/formal-aggregate.json \
	artifacts/h1-r5/formal-aggregate-summary.json \
	artifacts/h1-r5/paper-results.jsonl \
	artifacts/h1-r5/paper-table.csv \
	artifacts/h1-r5/source-binding.json \
	artifacts/results.schema.json \
	../experiments/false_effective/first-formal-real-study.json \
	../experiments/false_effective/first-formal-real-study.schema.json \
	../experiments/false_effective/first-formal-real-deployment.json \
	../experiments/false_effective/first-formal-real-deployment.schema.json \
	../experiments/false_effective/harness.py \
	../experiments/false_effective/scenarios.json \
	../experiments/false_effective/protocol.json \
	../experiments/false_effective/verified-adapters.json \
	../experiments/real_mod_composition/artifacts/h2-knorm-prelaunch-reject-20261013.json \
	../experiments/real_mod_composition/artifacts/h2-source-corpus-manager-predictions-20261013.json \
	../experiments/real_mod_composition/artifacts/h2-profiler-kvcompress-formal-r2-20261013/score-admission.json \
	../experiments/real_mod_composition/artifacts/h2-profiler-kvcompress-formal-r2-20261013/planner/planner-receipt.json \
	../experiments/real_mod_composition/artifacts/h2-minimal-real-source-corpus-r2-20261013/campaign.json \
	../experiments/real_mod_composition/artifacts/h2-minimal-real-source-corpus-r2-20261013/oracle-index.json \
	../experiments/real_mod_composition/artifacts/h2-minimal-real-source-corpus-r2-20261013/status.json \
	../experiments/real_mod_composition/artifacts/h2-real-source-augmentation-20261013/augmentation.json \
	../experiments/real_mod_composition/artifacts/h2-process-carrier-oracle-20261013/oracle.json \
	../experiments/real_mod_composition/artifacts/h2-process-carrier-oracle-20261013/manager-predictions.json \
	../experiments/transaction_model/explore.py \
	../experiments/transaction_model/artifacts/result-summary.json \
	../experiments/transaction_model/result-summary.schema.json \
	../spec/0.1/contract-taxonomy.json \
	../spec/0.1/contract-taxonomy.schema.json \
	../spec/manifest-0.3/manifest.schema.json \
	../spec/manifest-0.3/conformance-vectors.json \
	../spec/manifest-0.3/migration-vectors.json \
	../src/vllm_hust_ext/contract_compiler.py \
	../src/vllm_hust_ext/formal_lifecycle_source.py

.PHONY: all clean evidence-summary check-evidence-summary check-research-matrix tectonic audit-pdf validate-results
all: main.pdf

$(EVIDENCE_SUMMARY): scripts/generate_evidence_summary.py $(EVIDENCE_INPUTS)
	$(PYTHON) scripts/generate_evidence_summary.py

evidence-summary: $(EVIDENCE_SUMMARY)

check-evidence-summary:
	$(PYTHON) scripts/generate_evidence_summary.py --check

check-research-matrix:
	$(PYTHON) ../scripts/validate_research_matrix.py

main.pdf: main.tex references.bib $(EVIDENCE_SUMMARY) check-research-matrix
	$(TECTONIC) --keep-logs main.tex

tectonic: main.pdf

audit-pdf: main.pdf
	$(PYTHON) scripts/audit_pdf.py main.pdf

validate-results: check-evidence-summary check-research-matrix
	$(PYTHON) scripts/validate_results.py artifacts/results.example.json

clean:
	$(RM) main.pdf main.log main.blg main.aux main.bcf main.run.xml main.synctex.gz
