from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest
from jsonschema import ValidationError

ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = ROOT / "paper/scripts/generate_evidence_summary.py"
INPUTS = (
    "docs/corpus/plugin-workshop-metadata.snapshot.json",
    "docs/corpus/workshop-mods.json",
    "docs/corpus/workshop-mods.schema.json",
    "docs/corpus/plugins.json",
    "docs/corpus/plugins.schema.json",
    "docs/corpus/source-snapshots.json",
    "docs/corpus/source-snapshots.schema.json",
    "docs/research/claims-to-experiment-matrix.json",
    "docs/research/claims-to-experiment-matrix.schema.json",
    "docs/release-readiness.json",
    "docs/release-readiness.schema.json",
    "docs/evidence/native-current-npu-qualification-2026-10-11.md",
    "experiments/contract_planner/cases.json",
    "experiments/contract_planner/cases.schema.json",
    "experiments/contract_planner/decision.schema.json",
    "experiments/contract_planner/oracle.json",
    "experiments/contract_planner/oracle.schema.json",
    "experiments/contract_planner/evaluate.py",
    "experiments/contract_planner/metrics.schema.json",
    "experiments/contract_planner/results/decisions.jsonl",
    "experiments/contract_planner/results/metrics.json",
    "experiments/false_effective/artifacts/formal-aggregate-summary.json",
    "experiments/false_effective/artifacts/reference-summary.json",
    "experiments/false_effective/first-formal-real-study.json",
    "experiments/false_effective/first-formal-real-study.schema.json",
    "experiments/false_effective/first-formal-real-deployment.json",
    "experiments/false_effective/first-formal-real-deployment.schema.json",
    "experiments/false_effective/scenarios.json",
    "experiments/false_effective/protocol.json",
    "experiments/false_effective/verified-adapters.json",
    "experiments/real_mod_composition/artifacts/h2-knorm-prelaunch-reject-20261013.json",
    "experiments/real_mod_composition/artifacts/h2-source-corpus-manager-predictions-20261013.json",
    "experiments/real_mod_composition/artifacts/h2-profiler-kvcompress-formal-r2-20261013/score-admission.json",
    "experiments/real_mod_composition/artifacts/h2-profiler-kvcompress-formal-r2-20261013/planner/planner-receipt.json",
    "experiments/real_mod_composition/artifacts/h2-minimal-real-source-corpus-r2-20261013/campaign.json",
    "experiments/real_mod_composition/artifacts/h2-minimal-real-source-corpus-r2-20261013/oracle-index.json",
    "experiments/real_mod_composition/artifacts/h2-minimal-real-source-corpus-r2-20261013/status.json",
    "experiments/real_mod_composition/artifacts/h2-real-source-augmentation-20261013/augmentation.json",
    "experiments/real_mod_composition/artifacts/h2-process-carrier-oracle-20261013/oracle.json",
    "experiments/real_mod_composition/artifacts/h2-process-carrier-oracle-20261013/manager-predictions.json",
    "experiments/real_mod_composition/artifacts/h2-remaining-surfaces-oracle-20261013/oracle.json",
    "experiments/real_mod_composition/artifacts/h2-remaining-surfaces-oracle-20261013/review-receipt.json",
    "experiments/real_mod_composition/artifacts/h2-remaining-surfaces-oracle-20261013/manager-prediction.json",
    "experiments/real_mod_composition/artifacts/h2-compression-transaction-20261013",
    "experiments/real_mod_composition/verify_h2_compression_transaction.py",
    "paper/artifacts/h1-r5/formal-aggregate.json",
    "paper/artifacts/h1-r5/formal-aggregate-summary.json",
    "paper/artifacts/h1-r5/paper-results.jsonl",
    "paper/artifacts/h1-r5/paper-table.csv",
    "paper/artifacts/h1-r5/source-binding.json",
    "paper/artifacts/results.schema.json",
    "experiments/transaction_model/artifacts/result-summary.json",
    "experiments/transaction_model/result-summary.schema.json",
    "experiments/transaction_model/explore.py",
    "spec/0.1/contract-taxonomy.json",
    "spec/0.1/contract-taxonomy.schema.json",
    "spec/manifest-0.3/manifest.schema.json",
    "src/vllm_hust_ext/contract_compiler.py",
    "src/vllm_hust_ext/providers/production_stack.py",
)


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "paper_evidence_summary", GENERATOR_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_inputs(destination: Path) -> None:
    for relative in INPUTS:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        source = ROOT / relative
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)
    readiness = json.loads((ROOT / "docs/release-readiness.json").read_text())
    for relative in {path for gate in readiness["gates"] for path in gate["evidence"]}:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def rewrite_json(path: Path, update) -> None:
    value = json.loads(path.read_text())
    update(value)
    path.write_text(json.dumps(value, indent=2) + "\n")


def test_checked_summary_matches_all_authoritative_inputs() -> None:
    generator = load_generator()
    summary = generator.collect_summary(ROOT)

    assert summary == {
        "workshop_mods": 24,
        "workshop_bundle_namespace": 16,
        "workshop_test_pass": 17,
        "workshop_environment_blocked": 5,
        "planner_seed_extensions": 11,
        "adaptation_candidates": 5,
        "planner_cases": 31,
        "planner_admits": 21,
        "planner_rejects": 10,
        "planner_reject_precision": "1.0",
        "planner_reject_recall": "1.0",
        "planner_admit_recall": "1.0",
        "source_repositories": 15,
        "source_objects": 41,
        "formal_completed": 1,
        "formal_starts": 9,
        "formal_lifecycle_sources": 5,
        "h1_false_effective_numerator": 3,
        "h1_false_effective_denominator": 3,
        "h1_coverage": "0.5",
        "h2_scored_cases": 4,
        "h2_true_positive": 1,
        "h2_true_negative": 3,
        "h2_false_positive": 0,
        "h2_false_negative": 0,
        "h2_admit_precision": "1.0",
        "h2_admit_recall": "1.0",
        "h2_reject_precision": "1.0",
        "h2_reject_recall": "1.0",
        "h2_accepted_orders": 2,
        "h2_compression_orders": 2,
        "h2_compression_semantic_tokens": 1201,
        "h2_compression_physical_tokens": 1024,
        "h2_compression_worker_acks": 2,
        "formal_planned": 30,
        "verified_adapters": 3,
        "reference_starts": 45,
        "formal_arms": 3,
        "minimum_starts": 3,
        "schedule_rows": 3,
        "research_claims": 4,
        "first_study_starts": 9,
        "deployment_blockers": 0,
        "registered_deployment_arms": 3,
        "transaction_model_states": 39,
        "transaction_model_edges": 102,
        "transaction_model_rejections": 522,
        "transaction_model_invariants": 7,
        "release_version": "0.3.0",
        "manifest_version": "0.3",
        "release_distributions": 36,
        "release_registrations": 39,
        "release_activation_intent": 24,
        "release_inspect_only": 15,
        "release_gates": 9,
        "native_lifecycle_qualifications": 1,
    }
    assert (
        generator.render(summary)
        == (ROOT / "paper/generated/evidence-summary.tex").read_text()
    )


def test_generator_rejects_inconsistent_formal_plan_count(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    aggregate = (
        tmp_path / "experiments/false_effective/artifacts/formal-aggregate-summary.json"
    )
    rewrite_json(aggregate, lambda value: value.__setitem__("planned_records", 29))

    with pytest.raises(ValueError, match="scenarios times arms"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_planner_classification_drift(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    metrics = tmp_path / "experiments/contract_planner/results/metrics.json"
    rewrite_json(
        metrics,
        lambda value: value["overall"].__setitem__("false_admit", 1),
    )

    with pytest.raises(ValueError, match="planner evidence is internally inconsistent"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_h2_partial_result_overclaim(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    status = (
        tmp_path
        / "experiments/real_mod_composition/artifacts/"
        "h2-minimal-real-source-corpus-r2-20261013/status.json"
    )
    rewrite_json(
        status, lambda value: value.__setitem__("h2_acceptance_complete", True)
    )

    with pytest.raises(ValueError, match="explicit incompleteness"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_h2_external_authority_promotion(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    prediction = (
        tmp_path
        / "experiments/real_mod_composition/artifacts/"
        "h2-remaining-surfaces-oracle-20261013/manager-prediction.json"
    )
    rewrite_json(prediction, lambda value: value.__setitem__("h2_complete", True))

    with pytest.raises(ValueError, match="remaining-surface evidence"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_formalized_h2_compression_qualification(
    tmp_path: Path,
) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    admission = (
        tmp_path
        / "experiments/real_mod_composition/artifacts/"
        "h2-compression-transaction-20261013/admission.json"
    )
    rewrite_json(
        admission,
        lambda value: value.__setitem__("status", "FORMAL"),
    )

    with pytest.raises(ValueError, match="differs from raw recomputation"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_unregistered_formal_completion(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    aggregate = (
        tmp_path / "experiments/false_effective/artifacts/formal-aggregate-summary.json"
    )
    rewrite_json(aggregate, lambda value: value.__setitem__("completed_cells", 1))
    registry = tmp_path / "experiments/false_effective/verified-adapters.json"
    rewrite_json(registry, lambda value: value.__setitem__("adapters", []))

    with pytest.raises(ValueError, match="require a verified adapter"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_premature_deployment_registration(
    tmp_path: Path,
) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    deployment = (
        tmp_path / "experiments/false_effective/first-formal-real-deployment.json"
    )
    rewrite_json(
        deployment,
        lambda value: value.__setitem__("producer_admission_receipt", None),
    )

    with pytest.raises(ValueError, match="not fail closed"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_incomplete_registered_deployment_identity(
    tmp_path: Path,
) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    deployment = (
        tmp_path / "experiments/false_effective/first-formal-real-deployment.json"
    )
    rewrite_json(
        deployment,
        lambda value: value["deployment_identity"].__setitem__(
            "environment_digest", None
        ),
    )

    with pytest.raises(ValueError, match="not fail closed"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_blocked_release_gate(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    readiness = tmp_path / "docs/release-readiness.json"

    def block_gate(value) -> None:
        value["gates"][0]["status"] = "blocked"
        value["gates"][0]["remaining_action"] = "repair the release gate"

    rewrite_json(readiness, block_gate)

    with pytest.raises(ValueError, match="release evidence is not closed"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_native_qualification_promoted_to_performance(
    tmp_path: Path,
) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    qualification = (
        tmp_path / "docs/evidence/native-current-npu-qualification-2026-10-11.md"
    )
    qualification.write_text(
        qualification.read_text().replace(
            "it is not a performance result", "it is a performance result"
        )
    )

    with pytest.raises(ValueError, match="qualification boundary is incomplete"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_transaction_model_relabelled_as_formal_real(
    tmp_path: Path,
) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    summary = tmp_path / "experiments/transaction_model/artifacts/result-summary.json"
    rewrite_json(
        summary,
        lambda value: value.__setitem__("formal_real_result", True),
    )

    with pytest.raises(ValidationError):
        generator.collect_summary(tmp_path)


def test_generator_recomputes_transaction_model_instead_of_trusting_artifact(
    tmp_path: Path,
) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    summary = tmp_path / "experiments/transaction_model/artifacts/result-summary.json"

    def forge(value) -> None:
        value["reachable_states"] += 1
        value["valid_edges"] += 1
        value["rejected_state_action_pairs"] -= 1
        value["reachable_states_sha256"] = "1" * 64
        value["valid_edges_sha256"] = "2" * 64

    rewrite_json(summary, forge)

    with pytest.raises(ValueError, match="modeled evidence"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_stale_planner_input_digest(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    cases = tmp_path / "experiments/contract_planner/cases.json"
    rewrite_json(
        cases,
        lambda value: value["cases"][0].__setitem__(
            "rationale", value["cases"][0]["rationale"] + " tampered"
        ),
    )

    with pytest.raises(ValueError, match="oracle does not bind"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_declared_corpus_count_drift(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    corpus = tmp_path / "docs/corpus/plugins.json"
    rewrite_json(
        corpus,
        lambda value: value["counts"].__setitem__("registered_extensions", 999),
    )

    with pytest.raises(ValueError, match="declared counts"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_workshop_authority_identity_drift(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    corpus = tmp_path / "docs/corpus/workshop-mods.json"
    rewrite_json(
        corpus,
        lambda value: value["population"].__setitem__("commit_sha", "1" * 40),
    )

    with pytest.raises(ValueError, match="frozen authority"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_coordinated_workshop_row_substitution(
    tmp_path: Path,
) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    corpus = tmp_path / "docs/corpus/workshop-mods.json"

    def substitute_and_rehash(value) -> None:
        value["mods"][0]["repository"] = "vLLM-HUST/not-a-page-mod"
        source_rows = [
            {field: row[field] for field in generator.WORKSHOP_SOURCE_FIELDS}
            for row in value["mods"]
        ]
        value["population"]["source_rows_sha256"] = generator.canonical_digest(
            source_rows
        )
        value["population"]["audit_rows_sha256"] = generator.canonical_digest(
            value["mods"]
        )

    rewrite_json(corpus, substitute_and_rehash)

    with pytest.raises(ValueError, match="frozen authority|frozen page snapshot"):
        generator.collect_summary(tmp_path)


def test_generator_applies_checked_json_schemas(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    corpus = tmp_path / "docs/corpus/plugins.json"
    rewrite_json(corpus, lambda value: value["plugins"][0].pop("id"))

    with pytest.raises(ValidationError, match="'id' is a required property"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_candidate_identity_drift(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    cases = tmp_path / "experiments/contract_planner/cases.json"
    rewrite_json(
        cases,
        lambda value: value["excluded_candidates"].__setitem__(
            0, "intellistream/not-the-reviewed-candidate"
        ),
    )

    with pytest.raises(ValueError, match="exclusions do not exactly match"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_reference_start_drift(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    summary = tmp_path / "experiments/false_effective/artifacts/reference-summary.json"
    rewrite_json(summary, lambda value: value.__setitem__("starts", 44))

    with pytest.raises(ValueError, match="reference summary is inconsistent"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_stale_decision_digest(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    decisions = tmp_path / "experiments/contract_planner/results/decisions.jsonl"
    lines = decisions.read_text().splitlines()
    lines[0] = json.dumps(json.loads(lines[0]), sort_keys=True)
    decisions.write_text("\n".join(lines) + "\n")

    with pytest.raises(ValueError, match="metrics do not bind"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_stale_implementation_digest(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    evaluator = tmp_path / "experiments/contract_planner/evaluate.py"
    evaluator.write_text(evaluator.read_text() + "\n")

    with pytest.raises(ValueError, match="metrics do not bind"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_source_identity_drift(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    snapshots = tmp_path / "docs/corpus/source-snapshots.json"
    rewrite_json(
        snapshots,
        lambda value: value["sources"][0].__setitem__(
            "repository_id", value["sources"][0]["repository_id"] + 1
        ),
    )

    with pytest.raises(ValueError, match="oracle does not bind"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_coordinated_source_repository_drift(
    tmp_path: Path,
) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    snapshots = tmp_path / "docs/corpus/source-snapshots.json"
    rewrite_json(
        snapshots,
        lambda value: value["sources"][0].__setitem__(
            "requested_repository", "evil/not-corpus"
        ),
    )

    with pytest.raises(ValueError, match="exactly cover corpus repositories"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_snapshot_evidence_path_drift(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    snapshots = tmp_path / "docs/corpus/source-snapshots.json"
    rewrite_json(
        snapshots,
        lambda value: value["sources"][0]["evidence_objects"][0].__setitem__(
            "path", "not-the-corpus-evidence.txt"
        ),
    )

    with pytest.raises(ValueError, match="exactly cover corpus evidence paths"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_taxonomy_schema_violation(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    taxonomy = tmp_path / "spec/0.1/contract-taxonomy.json"
    rewrite_json(taxonomy, lambda value: value.pop("scope"))

    with pytest.raises(ValidationError, match="'scope' is a required property"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_unbalanced_protocol_schedule(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    protocol = tmp_path / "experiments/false_effective/protocol.json"
    rewrite_json(
        protocol,
        lambda value: value["schedule"].__setitem__(1, value["schedule"][0]),
    )

    with pytest.raises(ValueError, match="square balanced arm schedule"):
        generator.collect_summary(tmp_path)
