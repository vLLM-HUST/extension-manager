"""Paper numbers must derive from the complete real corpus and retain scope."""

import importlib.util
import json
from pathlib import Path

from scripts.benchmark_inputs import resolve_original

ROOT = Path(__file__).parents[1]


def test_checked_in_paper_counts_replay_real_source_closed_corpus():
    script = ROOT / "paper/scripts/generate_attention_source_summary.py"
    spec = importlib.util.spec_from_file_location("attention_paper_summary", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.derive(ROOT)
    saved = json.loads(
        resolve_original(
            ROOT / "paper/artifacts/attention-source-drain-r4/source-binding.json"
        ).read_bytes()
    )
    assert saved == summary
    assert resolve_original(
        ROOT / "paper/generated/attention-source-summary.tex"
    ).read_text() == (module.render(summary))
    assert summary["formal_result"] is False
    assert summary["formal_H3_starts"] == summary["formal_H4_starts"] == 0
    assert summary["numerical_attention_correctness"] is None
    assert summary["full_model_quality"] is None
    assert summary["performance_result"] is None


def test_anonymous_overlay_copies_all_referenced_generated_inputs(tmp_path):
    script = ROOT / "paper/scripts/render_anonymous.py"
    spec = importlib.util.spec_from_file_location("attention_anonymous_fixture", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "fixture-overlay"
    module.prepare(
        output,
        alias="TestAlias",
        title="A Fixture Title for Contracted Inference",
    )
    generated = (output / "generated/attention-source-summary.tex").read_text()
    assert "ECPA" not in generated
    assert r"\ReviewDataAttentionSourceRecords" in generated
    assert (output / "generated/evidence-summary.tex").is_file()
