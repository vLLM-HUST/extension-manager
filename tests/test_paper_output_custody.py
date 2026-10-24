"""Paper output isolation must not weaken archived-input or replay validation."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from scripts.benchmark_inputs import original_path

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / f"paper/scripts/{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "name", ["generate_evidence_summary", "generate_attention_source_summary"]
)
def test_generation_requires_explicit_new_external_output(name, tmp_path, monkeypatch):
    module = load(name)
    monkeypatch.setattr(sys, "argv", [name])
    with pytest.raises(SystemExit):
        module.main()
    existing = tmp_path / "existing"
    existing.write_text("keep")
    for target in (
        existing,
        ROOT / "paper/new-output",
        original_path(ROOT, "paper/generated/evidence-summary.tex").parent
        / "new-output",
    ):
        monkeypatch.setattr(sys, "argv", [name, "--output", str(target)])
        with pytest.raises(ValueError, match="Output must be new"):
            module.main()
    assert existing.read_text() == "keep"


def test_attention_projection_uses_fresh_output_and_checks_archived_binding(
    tmp_path, monkeypatch
):
    module = load("generate_attention_source_summary")
    binding = original_path(
        ROOT, "paper/artifacts/attention-source-drain-r4/source-binding.json"
    )
    original = binding.read_bytes()
    summary = json.loads(original)
    # I/O-only test. The separate unmocked corpus replay test remains mandatory.
    monkeypatch.setattr(module, "derive", lambda root: summary)
    target = tmp_path / "new-projection"
    monkeypatch.setattr(sys, "argv", ["generate", "--output", str(target)])
    module.main()
    assert (
        target / "artifacts/attention-source-drain-r4/source-binding.json"
    ).read_bytes() == original
    assert (
        target / "generated/attention-source-summary.tex"
    ).read_text() == module.render(summary)
    assert binding.read_bytes() == original
    monkeypatch.setattr(sys, "argv", ["generate", "--check"])
    module.main()
    monkeypatch.setattr(
        module, "derive", lambda root: dict(summary, formal_result=True)
    )
    with pytest.raises(ValueError, match="output differs"):
        module.main()


def test_public_build_copies_verified_projections_without_source_writes(tmp_path):
    module = load("build_paper")
    target = tmp_path / "public"
    assert module.prepare(target) == target / "main.tex"
    for name in ("evidence-summary.tex", "attention-source-summary.tex"):
        assert (target / "generated" / name).read_bytes() == original_path(
            ROOT, "paper/generated/" + name
        ).read_bytes()
    with pytest.raises(ValueError, match="Output must be new"):
        module.prepare(target)
    with pytest.raises(ValueError, match="Output must be new"):
        module.prepare(ROOT / "paper/build")


def test_build_validates_all_inputs_before_compiler(tmp_path, monkeypatch):
    module = load("build_paper")
    output = tmp_path / "public"
    monkeypatch.setattr(sys, "argv", ["build", "--output", str(output)])
    calls = []
    monkeypatch.setattr(
        module.subprocess, "run", lambda command, **kwargs: calls.append(command)
    )
    assert module.main() == 0
    assert calls[0][-3:] == [
        "check-evidence-summary",
        "check-attention-source-summary",
        "check-research-matrix",
    ]
    assert calls[1][0] == "tectonic"


def test_build_refuses_missing_originals_before_output(tmp_path, monkeypatch):
    module = load("build_paper")
    monkeypatch.delenv("VLLM_HUST_BENCHMARK_ORIGINALS", raising=False)
    with pytest.raises(ValueError, match="Download originals"):
        module.prepare(tmp_path / "public")
    assert not (tmp_path / "public").exists()
