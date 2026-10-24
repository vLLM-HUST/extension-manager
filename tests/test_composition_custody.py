"""External originals and new producer outputs must never share storage."""

import hashlib
import importlib
import json
import subprocess
import sys

import pytest

from scripts import benchmark_inputs as inputs
from scripts import verify_composition_originals as frozen

PRODUCERS = (
    "build_h2_augmentation_candidates",
    "build_h2_source_corpus_r2",
    "collect_h2_process_carrier_predictions",
    "collect_h2_remaining_surface_prediction",
    "collect_h2_source_corpus_predictions",
)


def test_no_composition_artifacts_remain_tracked():
    tracked = subprocess.check_output(
        ["git", "ls-files", "experiments/real_mod_composition/artifacts"],
        cwd=inputs.ROOT,
        text=True,
    )
    assert tracked == ""
    config = json.loads((inputs.ROOT / "BENCHMARK_ORIGINALS.json").read_text())
    assert len(config["migrated_sha256"]) == 286
    tracked_all = subprocess.check_output(
        ["git", "ls-files"], cwd=inputs.ROOT, text=True
    ).splitlines()
    assert not set(config["migrated_sha256"]).intersection(tracked_all)


@pytest.mark.parametrize("kind", frozen.PACKAGES)
def test_frozen_export_rejects_changed_verifier(kind, tmp_path, monkeypatch):
    relative = "experiments/real_mod_composition"
    source = tmp_path / relative
    source.mkdir(parents=True)
    name = frozen.PACKAGES[kind][0]
    (source / name).write_text("raise AssertionError('must not execute')")
    canonical_root = inputs.ROOT
    monkeypatch.setattr(frozen, "ROOT", tmp_path)
    monkeypatch.setattr(
        frozen,
        "original_path",
        lambda root, path: inputs.original_path(canonical_root, path),
    )
    with pytest.raises(ValueError, match="Frozen verifier checksum"):
        frozen.export(kind, tmp_path / "export")
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("name", PRODUCERS)
@pytest.mark.parametrize("location", ("source", "originals", "existing"))
def test_producers_reject_unsafe_output_before_any_collection(
    name, location, tmp_path, monkeypatch
):
    module = importlib.import_module("experiments.real_mod_composition." + name)
    original = tmp_path / "originals"
    original.mkdir()
    monkeypatch.setenv("VLLM_HUST_BENCHMARK_ORIGINALS", str(original))
    existing = tmp_path / "existing"
    existing.write_text("keep")
    target = {
        "source": inputs.ROOT / "forbidden-output.json",
        "originals": original / "forbidden-output.json",
        "existing": existing,
    }[location]
    monkeypatch.setattr(sys, "argv", [name, "--output", str(target)])
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *a, **k: pytest.fail("must reject before any command or NPU probe"),
    )
    with pytest.raises(ValueError, match="Output must be new"):
        module.main()
    assert existing.read_text() == "keep"
    assert not (original / "forbidden-output.json").exists()


def test_output_symlinks_and_existing_directories_are_rejected(tmp_path, monkeypatch):
    external = tmp_path / "originals"
    external.mkdir()
    monkeypatch.setenv("VLLM_HUST_BENCHMARK_ORIGINALS", str(external))
    alias = tmp_path / "alias"
    alias.symlink_to(external, target_is_directory=True)
    for target in (alias / "new.json", external, tmp_path):
        with pytest.raises(ValueError, match="Output must be new"):
            inputs.new_output(target)
    assert inputs.new_output(tmp_path / "new.json") == tmp_path / "new.json"


@pytest.mark.parametrize("name", PRODUCERS[:2])
def test_builders_reproduce_originals_in_fresh_output(name, tmp_path, monkeypatch):
    """Use hash-bound source bytes, never fetch/execute old checkout code."""
    module = importlib.import_module("experiments.real_mod_composition." + name)
    output = tmp_path / "new-output"
    historical = module.OUT if hasattr(module, "OUT") else module.OUTPUT
    originals = inputs.resolve_original(historical)
    monkeypatch.setattr(sys, "argv", [name, "--output", str(output)])
    if hasattr(module, "SOURCES"):

        def command(argv, **kwargs):
            repo, operation, ref = argv[2], argv[3], argv[4]
            matches = [s for s in module.SOURCES.values() if str(s["repo"]) == repo]
            if ref.endswith("^{tree}"):
                assert operation == "rev-parse"
                return matches[0]["tree"] + "\n"
            source_id, spec = next(
                (key, s)
                for key, s in module.SOURCES.items()
                if str(s["repo"]) == repo and ref == f"{s['commit']}:{s['path']}"
            )
            raw = (originals / f"{source_id}-manifest.json").read_bytes()
            if operation == "show":
                return raw
            assert operation == "rev-parse"
            return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest() + "\n"  # noqa: S324
    else:

        def command(argv, **kwargs):
            member = "lifecycle_profiler" if "profiler" in argv[2] else "kvcompress"
            raw = (originals / f"current-{member}-manifest.json").read_bytes()
            if argv[3] == "show":
                return raw
            assert argv[3] == "rev-parse"
            return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest() + "\n"  # noqa: S324

    monkeypatch.setattr(module.subprocess, "check_output", command)
    assert module.main() == 0
    expected = {p.name: p.read_bytes() for p in originals.iterdir()}
    actual = {p.name: p.read_bytes() for p in output.iterdir()}
    assert actual == expected
    with pytest.raises(ValueError, match="Output must be new"):
        module.main()
