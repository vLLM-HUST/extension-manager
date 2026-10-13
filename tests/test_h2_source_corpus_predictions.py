from __future__ import annotations

import importlib.util
from pathlib import Path


def test_h2_source_corpus_prediction_artifact() -> None:
    root = Path(__file__).resolve().parents[1]
    path = (
        root
        / "experiments"
        / "real_mod_composition"
        / "verify_h2_source_corpus_predictions.py"
    )
    spec = importlib.util.spec_from_file_location("verify_h2_source_corpus", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main() == 0


def test_h2_source_corpus_successor_metrics() -> None:
    root = Path(__file__).resolve().parents[1]
    path = (
        root / "experiments" / "real_mod_composition" / "verify_h2_source_corpus_r2.py"
    )
    spec = importlib.util.spec_from_file_location("verify_h2_source_corpus_r2", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main() == 0


def test_h2_real_source_augmentation_freeze() -> None:
    root = Path(__file__).resolve().parents[1]
    path = (
        root
        / "experiments"
        / "real_mod_composition"
        / "verify_h2_augmentation_candidates.py"
    )
    spec = importlib.util.spec_from_file_location("verify_h2_augmentation", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main() == 0
