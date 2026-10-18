"""CPU replay isolation regression; no native proof or qualification fixture."""

import builtins
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from experiments.formal_campaign import h4_sampled_calibration as calibration
from vllm_hust_ext import activation_profile


def test_cpu_child_removes_only_runtime_controls_without_changing_host(
    monkeypatch, tmp_path
):
    phase_environment = {
        key: "product-owned" for key in calibration._TOKENIZER_RUNTIME_ENVIRONMENT
    }
    phase_environment.update(
        PATH="/selected/bin:/cann/bin",
        PYTHONPATH="/selected/sdk:/cann/python",
        VLLM_PLUGINS="selected-kv,profiler",
        ECPA_ACTIVATION_PROFILE_PATH="/registered/profile.json",
        ECPA_ACTIVATION_PROFILE_SHA256="a" * 64,
        VLLM_ASCEND_KVCOMPRESS_ENABLED="1",
        VLLM_ASCEND_KVCOMPRESS_CONFIG='{"exact":"registered"}',
    )
    original = dict(phase_environment)
    monkeypatch.setenv("VLLM_ECPA_EVIDENCE_SINK", "parent-owned")
    child = calibration._tokenizer_environment(
        phase_environment, cache_directory=tmp_path / "tokenizer-cache"
    )
    assert phase_environment == original
    assert os.environ["VLLM_ECPA_EVIDENCE_SINK"] == "parent-owned"
    assert not calibration._TOKENIZER_RUNTIME_ENVIRONMENT.intersection(child)
    for key, value in original.items():
        if key not in calibration._TOKENIZER_RUNTIME_ENVIRONMENT:
            assert child[key] == value
    assert child["HF_HUB_OFFLINE"] == child["TRANSFORMERS_OFFLINE"] == "1"


def test_tokenizer_cache_side_effect_cannot_claim_or_warm_product_directory(tmp_path):
    product = tmp_path / "future-run"
    environment = dict(os.environ, TRITON_CACHE_DIR=str(product / "triton-cache"))
    original = dict(environment)
    with tempfile.TemporaryDirectory(prefix="tokenizer-", dir=tmp_path) as isolated:
        child = calibration._tokenizer_environment(
            environment, cache_directory=isolated
        )
        # Reproduce the actual import side effect with a real stdlib child;
        # no Host, model, native qualification or device is simulated.
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import os,pathlib; p=pathlib.Path(os.environ['TRITON_CACHE_DIR']); "
                "p.mkdir(parents=True,exist_ok=True); "
                "(p/'import-utility').write_bytes(b'cpu-import')",
            ],
            env=child,
            check=True,
            timeout=10,
        )
        assert (Path(isolated) / "import-utility").read_bytes() == b"cpu-import"
        assert environment == original
        assert not product.exists()
        product.mkdir()  # The original exclusive run creation still succeeds.
        assert list(product.iterdir()) == []
    assert not Path(isolated).exists()


@pytest.mark.parametrize("profile_present", [False, True])
def test_original_profile_binding_precedes_first_vllm_import(
    monkeypatch, profile_present
):
    calls = []

    class ImportBoundaryReached(Exception):
        pass

    class Profile:
        def bind_environment(self):
            calls.append("original-bind")

    def load_profile():
        calls.append("original-load")
        return Profile() if profile_present else None

    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "vllm" or name.startswith("vllm."):
            expected = ["original-load"]
            if profile_present:
                expected.append("original-bind")
            assert calls == expected
            raise ImportBoundaryReached
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(activation_profile, "profile_from_environment", load_profile)
    monkeypatch.setattr(builtins, "__import__", guarded_import)
    with pytest.raises(ImportBoundaryReached):
        calibration.tokenizer_worker({})


def test_original_profile_rejection_prevents_all_vllm_imports(monkeypatch):
    class OriginalProfileRejection(ValueError):
        pass

    def reject():
        raise OriginalProfileRejection("conflicting inherited configuration")

    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        assert name != "vllm" and not name.startswith("vllm.")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(activation_profile, "profile_from_environment", reject)
    monkeypatch.setattr(builtins, "__import__", guarded_import)
    with pytest.raises(OriginalProfileRejection):
        calibration.tokenizer_worker({})
