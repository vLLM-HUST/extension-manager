"""Historical source construction retains its exact original SHA boundary."""
import hashlib
import shutil

import pytest
from experiments.native_attention_candidate import build_source_patch


@pytest.fixture
def isolated_historical_source(tmp_path, monkeypatch):
    original = build_source_patch.ROOT
    root = tmp_path / "native_attention_candidate"
    shutil.copytree(original / "source", root / "source")
    shutil.copyfile(original / "operator_observer.py", root / "operator_observer.py")
    live = tmp_path / "native_kv_tensor_candidate"
    live.mkdir()
    (live / "artifact_bootstrap.py").write_text("raise AssertionError('live wrapper')\n")
    monkeypatch.setattr(build_source_patch, "ROOT", root)
    return root


def test_historical_patch_uses_exact_frozen_preimage_not_live_wrapper(isolated_historical_source):
    snapshot = (isolated_historical_source / "source/tensor-artifact-bootstrap-c435.py").read_bytes()
    assert hashlib.sha256(snapshot).hexdigest() == (
        "85b9a5226980fa92c1fea9357c72c831b943a851c23922ef1d4cb8ff26053211"
    )
    original, patched = build_source_patch.patched()
    path = "vllm/plugins/native_tensor_artifact_bootstrap.py"
    assert original[path].encode() == snapshot
    assert "remember_acknowledged_materialization(published, ack)" in patched[path]
    assert "register_source_candidate" in patched[path]


def test_changed_historical_preimage_still_rejects(isolated_historical_source):
    path = isolated_historical_source / "source/tensor-artifact-bootstrap-c435.py"
    path.write_bytes(path.read_bytes() + b"# changed historical bytes\n")
    with pytest.raises(ValueError, match="c435 source-owned tensor bootstrap preimage changed"):
        build_source_patch.patched()
