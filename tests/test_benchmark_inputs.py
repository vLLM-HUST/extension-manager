import hashlib
import json

import pytest

from scripts import benchmark_inputs as inputs


def test_external_original_is_required_and_verified(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    relative = "original.json"
    raw = b'{"synthetic":true}'
    (checkout / "BENCHMARK_ORIGINALS.json").write_text(
        json.dumps({"migrated_sha256": {relative: hashlib.sha256(raw).hexdigest()}})
    )
    monkeypatch.setattr(inputs, "ROOT", checkout)
    monkeypatch.delenv("VLLM_HUST_BENCHMARK_ORIGINALS", raising=False)
    (checkout / relative).write_bytes(raw)
    with pytest.raises(ValueError, match="Download originals"):
        inputs.original_path(checkout, relative)
    monkeypatch.setenv("VLLM_HUST_BENCHMARK_ORIGINALS", str(checkout))
    with pytest.raises(ValueError, match="outside"):
        inputs.original_path(checkout, relative)
    external = tmp_path / "external"
    external.mkdir()
    monkeypatch.setenv("VLLM_HUST_BENCHMARK_ORIGINALS", str(external))
    with pytest.raises(FileNotFoundError):
        inputs.original_path(checkout, relative)
    (external / relative).write_bytes(raw)
    assert inputs.original_path(checkout, relative) == external / relative
    (external / relative).write_bytes(raw + b"corrupt")
    with pytest.raises(ValueError, match="checksum"):
        inputs.original_path(checkout, relative)
    assert (
        inputs.original_path(tmp_path / "negative-fixture", relative)
        == tmp_path / "negative-fixture" / relative
    )


def test_directory_checks_members_hashes_and_escape(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    external = tmp_path / "originals"
    package = external / "packet"
    package.mkdir(parents=True)
    raw = b"synthetic input"
    (package / "input.txt").write_bytes(raw)
    (checkout / "BENCHMARK_ORIGINALS.json").write_text(
        json.dumps(
            {"migrated_sha256": {"packet/input.txt": hashlib.sha256(raw).hexdigest()}}
        )
    )
    monkeypatch.setattr(inputs, "ROOT", checkout)
    monkeypatch.setenv("VLLM_HUST_BENCHMARK_ORIGINALS", str(external))
    assert inputs.resolve_original(checkout / "packet") == package
    extra = package / "unexpected.txt"
    extra.write_text("unexpected")
    with pytest.raises(ValueError, match="Unexpected"):
        inputs.resolve_original(checkout / "packet")
    extra.unlink()
    (package / "input.txt").write_bytes(raw + b"corrupt")
    with pytest.raises(ValueError, match="checksum"):
        inputs.resolve_original(checkout / "packet")
    (package / "input.txt").unlink()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(raw)
    (package / "input.txt").symlink_to(outside)
    with pytest.raises(ValueError, match="Unsafe"):
        inputs.resolve_original(checkout / "packet")
