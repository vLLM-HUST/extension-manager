"""Real CPU file durability with fixture metadata: not a Host/model qualification."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace as Obj

import pytest

import experiments.exposure_gate.semantic_candidate.producer as producer_module
from experiments.exposure_gate.semantic_candidate.producer import (
    PublicationAck,
    canonical,
    current_process,
    digest,
    emit_worker_projection,
    projection_receipt,
    verify_receipt,
    write_durable_receipt,
)


class Table:
    def __init__(self, row):
        self.row = row

    def get_numpy_array(self):
        return self

    def __getitem__(self, index):
        return self.row[index[1]]


def fixture():
    pid = os.getpid()
    raw = Path(f"/proc/{pid}/stat").read_bytes()
    ticks = int(raw[raw.rfind(b")") + 2 :].split()[19])
    scope = dict(
        plan_id="p",
        launch_id="l",
        controller_instance="c",
        candidate_generation=1,
        membership_epoch=2,
        source_provider_sha256="a" * 64,
        source_host_sha256="b" * 64,
    )
    host = dict(
        plan_id="p",
        launch_id="l",
        binding_status="bound",
        process=dict(
            host="cpu-fixture",
            role="worker",
            ordinal=0,
            process_epoch=2,
            assignment_source="host",
            pid=pid,
            start_identity=f"pid:{pid}:start_ticks:{ticks}",
        ),
    )
    pending = Obj(semantic_anchor=1201, physical_anchor=1024, block_ids=(11, 12))
    table = Table([11, 12])
    provider = Obj(
        attention_group_index=0,
        active={"r": pending},
        runner=Obj(
            requests={"r": Obj(block_ids=([11, 12],))},
            input_batch=Obj(
                req_id_to_index={"r": 0}, block_table=Obj(block_tables=[table])
            ),
        ),
    )
    output = Obj(num_scheduled_tokens={"r": 1})
    return provider, output, pending, scope, host, table


def test_cpu_receipt_written_durably_and_independently_checked(tmp_path):
    provider, output, pending, scope, host, _ = fixture()
    tmp_path.chmod(0o700)
    stat = tmp_path.stat()

    acknowledgements = []

    def sink(raw):
        ack = write_durable_receipt(tmp_path, raw, (stat.st_dev, stat.st_ino))
        acknowledgements.append(ack)
        return ack

    assert emit_worker_projection(
        provider, output, "r", pending, scope=scope, host_scope=host, durable_sink=sink
    )
    raw = next(tmp_path.glob("*.json")).read_bytes()
    transaction = dict(
        runtime_request_id="r",
        attention_group=0,
        semantic_anchor=1201,
        physical_anchor=1024,
        destination_block_ids=[11, 12],
    )
    receipt = verify_receipt(
        raw,
        expected_scope=scope,
        expected_process=current_process(host),
        expected_transaction=transaction,
        expected_producer_sha256=digest(Path(producer_module.__file__).read_bytes()),
        publication_ack=acknowledgements[0],
        expected_directory_identity=(stat.st_dev, stat.st_ino),
    )
    assert receipt["formal_producer_registration"] is False
    assert receipt["kv_tensor_equivalence"] is None
    assert receipt["gpu_table_upload_observed"] is False


@pytest.mark.parametrize(
    "change",
    ["pre-effect", "missing-barrier", "wrong-launch", "pid-reuse", "environment-role"],
)
def test_no_receipt_on_failed_effect_or_identity(change):
    provider, output, pending, scope, host, table = fixture()
    if change == "pre-effect":
        table.row = [99, 98]
    if change == "missing-barrier":
        output.num_scheduled_tokens = {}
    if change == "wrong-launch":
        scope["launch_id"] = "other"
    if change == "pid-reuse":
        host["process"]["start_identity"] = "wrong"
    if change == "environment-role":
        host["process"]["assignment_source"] = "environment"
    written = []
    assert not emit_worker_projection(
        provider,
        output,
        "r",
        pending,
        scope=scope,
        host_scope=host,
        durable_sink=lambda raw: written.append(raw) or True,
    )
    assert not written


def test_failed_fsync_does_not_grant_receipt(tmp_path, monkeypatch):
    provider, output, pending, scope, host, _ = fixture()
    tmp_path.chmod(0o700)
    stat = tmp_path.stat()

    def failed(_fd):
        raise OSError("injected real fsync failure")

    monkeypatch.setattr(os, "fsync", failed)
    assert not emit_worker_projection(
        provider,
        output,
        "r",
        pending,
        scope=scope,
        host_scope=host,
        durable_sink=lambda raw: write_durable_receipt(
            tmp_path, raw, (stat.st_dev, stat.st_ino)
        ),
    )
    assert not list(tmp_path.glob("*.json"))


@pytest.mark.parametrize(
    "field", ["scope", "transaction", "formal_producer_registration", "model_quality"]
)
def test_consumer_refuses_rehashed_crossbinding_or_promotion(field):
    provider, output, pending, scope, host, _ = fixture()
    receipt = projection_receipt(provider, output, "r", pending, scope, host)
    original = receipt.copy()
    if field == "scope":
        receipt[field] = scope | {"launch_id": "other"}
    if field == "transaction":
        receipt[field] = receipt[field] | {"runtime_request_id": "other"}
    if field == "formal_producer_registration":
        receipt[field] = True
    if field == "model_quality":
        receipt[field] = True
    receipt["event_id"] = digest(
        canonical({k: v for k, v in receipt.items() if k != "event_id"})
    )
    with pytest.raises(ValueError):
        verify_receipt(
            canonical(receipt),
            expected_scope=scope,
            expected_process=current_process(host),
            expected_transaction=original["transaction"],
            expected_producer_sha256=original["producer_sha256"],
            expected_directory_identity=(1, 2),
            publication_ack=PublicationAck(
                digest(canonical(receipt)),
                digest(canonical(receipt)) + ".json",
                1,
                2,
                os.getpid(),
            ),
        )


def test_source_hook_applies_to_exact_frozen_bytes(tmp_path):
    import ast
    import json
    import subprocess

    package = Path(__file__).resolve().parents[1] / (
        "experiments/exposure_gate/semantic_candidate"
    )
    manifest = json.loads((package / "manifest.json").read_text())
    assert manifest["registered_formal_producer"] is False
    assert manifest["real_model_tested"] is False
    for name, sha in manifest["source_sha256"].items():
        assert digest((package / "source" / name).read_bytes()) == sha
    target = tmp_path / "src/vllm_ascend_kvcompress/provider.py"
    target.parent.mkdir(parents=True)
    target.write_bytes((package / "source/provider-00cc78.py.snapshot").read_bytes())
    subprocess.run(
        ["git", "apply", str(package / "provider-00cc78.patch")],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    assert digest(target.read_bytes()) == manifest["patched_provider_sha256"]
    ast.parse(target.read_text())


@pytest.mark.parametrize("ack", [True, False, None, 1, "true"])
def test_sink_nack_or_nonboolean_does_not_grant_evidence(ack):
    provider, output, pending, scope, host, _ = fixture()
    assert not emit_worker_projection(
        provider,
        output,
        "r",
        pending,
        scope=scope,
        host_scope=host,
        durable_sink=lambda raw: ack,
    )


def test_sink_exception_does_not_change_serving_operation():
    provider, output, pending, scope, host, _ = fixture()

    def broken(raw):
        raise RuntimeError("custom source sink unavailable")

    assert not emit_worker_projection(
        provider,
        output,
        "r",
        pending,
        scope=scope,
        host_scope=host,
        durable_sink=broken,
    )


def test_concurrent_raw_visibility_before_directory_fsync_is_not_admissible(
    tmp_path, monkeypatch
):
    import json
    import stat as stat_module
    import threading

    provider, output, pending, scope, host, _ = fixture()
    raw = canonical(projection_receipt(provider, output, "r", pending, scope, host))
    tmp_path.chmod(0o700)
    stat = tmp_path.stat()
    identity = (stat.st_dev, stat.st_ino)
    published = threading.Event()
    release = threading.Event()
    real_fsync = os.fsync

    def controlled_fsync(fd):
        if stat_module.S_ISDIR(os.fstat(fd).st_mode):
            published.set()
            assert release.wait(3)
            raise OSError("directory fsync failed after reader saw raw")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", controlled_fsync)
    results = []
    thread = threading.Thread(
        target=lambda: results.append(write_durable_receipt(tmp_path, raw, identity))
    )
    thread.start()
    try:
        assert published.wait(3)
        visible = next(tmp_path.glob("*.json")).read_bytes()
        assert visible == raw
        with pytest.raises(ValueError, match="publication acknowledgement"):
            verify_receipt(
                visible,
                expected_scope=scope,
                expected_process=current_process(host),
                expected_transaction=json.loads(raw)["transaction"],
                expected_producer_sha256=digest(
                    Path(producer_module.__file__).read_bytes()
                ),
                expected_directory_identity=identity,
            )
    finally:
        release.set()
        thread.join(3)
    assert results == [None]
    assert not list(tmp_path.iterdir())
