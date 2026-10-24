"""Fully rehashed archive negatives, not just a compressed-byte hash check."""

import json
import tarfile
from pathlib import Path

import pytest

from experiments.formal_campaign.verify_kv_failures import (
    canonical,
    load_archive,
    sha,
    verify_archive,
)
from scripts.benchmark_inputs import resolve_original

ARTIFACT = resolve_original(
    Path(__file__).resolve().parents[1]
    / "experiments/formal_campaign/artifacts/kv-failures-20261014"
)


@pytest.fixture(scope="module")
def original():
    return load_archive(ARTIFACT / "manifest.json", ARTIFACT / "raw.tar.gz")


def repack(tmp, original, mutate):
    metadata, original_files = original
    files = dict(original_files)
    mutate(files)
    archive = tmp / "counterfactual.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        import io

        for name, raw in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
    manifest = dict(metadata)
    manifest["archive_sha256"] = sha(archive.read_bytes())
    manifest["inventory"] = {
        k: {"sha256": sha(v), "bytes": len(v)} for k, v in files.items()
    }
    path = tmp / "manifest.json"
    path.write_bytes(canonical(manifest))
    return path, archive


def edit(files, path, callback):
    value = json.loads(files[path])
    callback(value)
    files[path] = canonical(value)


def test_actual_failed_archive(original):
    result = verify_archive(ARTIFACT / "manifest.json", ARTIFACT / "raw.tar.gz")
    assert result["failure_evidence_verified"] is True
    assert result["calibration_wrapper_exit"] == 1
    assert result["calibration_leaf_exit_raw_status"] is None
    assert result["calibration_artifact_structure_verified"] is None
    assert result["KV_projection_facts"] == 0
    assert result["r4_HTTP_status"] == 500
    assert result["durable_KV_join"] is None
    assert result["formal_result"] is False


def foreign_worker(files):
    path = "effect-r4/run/terminal-process-audit.json"

    def change(value):
        value["source_peers"][1]["source_process"]["pid"] += 100000
        value["source_peers"][1]["expected_kernel"]["pid"] += 100000

    edit(files, path, change)
    peers = json.loads(files["effect-r4/run/actual-owned-source-peers.json"])
    peers[1]["process"]["pid"] += 100000
    files["effect-r4/run/actual-owned-source-peers.json"] = canonical(peers)
    edit(files, "effect-r4/run/collector-spec.json", lambda x: x.update(senders=peers))


@pytest.mark.parametrize(
    "mutate,match",
    [
        (
            lambda f: edit(
                f, "effect-r4/run/result.json", lambda x: x.update(passed=True)
            ),
            "promoted",
        ),
        (
            lambda f: edit(
                f, "effect-r4/run/probe/result.json", lambda x: x.update(status=200)
            ),
            "HTTP failure",
        ),
        (
            lambda f: edit(
                f,
                "effect-r4/run/terminal-process-audit.json",
                lambda x: x["remaining_sessions"][0]["members"].append({"pid": 123}),
            ),
            "session terminal",
        ),
        (
            lambda f: edit(
                f,
                "effect-r3/run/terminal-process-audit.json",
                lambda x: x["remaining_sessions"][0]["owner"].update(session=123),
            ),
            "session terminal",
        ),
        (lambda f: f.pop("calibration/owner-cli.stderr"), "missing original raw"),
        (
            lambda f: f.update(
                {
                    "calibration/run/result.json": canonical(
                        {"passed": True, "returncode": 0}
                    )
                }
            ),
            "missing leaf status",
        ),
        (
            lambda f: edit(
                f,
                "calibration/late-terminal-diagnostic-audit.json",
                lambda x: x.update(leaf_exit_status_independently_recorded=True),
            ),
            "leaf status",
        ),
        (
            lambda f: f.update(
                {
                    "effect-r3/run/terminal-npu-smi.txt": f[
                        "effect-r3/run/terminal-npu-smi.txt"
                    ].replace(
                        b"No running processes found in NPU 3",
                        b"process 123 running in NPU 3",
                    )
                }
            ),
            "two-card",
        ),
        (
            lambda f: f.update(
                {
                    "effect-r4/run/terminal-npu-smi.txt": f[
                        "effect-r4/run/terminal-npu-smi.txt"
                    ]
                    + b"\n| 3 0 | 123 | python |\n"
                }
            ),
            "two-card",
        ),
        (
            lambda f: edit(
                f,
                "effect-r4/run/native-binding.json",
                lambda x: x["publisher"].update(pid=123),
            ),
            "handoff",
        ),
        (foreign_worker, "original Host invoked"),
    ],
)
def test_fully_rehashed_counterfactual(tmp_path, original, mutate, match):
    manifest, archive = repack(tmp_path, original, mutate)
    with pytest.raises(ValueError, match=match):
        verify_archive(manifest, archive)


def test_calibration_same_length_token_tamper(tmp_path, original):
    def mutate(files):
        edit(
            files,
            "calibration/actual-tokenizer-input-ids.json",
            lambda x: x["input_ids"][0].__setitem__(0, x["input_ids"][0][0] + 1),
        )

    manifest, archive = repack(tmp_path, original, mutate)
    with pytest.raises(ValueError, match="actual calibration IDs"):
        verify_archive(manifest, archive)


def test_original_authenticated_status_fork(tmp_path, original):
    def mutate(files):
        edit(
            files,
            "effect-r4/run/probe/collector-before.json",
            lambda x: x["status"]["collector"].update(pid=123),
        )

    manifest, archive = repack(tmp_path, original, mutate)
    with pytest.raises(ValueError, match="before-status"):
        verify_archive(manifest, archive)
