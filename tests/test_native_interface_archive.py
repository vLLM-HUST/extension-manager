"""Fully rehashed archive counterexamples; no hardware or original data edits."""

import base64
import copy
import gzip
import io
import json
import tarfile
from pathlib import Path

import pytest

from experiments.formal_campaign import verify_native_interface as verify

ARTIFACTS = (
    Path(__file__).parents[1]
    / "experiments/formal_campaign/artifacts/native-interface-20261013"
)


def corpus():
    with tarfile.open(ARTIFACTS / "raw.tar.gz", "r:gz") as archive:
        files = {x.name: archive.extractfile(x).read() for x in archive.getmembers()}
    return files, json.loads((ARTIFACTS / "manifest.json").read_bytes())


def change(files, path, function):
    obj = json.loads(files[path])
    function(obj)
    files[path] = verify.canonical(obj)


def rechain(files):
    path = "r2/run/native-raw.jsonl"
    rows = [json.loads(x) for x in files[path].splitlines()]
    previous = "0" * 64
    for row in rows:
        row["previous_sha256"] = previous
        row["event_sha256"] = verify.sha(
            verify.canonical({k: v for k, v in row.items() if k != "event_sha256"})
        )
        previous = row["event_sha256"]
    files[path] = b"".join(verify.canonical(x) + b"\n" for x in rows)
    path = "r2/run/probe/collector-after.json"
    status = json.loads(files[path])
    status["status"]["acknowledged_prefix"] = {
        "next_sequence": len(rows),
        "last_event_sha256": previous,
    }
    replace_status_raw(status)
    files[path] = verify.canonical(status)


def replace_status_raw(obj):
    raw = verify.canonical(obj["status"]) + b"\n"
    obj["status_raw_base64"] = base64.b64encode(raw).decode()
    obj["status_raw_sha256"] = verify.sha(raw)


def pack(tmp_path, files, original):
    archive = tmp_path / "changed.tar.gz"
    with (
        archive.open("wb") as stream,
        gzip.GzipFile(fileobj=stream, mode="wb", mtime=0) as zipped,
        tarfile.open(fileobj=zipped, mode="w") as tar,
    ):
        for path, raw in sorted(files.items()):
            entry = tarfile.TarInfo(path)
            entry.size, entry.mode = len(raw), 0o600
            tar.addfile(entry, io.BytesIO(raw))
    manifest = copy.deepcopy(original)
    manifest["archive_sha256"] = verify.sha(archive.read_bytes())
    manifest["files"] = {k: verify.sha(v) for k, v in files.items()}
    path = tmp_path / "manifest.json"
    path.write_bytes(verify.canonical(manifest))
    return path, archive


def test_real_finite_native_transport_archive():
    result = verify.verify_archive(
        ARTIFACTS / "manifest.json", ARTIFACTS / "raw.tar.gz"
    )
    assert result["two_rank_upload_counts"] == {0: 40, 1: 40}
    assert result["completion_tokens"] == 39
    assert result["actual_hardware_transport_observed"]
    assert result["formal_result"] is False
    assert result["KV_MOD_semantic_obligation_satisfied"] is None


@pytest.mark.parametrize(
    "case",
    [
        "http503-exactbody",
        "backend503",
        "r2-npu-live",
        "foreign-session",
        "r1-cleanup-omitted",
        "r1-npu-live",
        "r1-retargeted-worker",
        "legacy-source",
        "missing-accept-clock",
        "missing-ACK",
        "parsed-status-fork",
    ],
)
def test_fully_rehashed_semantic_and_ownership_negatives(tmp_path, case):
    files, manifest = corpus()
    if case == "http503-exactbody":
        change(files, "r2/run/probe/result.json", lambda x: x.update(status=503))
    elif case == "backend503":
        path = "r2/run/backend.stdout"
        files[path] = files[path].replace(
            b'"POST /v1/chat/completions HTTP/1.1" 200 OK',
            b'"POST /v1/chat/completions HTTP/1.1" 503 Service Unavailable',
        )
    elif case in {"r2-npu-live", "r1-npu-live"}:
        path = case[:2] + "/run/terminal-npu-smi.txt"
        files[path] += b"| 3     0                 | 851363 | python | 128 |\n"
    elif case == "foreign-session":
        change(
            files,
            "r2/run/terminal-process-audit.json",
            lambda x: x["remaining_sessions"][0]["owner"].update(pid=1, session=1),
        )
    elif case == "r1-cleanup-omitted":
        del files["r1/run/terminal-process-audit.json"]
    elif case == "r1-retargeted-worker":
        peers = json.loads(files["r1/run/actual-owned-source-peers.json"])
        p = peers[2]["process"]
        p["pid"] += 1000000
        p["start_identity"] = f"pid:{p['pid']}:start_ticks:{p['start_ticks']}"
        files["r1/run/actual-owned-source-peers.json"] = verify.canonical(peers)
        terminal = json.loads(files["r1/run/terminal-process-audit.json"])
        terminal["source_peers"][2]["source_process"] = p
        terminal["source_peers"][2]["expected_kernel"]["pid"] = p["pid"]
        files["r1/run/terminal-process-audit.json"] = verify.canonical(terminal)
    elif case in {"legacy-source", "missing-accept-clock"}:
        path = "r2/run/native-raw.jsonl"
        rows = [json.loads(x) for x in files[path].splitlines()]
        if case == "legacy-source":
            rows[0]["collector_source_sha256"] = (
                "135a3a9f06f9b2e7afe12a377ae3947a7b96801924fc09b853c836c12d65bf77"
            )
        else:
            for row in rows[1:]:
                row.pop("accepted_monotonic_ns")
        files[path] = b"".join(verify.canonical(x) + b"\n" for x in rows)
        rechain(files)
    elif case == "missing-ACK":

        def mutate(x):
            x["status"].pop("acknowledged_prefix")
            replace_status_raw(x)

        change(files, "r2/run/probe/collector-after.json", mutate)
    elif case == "parsed-status-fork":
        change(
            files,
            "r2/run/probe/collector-after.json",
            lambda x: x["status"]["acknowledged_prefix"].update(next_sequence=1),
        )
    changed_manifest, archive = pack(tmp_path, files, manifest)
    with pytest.raises(ValueError):
        verify.verify_archive(changed_manifest, archive)
