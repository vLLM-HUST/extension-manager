"""Full tar/manifest rehashes cannot forge task, native ACK or finite metadata scope."""

import base64
import io
import json
import tarfile
from pathlib import Path

import pytest

from experiments.formal_campaign import verify_kv_postack_metadata as verifier

ROOT = (
    Path(__file__).parents[1]
    / "experiments/formal_campaign/artifacts/kv-postack-metadata-20261014"
)


@pytest.fixture(scope="module")
def originals():
    return verifier.load_archive(ROOT / "manifest.json", ROOT / "raw.tar.gz")


def change(files, name, mutation):
    value = json.loads(files[name])
    mutation(value)
    files[name] = verifier.canonical(value)


def recalculate_snapshot(files):
    name = "enabled/portable-source-bound-snapshot/manifest.json"
    manifest = json.loads(files[name])
    prefix = "enabled/portable-source-bound-snapshot/"
    for path in manifest["file_sha256"]:
        manifest["file_sha256"][path] = verifier.sha(files[prefix + path])
    files[name] = verifier.canonical(manifest)


def status_prefix(files, new_prefix):
    for name in (
        "enabled/run/probe/collector-after.json",
        "enabled/portable-source-bound-snapshot/collector-after.json",
    ):
        value = json.loads(files[name])
        value["status"]["acknowledged_prefix"] = new_prefix
        raw = verifier.canonical(value["status"])
        value["status_raw_base64"] = base64.b64encode(raw).decode()
        value["status_raw_sha256"] = verifier.sha(raw)
        files[name] = verifier.canonical(value)


def rechain(files, mutation):
    rows = [json.loads(x) for x in files["enabled/run/native-raw.jsonl"].splitlines()]
    mutation(rows)
    previous = "0" * 64
    for row in rows:
        row["previous_sha256"] = previous
        row.pop("event_sha256")
        row["event_sha256"] = verifier.sha(verifier.canonical(row))
        previous = row["event_sha256"]
    raw = b"".join(verifier.canonical(x) + b"\n" for x in rows)
    files["enabled/run/native-raw.jsonl"] = files[
        "enabled/portable-source-bound-snapshot/native.jsonl"
    ] = raw
    status_prefix(
        files,
        {"next_sequence": len(rows), "last_event_sha256": rows[-1]["event_sha256"]},
    )


def test_real_source_bound_metadata(originals):
    result = verifier.inspect(originals)
    assert result["model_task"]["model_task_passed"] is True
    assert result["metadata_binding_verified"] is True
    assert result["raw_records"] == 160
    assert result["ACK_time_contract"]["selected_records"] == 159
    assert result["KV_tensor_equivalence"] is None
    assert result["formal_result"] is False
    assert [x["sequence"] for x in result["late_intakes_preserved"]] == [158, 159]


@pytest.mark.parametrize(
    "case",
    [
        "HTTP503",
        "foreign_peer",
        "foreign_collector_cleanup",
        "native_issuer_fork",
        "missing_after_ACK",
        "parsed_status_fork",
        "missing_ACK_rehashed_status",
        "late_events_erased",
        "wrong_full_row_prefix",
        "stale_final_ACK",
        "foreign_ACK_client",
        "expired_authentication_clock",
        "live_NPU",
        "wrong_source",
    ],
)
def test_fully_rehashed_partial_counterexamples(originals, tmp_path, case):
    files = dict(originals)
    if case == "HTTP503":
        for name in ("response-metadata.json", "result.json"):
            change(files, "enabled/run/probe/" + name, lambda v: v.update(status=503))
    elif case == "foreign_peer":
        change(
            files,
            "enabled/run/actual-owned-source-peers.json",
            lambda v: v[1]["process"].update(pid=1999999999),
        )
    elif case == "foreign_collector_cleanup":

        def fake(v):
            v["captured_sessions"][-1]["pid"] = 1999999999
            v["remaining_sessions"][-1]["owner"]["pid"] = 1999999999

        change(files, "enabled/outer-independent-terminal-audit.json", fake)
    elif case == "native_issuer_fork":
        change(
            files,
            "enabled/run/native-binding.json",
            lambda v: v["publisher"].update(pid=1999999999),
        )
    elif case == "missing_after_ACK":
        del files["enabled/run/probe/collector-after.json"]
        del files["enabled/portable-source-bound-snapshot/collector-after.json"]
    elif case == "parsed_status_fork":
        for name in (
            "enabled/run/probe/collector-after.json",
            "enabled/portable-source-bound-snapshot/collector-after.json",
        ):
            change(files, name, lambda v: v["status"].update(failed=True))
    elif case == "missing_ACK_rehashed_status":
        status_prefix(files, {})
    elif case == "late_events_erased":
        receive = json.loads(files["enabled/run/probe/response-metadata.json"])[
            "received_monotonic_ns"
        ]

        def erase(rows):
            rows[-2]["accepted_monotonic_ns"] = receive - 2
            rows[-1]["accepted_monotonic_ns"] = receive - 1

        rechain(files, erase)
    elif case == "wrong_full_row_prefix":

        def wrong(rows):
            for row in rows[1:]:
                f = json.loads(base64.b64decode(row["raw_base64"]))
                if (
                    f["schema"] == "ecpa-native-block-table-upload/v1"
                    and f["process"]["ordinal"] == 0
                ):
                    for r in f["uploaded_rows"]:
                        r["blocks"] = [20] + r["blocks"][1:]
                    f["uploaded_rows_sha256"] = verifier.sha(
                        verifier.canonical(f["uploaded_rows"])
                    )
                    raw = verifier.canonical(f)
                    row["raw_base64"] = base64.b64encode(raw).decode()
                    row["raw_sha256"] = verifier.sha(raw)

        rechain(files, wrong)
    elif case in {
        "stale_final_ACK",
        "foreign_ACK_client",
        "expired_authentication_clock",
    }:
        for name in (
            "enabled/run/probe/collector-after.json",
            "enabled/portable-source-bound-snapshot/collector-after.json",
        ):
            value = json.loads(files[name])
            if case == "stale_final_ACK":
                value["status"]["issued_monotonic_ns"] -= 10_000_000_000
                raw = verifier.canonical(value["status"])
                value["status_raw_base64"] = base64.b64encode(raw).decode()
                value["status_raw_sha256"] = verifier.sha(raw)
            elif case == "foreign_ACK_client":
                value["authentication_clock"]["client"]["pid"] = 1999999999
            else:
                value["authentication_clock"]["completed_monotonic_ns"] += (
                    10_000_000_000
                )
            files[name] = verifier.canonical(value)
    elif case == "live_NPU":
        files["enabled/run/terminal-npu-smi.txt"] += (
            b"| 3 0 | 12345 | python | 3000 |\n"
        )
    else:
        cfg = json.loads(files["enabled/owner-config.json"])
        source = next(x for x in cfg["sources"] if x["role"] == "collector")
        files["snapshots/" + source["sha256"]] += b"\n"
    if case != "missing_after_ACK":
        recalculate_snapshot(files)
    archive = tmp_path / "raw.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, raw in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(raw)
            tar.addfile(item, io.BytesIO(raw))
    manifest = json.loads((ROOT / "manifest.json").read_bytes())
    manifest["archive_sha256"] = verifier.sha(archive.read_bytes())
    manifest["inventory"] = {
        name: {"sha256": verifier.sha(raw), "bytes": len(raw)}
        for name, raw in files.items()
    }
    path = tmp_path / "manifest.json"
    path.write_bytes(verifier.canonical(manifest))
    with pytest.raises(ValueError):
        verifier.verify_archive(path, archive)
