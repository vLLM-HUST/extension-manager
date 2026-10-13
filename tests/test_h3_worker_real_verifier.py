from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from experiments.formal_campaign import verify_h3_worker_real as verifier

ROOT = (
    Path(__file__).parents[1]
    / "experiments/formal_campaign/artifacts/h3-worker-real-20261013"
)


def original():
    manifest = json.loads((ROOT / "r1-manifest.json").read_text())
    return verifier.unpack((ROOT / manifest["archive"]).read_bytes()), manifest


def change_json(files, path, change):
    obj = json.loads(files[path])
    change(obj)
    files[path] = (json.dumps(obj, indent=2) + "\n").encode()


def test_raw_failed_task_is_recomputed_separately_from_six_rpc_starts():
    files, _ = original()
    result = verifier.inspect(files, "r1", False)
    assert result["generation_backend_starts"] == 6
    assert result["owned_worker_faults"] == 3
    assert result["task_oracle_status"] == "task_oracle_failed"
    assert all(not row["exact_task"] for row in result["rows"])
    assert result["formal_result"] is False
    assert result["lost_requests"] is None
    assert "r1/cpu-preflight/campaign.json" not in files
    exclusion = json.loads(files["r1/publication-exclusions.json"])
    assert exclusion["public_copy_is_complete_original_directory"] is False


@pytest.mark.parametrize(
    "mutation,match",
    [
        (
            lambda files: change_json(
                files, "r1/ecpa/result.json", lambda d: d.update(formal_result=True)
            ),
            "scope promoted",
        ),
        (
            lambda files: change_json(
                files, "r1/ecpa/result.json", lambda d: d.update(lost_requests=0)
            ),
            "objective promoted",
        ),
        (
            lambda files: change_json(
                files,
                "r1/ecpa/result.json",
                lambda d: d.update(cleanup_errors=["survived"]),
            ),
            "cleanup failed",
        ),
        (
            lambda files: change_json(
                files,
                "r1/ecpa/result.json",
                lambda d: d["events"][1]["identity"].update(pid=1),
            ),
            "fault target differs",
        ),
        (
            lambda files: change_json(
                files,
                "r1/ecpa/result.json",
                lambda d: d["events"][3].update(
                    process_epoch=d["events"][0]["process_epoch"]
                ),
            ),
            "epoch reused",
        ),
        (
            lambda files: change_json(
                files,
                "r1/ecpa/phase0.native-binding.json",
                lambda d: d.update(binding_sha256="0" * 64),
            ),
            "raw body hash changed",
        ),
        (
            lambda files: change_json(
                files,
                "r1/ecpa/phase0.launch-argv.json",
                lambda d: d.append("--disable-ecpa-manager"),
            ),
            "launch argv changed",
        ),
        (
            lambda files: files.update({"r1/ecpa/host.source": b"fake source"}),
            "source bytes changed",
        ),
        (
            lambda files: files.update(
                {"r1/ecpa/phase0.evidence.jsonl": b"fake evidence\n"}
            ),
            "snapshot not",
        ),
        (
            lambda files: files.update(
                {"r1/terminal-npu-smi.txt": b"NPU worker still live"}
            ),
            "devices not clean",
        ),
    ],
)
def test_negative_claims_fail_when_archive_inventory_is_not_the_oracle(mutation, match):
    files, _ = original()
    mutation(files)
    with pytest.raises(ValueError, match=match):
        verifier.inspect(files, "r1", False)


def test_summary_pass_cannot_promote_wrong_raw_content():
    files, _ = original()
    change_json(files, "r1/summary.json", lambda d: d.update(task_oracle_passed=True))
    assert (
        verifier.inspect(files, "r1", False)["task_oracle_status"]
        == "task_oracle_failed"
    )
    with pytest.raises(ValueError, match="unexpected hidden input"):
        verifier.inspect(files, "r1", True)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "r1/../escape"])
def test_unsafe_archive_paths_are_rejected(name):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as archive:
        member = tarfile.TarInfo(name)
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(ValueError, match="unsafe archive"):
        verifier.unpack(out.getvalue())


def rewrite_rank(files, change):
    journal = "r1/vanilla-vllm-entry-points-phase0.jsonl"
    snapshot = "r1/vanilla-vllm-entry-points/phase0.evidence.jsonl"
    for name in (journal, snapshot):
        rows = [json.loads(line) for line in files[name].splitlines()]
        for row in rows:
            if (
                row["process"]["role"] == "worker"
                and row["process"]["ordinal"] == 1
                and row["entry_point"]["name"] == "kv_materialization"
            ):
                change(row)
        files[name] = b"".join((json.dumps(row) + "\n").encode() for row in rows)


def test_wrong_phase_rank1_is_rejected_with_true_rank0_and_rewritten_prefix():
    files, _ = original()
    rewrite_rank(
        files, lambda row: row.update(plan_id="wrongplan", launch_id="staleother")
    )
    assert files["r1/vanilla-vllm-entry-points-phase0.jsonl"].startswith(
        files["r1/vanilla-vllm-entry-points/phase0.evidence.jsonl"]
    )
    with pytest.raises(ValueError, match="same-phase MOD TP2 workers"):
        verifier.inspect(files, "r1", False)


def test_receipt_publisher_cannot_fork_from_matching_raw_body_hash():
    files, _ = original()
    change_json(
        files,
        "r1/ecpa/phase0.native-binding.json",
        lambda d: d["publisher"].update(pid=d["publisher"]["pid"] + 1000000),
    )
    with pytest.raises(ValueError, match="receipt differs from raw canonical"):
        verifier.inspect(files, "r1", False)


def test_rehashed_publisher_must_still_be_captured_owned_manager():
    files, _ = original()
    body = json.loads(files["r1/ecpa/phase0.handoff-unvalidated.json"])
    body["publisher"]["pid"] += 1000000
    body["publisher"]["session"] = body["publisher"]["pid"]
    raw = json.dumps(body).encode()
    files["r1/ecpa/phase0.handoff-unvalidated.json"] = raw
    receipt = {**body, "binding_sha256": verifier.digest(raw)}
    files["r1/ecpa/phase0.native-binding.json"] = json.dumps(receipt).encode()
    with pytest.raises(ValueError, match="captured owned Manager"):
        verifier.inspect(files, "r1", False)


def test_actual_terminal_identity_cannot_be_omitted_or_claimed_alive():
    for alteration in (
        lambda d: d["rows"].pop(),
        lambda d: d["rows"][0].update(expected_identity_alive=True),
    ):
        files, _ = original()
        change_json(files, "r1/late-terminal-process-audit.json", alteration)
        with pytest.raises(ValueError, match="terminal identities|process survived"):
            verifier.inspect(files, "r1", False)


def r2_original():
    manifest = json.loads((ROOT / "r2-manifest.json").read_text())
    return verifier.unpack((ROOT / manifest["archive"]).read_bytes())


def accepted_response_name(files, arm, phase):
    attempts = json.loads(files[f"r2/{arm}/phase{phase}.probe-attempts.json"])
    return f"r2/{arm}/" + next(a["response_path"] for a in attempts if a["accepted"])


def test_real_r2_raw_exact_task_is_recomputed_without_summary():
    files = r2_original()
    files.pop("r2/summary.json")
    result = verifier.inspect(files, "r2", True)
    assert len(result["rows"]) == 6 and all(r["exact_task"] for r in result["rows"])
    assert result["formal_result"] is False
    assert result["full_objective_satisfied"] is None


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("model", "wrong-model", "completed generation RPC"),
        ("content", "wrong task", "unexpected task-oracle"),
        ("finish_reason", "length", "unexpected task-oracle"),
    ],
)
def test_correct_rpc_cannot_hide_model_content_or_finish_failure(field, value, match):
    files = r2_original()
    name = accepted_response_name(files, "vanilla-vllm-entry-points", 0)
    response = json.loads(files[name])
    if field == "content":
        response["choices"][0]["message"][field] = value
    elif field == "finish_reason":
        response["choices"][0][field] = value
    else:
        response[field] = value
    files[name] = json.dumps(response).encode()
    with pytest.raises(ValueError, match=match):
        verifier.inspect(files, "r2", True)


def test_frozen_probe_before_fault_eligibility_and_api_clock_consistency():
    files = r2_original()
    path = "r2/vanilla-vllm-entry-points/phase0.probe-attempts.json"
    result = json.loads(files["r2/vanilla-vllm-entry-points/result.json"])
    change_json(
        files,
        path,
        lambda d: d[-1].update(monotonic_ns=result["events"][0]["monotonic_ns"] + 1),
    )
    with pytest.raises(ValueError, match="does not precede fault eligibility"):
        verifier.inspect(files, "r2", True)
    files = r2_original()
    first, second = (
        accepted_response_name(files, "vanilla-vllm-entry-points", i) for i in (0, 1)
    )
    files[first], files[second] = files[second], files[first]
    with pytest.raises(ValueError, match="API response clock"):
        verifier.inspect(files, "r2", True)


def test_terminal_observer_must_follow_every_phase_journal():
    files = r2_original()
    journal = "vanilla-vllm-entry-points-phase0.jsonl"
    name = "r2/" + journal
    row = json.loads(files[name].splitlines()[0])
    terminal = json.loads(files["r2/late-terminal-process-audit.json"])
    row["observed_at_ns"] = terminal["wall_ns"] + 1
    files[name] += (json.dumps(row) + "\n").encode()
    change_json(
        files,
        "r2/late-terminal-process-audit.json",
        lambda d: d["journal_sha256"].update({journal: verifier.digest(files[name])}),
    )
    assert files[name].startswith(
        files["r2/vanilla-vllm-entry-points/phase0.evidence.jsonl"]
    )
    with pytest.raises(ValueError, match="terminal observer predates"):
        verifier.inspect(files, "r2", True)


def test_cache_directory_identity_and_cold_policy_are_bound():
    for field, value in (("inode", 1), ("initial_files", ["previous-run-cache"])):
        files = r2_original()
        change_json(
            files,
            "r2/cache-policy.json",
            lambda d, field=field, value=value: d["arms"]["ecpa"].update(
                {field: value}
            ),
        )
        # Rehash the metadata binding to exercise the independent semantic check.
        change_json(
            files,
            "r2/freeze.json",
            lambda d, files=files: d["files_sha256"].update(
                {"cache-policy.json": verifier.digest(files["r2/cache-policy.json"])}
            ),
        )
        with pytest.raises(ValueError, match="cache identity|cold cache"):
            verifier.inspect(files, "r2", True)
