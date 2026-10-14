"""Replay the sealed v2 r1 partial trace; never turn missing HTTP/ACK into success."""

from __future__ import annotations

import argparse
import ast
import base64
import importlib.util
import json
import re
import tarfile
import tempfile
from pathlib import Path

from .verify_kv_failures import canonical, need, sha

COLLECTOR = "a4f1cc02610700d2cfb27bf00b817a7adc2a3bc31304b2254cc1e1f8349e0a2a"
PRODUCER = "328974a3ecb7091f4dc54d209bd949d9dbcf1c1f2657743c147e26603e81ad77"
PROVIDER = "094764eebfbc728c674ac4f33da01870bc03bfefbec44b2feef330d062a539c7"


def load_archive(manifest, archive, *, oracle_failure=False):
    metadata = json.loads(Path(manifest).read_bytes())
    need(
        metadata["schema"]
        == (
            "ecpa-materialized-r3-oracle-failure-preservation/v1"
            if oracle_failure
            else "PRIVATE-materialized-r1-partial-failure-preservation/v1"
        )
        and metadata["formal_result"] is False
        and metadata["original_wrapper_exit"] == 1
        and metadata["cohort_qualified"] is False
        and (
            metadata["final_authenticated_ACK_missing"] is True
            and metadata["HTTP_response_present"] is True
            if oracle_failure
            else metadata["HTTP_and_final_authenticated_ACK_missing"] is True
        ),
        "original partial preservation scope",
    )
    need(sha(Path(archive).read_bytes()) == metadata["archive_sha256"], "archive hash")
    files = {}
    with tarfile.open(archive) as handle:
        for member in handle:
            path = Path(member.name)
            need(
                member.isfile()
                and not path.is_absolute()
                and ".." not in path.parts
                and member.name not in files
                and member.size < 16_000_000,
                "unsafe/duplicate/unbounded archive member",
            )
            files[member.name] = handle.extractfile(member).read()
    need(set(files) == set(metadata["files"]), "complete original inventory")
    for name, raw in files.items():
        need(
            sha(raw) == metadata["files"][name]["sha256"]
            and len(raw) == metadata["files"][name]["bytes"],
            "member bytes/hash",
        )
    return files


def inspect(files, *, oracle_failure=False):
    def raw(name):
        need(name in files, "missing original raw: " + name)
        return files[name]

    def obj(name):
        return json.loads(raw(name))

    p = "original/"
    cfg, recipe = obj(p + "owner-config.json"), obj(p + "recipe.json")
    freeze = obj(p + "freeze-summary.json")
    need(
        cfg == obj(p + "run/owner-config.json")
        and cfg["formal_result"] is False
        and cfg["scope"] == "KV-host-metadata-to-later-upload-only"
        and cfg["runner_source_commit"]
        == (
            "11d5b79d695b3bb42ac074e626b233e5d8426904"
            if oracle_failure
            else "7a6513ef11d6db57facda32256f56d60dec38924"
        )
        and cfg["physical_devices"] == [3, 6]
        and cfg["runtime_devices"] == [0, 1],
        "frozen original runtime/input scope",
    )
    need(
        sha(raw(p + "owner-config.json")) == freeze["owner_config_sha256"]
        and sha(raw(p + "owner.source.py"))
        == cfg["owner_source_sha256"]
        == freeze["owner_source_sha256"]
        and sha(raw(p + "recipe.json"))
        == cfg["recipe_sha256"]
        == freeze["recipe"]["sha256"],
        "original owner/input freeze",
    )
    snapshots = obj("source-map.json")["sources"]
    need(
        len(snapshots)
        == len(cfg["sources"])
        == freeze["source_files"]
        == (55 if oracle_failure else 54),
        "original source snapshot closure",
    )
    source_map = {}
    for snapshot, source in zip(snapshots, cfg["sources"], strict=True):
        need(
            all(snapshot[k] == v for k, v in source.items())
            and sha(raw(snapshot["archived_path"])) == source["sha256"],
            "exact original source bytes",
        )
        source_map[source["path"]] = snapshot
    for source in cfg["native_source_files"]:
        need(
            source_map[source["path"]]["sha256"] == source["sha256"],
            "native source closure",
        )
    roles = {s["role"]: s for s in snapshots}
    for role, digest in [
        ("collector", COLLECTOR),
        ("host-native-collector", COLLECTOR),
        ("host-native-materialized-producer", PRODUCER),
        ("mod-provider", PROVIDER),
    ]:
        need(roles[role]["sha256"] == digest, "pinned original semantic source")
    client_source = raw(roles["request-runner"]["archived_path"])
    rpc = next(
        n
        for n in ast.parse(client_source).body
        if isinstance(n, ast.FunctionDef) and n.name == "run_rpc_only"
    )
    need(
        ast.literal_eval(rpc.args.defaults[-1]) == 30, "original socket timeout source"
    )
    phase = recipe["phases"][0]
    need(
        recipe["schema"] == "ecpa-native-kv-challenge-campaign/v2"
        and len(recipe["phases"]) == 1
        and (
            phase.get("rpc_budget_s") == 180
            if oracle_failure
            else "rpc_budget_s" not in phase
        )
        and phase["minimum_completion_tokens"] == 32
        and phase["payload"]["max_tokens"] == 128
        and len(phase["tokenization"]["prompt_token_ids"]) == 1201
        and sha(canonical(phase["tokenization"]["prompt_token_ids"]))
        == phase["tokenization"]["prompt_token_ids_sha256"],
        "original v2 1201/min32/legacy budget recipe",
    )
    oracle = obj(p + "oracle-tokenization.json")
    need(
        sha(raw(p + "oracle-tokenization.json")) == cfg["oracle_tokenization_sha256"]
        and oracle["expected"] == phase["response_oracle"]["expected"]
        and oracle["CPU_precondition_only_not_HTTP_usage"] is True
        and oracle["add_special_tokens"] is False
        and oracle["count"] == len(oracle["token_ids"]) >= 32
        and oracle["token_ids_sha256"] == sha(canonical(oracle["token_ids"])),
        "original CPU-only oracle precondition",
    )
    probe = obj(p + "run/probe/result.json")
    result = obj(p + "run/result.json")
    need(
        result["passed"] is False
        and result["formal_result"] is False
        and result["probe"]
        == (
            {
                **probe,
                "independent_phase_watchdog_fired": False,
                "independent_phase_total_elapsed_gate_passed": True,
            }
            if oracle_failure
            else probe
        )
        and probe["rpc_task_passed"] is False
        and probe["native_join_qualified"] is False
        and probe["formal_result"] is False
        and probe["hardware_result"] is False
        and probe["failure"]
        == ("phase challenge task_oracle_failed" if oracle_failure else "timed out")
        and probe["recipe_sha256"] == cfg["recipe_sha256"]
        and all(
            probe[k] is None
            for k in [
                "GPU_semantic_qualification",
                "KV_MOD_semantic_obligation_satisfied",
                "full_objective_satisfied",
                "lost_requests",
                "duplicate_requests",
            ]
        ),
        "original failed runner cannot become a qualified result",
    )
    absent = (
        ["collector-after.json"]
        if oracle_failure
        else ["response.bin", "response-metadata.json", "collector-after.json"]
    )
    for name in absent:
        need(
            p + "run/probe/" + name not in files,
            "absent response/final ACK cannot be manufactured",
        )
    http_elapsed = None
    metadata = None
    if oracle_failure:
        metadata = obj(p + "run/probe/response-metadata.json")
        body = raw(p + "run/probe/response.bin")
        response = json.loads(body)
        need(
            metadata["schema"] == "ecpa-observed-KV-HTTP-response/v2"
            and probe["status"] == metadata["status"] == 200
            and metadata["url"] == phase["url"]
            and metadata["response_sha256"] == probe["response_sha256"] == sha(body)
            and metadata["request_sha256"] == sha(raw(p + "run/probe/request.bin"))
            and metadata["client_source_sha256"]
            == roles["request-runner"]["sha256"]
            == "5fd84ed40ec10c35d193381028b5fc8a05728a112f4990765b6f5d27b7fb430d",
            "original response/client/source/request binding",
        )
        choice = response["choices"][0]
        expected = ("ECPA-CHALLENGE-" + phase["challenge_nonce"] + " ") * 2
        need(
            phase["response_oracle"]["expected"] == expected.strip()
            and response["id"]
            == phase["expected_response_id"]
            == phase["external_request_id"]
            and response["model"] == phase["payload"]["model"]
            and response["usage"]["prompt_tokens"] == 1201
            and response["usage"]["completion_tokens"] == 81
            and choice["finish_reason"] == "stop"
            and isinstance(choice["message"]["content"], str)
            and choice["message"]["content"].strip()
            != phase["response_oracle"]["expected"],
            "strict frozen two-nonce task must remain an observed oracle failure",
        )
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "client.py"
            source.write_bytes(client_source)
            client_spec = importlib.util.spec_from_file_location(
                "_r3_frozen_budget_client", source
            )
            client_module = importlib.util.module_from_spec(client_spec)
            client_spec.loader.exec_module(client_module)
            client_module.verify_rpc_budget(phase, metadata)
        http_elapsed = (
            metadata["received_monotonic_ns"] - metadata["sent_monotonic_ns"]
        ) / 1_000_000_000
        need(
            probe["rpc_budget_from_frozen_phase"] is True
            and probe["rpc_budget_s"] == 180
            and probe["rpc_elapsed_gate_passed"] is True
            and probe["rpc_dispatch_monotonic_ns"] == metadata["sent_monotonic_ns"]
            and probe["rpc_completed_monotonic_ns"]
            == metadata["received_monotonic_ns"],
            "original actual HTTP clocks/frozen budget summary",
        )
    need(
        raw(p + "run/probe/request.bin") == canonical(phase["payload"])
        and obj(p + "run/probe/headers.json") == phase["headers"],
        "raw frozen request bytes",
    )
    binding, owner = (
        obj(p + "run/native-binding.json"),
        obj(p + "run/launcher-kernel-identity.json"),
    )
    handoff = obj(p + "run/handoff-raw.json")
    need(
        binding == {**handoff, "binding_sha256": sha(raw(p + "run/handoff-raw.json"))}
        and binding["publisher"] == owner
        and binding["manager_source_sha256"] == cfg["manager_source_sha256"],
        "original native publisher/kernel/handoff",
    )
    spec, ready = obj(p + "run/collector-spec.json"), obj(p + "run/collector-ready.bin")
    descriptor = obj(p + "run/collector-launcher-descriptor.json")
    need(
        spec["schema"] == "ecpa-native-kv-semantic-collector-prereg/v2"
        and spec["senders"] == obj(p + "run/actual-owned-source-peers.json")
        and spec["native_plan_id"] == binding["environment"]["VLLM_ECPA_PLAN_ID"]
        and spec["native_launch_id"] == binding["environment"]["VLLM_ECPA_LAUNCH_ID"]
        and all(descriptor[k] == v for k, v in ready.items())
        and descriptor["launcher_observed_identity"] == ready["collector"]
        and ready["collector_source_sha256"] == COLLECTOR
        and ready["spec_sha256"] == sha(raw(p + "run/collector-spec.json")),
        "original peer/source/spec descriptor",
    )
    before = obj(p + "run/probe/collector-before.json")
    status_bytes = base64.b64decode(before["status_raw_base64"], validate=True)
    status = before["status"]
    need(
        sha(status_bytes) == before["status_raw_sha256"]
        and json.loads(status_bytes) == status
        and before["kernel_peer"]
        == {
            "pid": ready["collector"]["pid"],
            "uid": obj(p + "run/collector-directory-identity.json")["uid"],
        }
        and all(
            status[k] == ready[k]
            for k in [
                "collector",
                "collector_source_sha256",
                "spec_sha256",
                "socket_identity",
                "archive_identity",
            ]
        )
        and status["failed"] is False,
        "recorded original before-request peer/status",
    )
    for sender in spec["senders"]:
        for source in sender["source_files"]:
            need(
                source_map[source["path"]]["sha256"] == source["sha256"],
                "original peer source bytes",
            )
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "source.py").write_bytes(raw(roles["collector"]["archived_path"]))
        (root / "spec.json").write_bytes(raw(p + "run/collector-spec.json"))
        (root / "spec.json").chmod(0o600)
        (root / "raw.jsonl").write_bytes(raw(p + "run/native-raw.jsonl"))
        module_spec = importlib.util.spec_from_file_location(
            "_partial_v2_frozen_collector", root / "source.py"
        )
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        proof = module.verify_journal(root / "spec.json", root / "raw.jsonl")
    events = [json.loads(line) for line in raw(p + "run/native-raw.jsonl").splitlines()]
    need(
        len(events) == (168 if oracle_failure else 100)
        and events[0]["collector"] == ready["collector"]
        and events[0]["archive_identity"] == ready["archive_identity"]
        and proof["durable_ACK_status"] == "unverified"
        and proof["complete_two_rank_KV_projection_upload_phases"] is None,
        "raw partial cannot provide missing durable final ACK",
    )
    facts = [
        json.loads(base64.b64decode(e["raw_base64"], validate=True)) for e in events[1:]
    ]
    mappings = [f for f in facts if f["schema"] == module.MAPPING]
    projections = [f for f in facts if f["schema"] == module.PROJECTION_V2]
    uploads = [f for f in facts if f["schema"] == module.UPLOAD]
    need(
        len(mappings) == 1
        and len(projections) == 2
        and len(uploads) == (164 if oracle_failure else 96)
        and mappings[0]["external_request_id"] == phase["external_request_id"]
        and all(
            f["runtime_request_id"] == mappings[0]["runtime_request_id"] for f in facts
        ),
        "exact observed single-request partial raw types",
    )
    ranks = []
    for projection in sorted(projections, key=lambda f: f["process"]["ordinal"]):
        rank = projection["process"]["ordinal"]
        matching = [
            u
            for u in uploads
            if module.projection_upload_match(projection, u)
            and any(
                row["row"] == projection["metadata_row"]
                and row["group"] == projection["attention_group"]
                and row["blocks"][: len(projection["host_cpu_block_ids"])]
                == projection["host_cpu_block_ids"]
                for row in u["uploaded_rows"]
            )
        ]
        need(
            len(matching) == (81 if oracle_failure else 47)
            and len(projection["host_cpu_block_ids"]) == 9
            and projection["scheduled_appended_block_ids"] == [19],
            "observed full-row/suffix/later prefix differs",
        )
        ranks.append(
            {
                "rank": rank,
                "later_same_row_prefix_count": len(matching),
                "observed_full_CPU_row": projection["host_cpu_block_ids"],
            }
        )
    need([r["rank"] for r in ranks] == [0, 1], "both actual source ranks")
    late_acceptances = []
    if oracle_failure:
        need(
            metadata["client"]
            == {
                **obj(p + "actual-owner-kernel.json")["kernel"],
                "start_identity": "pid:{pid}:start_ticks:{start_ticks}".format(
                    **obj(p + "actual-owner-kernel.json")["kernel"]
                ),
            },
            "original HTTP client kernel identity",
        )
        phase_end = obj(p + "run/phase-total-elapsed.json")[
            "probe_completed_monotonic_ns"
        ]
        for event in events[1:]:
            fact = json.loads(base64.b64decode(event["raw_base64"]))
            need(
                metadata["sent_monotonic_ns"]
                <= fact["monotonic_ns"]
                <= metadata["received_monotonic_ns"]
                and fact["monotonic_ns"] <= event["accepted_monotonic_ns"] <= phase_end,
                "native fact/acceptance outside recorded HTTP/phase boundaries",
            )
            if event["accepted_monotonic_ns"] > metadata["received_monotonic_ns"]:
                late_acceptances.append(
                    {
                        "sequence": event["sequence"],
                        "rank": fact["process"]["ordinal"],
                        "after_HTTP_read_ns": event["accepted_monotonic_ns"]
                        - metadata["received_monotonic_ns"],
                    }
                )
        need(
            len(late_acceptances) == 2
            and {e["rank"] for e in late_acceptances} == {0, 1},
            "original two post-read accepted uploads",
        )
    expected_phase = {
        k: phase[k]
        for k in [
            "phase_id",
            "client_request_id",
            "challenge_nonce",
            "external_request_id",
            "expected_ranks",
        ]
    }
    need(spec["phases"] == [expected_phase], "original request/nonce preregistration")
    host_events = [
        json.loads(line)
        for line in raw(
            p + Path(binding["environment"]["VLLM_HUST_EXT_EVIDENCE_PATH"]).name
        ).splitlines()
    ]
    source_processes = [sender["process"] for sender in spec["senders"]]
    need(
        {(process["role"], process["ordinal"]) for process in source_processes}
        == {("api-server", 0), ("worker", 0), ("worker", 1)},
        "original three role/rank peers",
    )
    for process in source_processes:
        need(
            process["assignment_source"] == "host"
            and process["boot_id"] == owner["boot_id"]
            and process["start_identity"]
            == f"pid:{process['pid']}:start_ticks:{process['start_ticks']}"
            and any(
                event.get("event") == "invoked"
                and event.get("entry_point", {}).get("name") == "ascend_kvcompress"
                and event.get("plan_id") == spec["native_plan_id"]
                and event.get("launch_id") == spec["native_launch_id"]
                and all(
                    event.get("process", {}).get(k) == v
                    for k, v in process.items()
                    if k not in {"boot_id", "session", "start_ticks"}
                )
                for event in host_events
            ),
            "original Host invocation/process/request source scope",
        )
    terminal = obj(p + "run/terminal-process-audit.json")
    need(
        terminal["formal_result"] is False
        and len(terminal["source_peers"]) == 3
        and all(
            x["observed_kernel"] is None
            and x["same_identity_live"] is False
            and x["different_live_identity"] is False
            for x in terminal["source_peers"]
        )
        and all(not x["members"] for x in terminal["remaining_sessions"])
        and terminal["backend_port"]["open"] is False,
        "recorded source-peer/session cleanup",
    )
    need(
        [peer["source_process"] for peer in terminal["source_peers"]]
        == source_processes,
        "terminal epoch differs from original registered peer",
    )
    api = next(
        process for process in source_processes if process["role"] == "api-server"
    )
    expected_sessions = [
        owner,
        {k: api[k] for k in ["pid", "start_ticks", "boot_id", "session"]},
    ]
    need(
        terminal["captured_sessions"] == expected_sessions
        and terminal["remaining_sessions"]
        == [{"owner": session, "members": []} for session in expected_sessions]
        and terminal["wall_ns"] > max(event["observed_at_ns"] for event in host_events),
        "original owned session terminal coverage",
    )
    for peer in terminal["source_peers"]:
        need(
            peer["expected_kernel"]
            == {
                k: peer["source_process"][k]
                for k in ["pid", "start_ticks", "boot_id", "session"]
            },
            "original terminal peer identity",
        )
    npu = raw(p + "run/terminal-npu-smi.txt").decode()
    need(
        set(re.findall(r"No running processes found in NPU (\d+)", npu)) == {"3", "6"},
        "recorded two-card terminal",
    )
    if oracle_failure:
        outer = obj(p + "outer-watchdog-result.json")
        outer_terminal = obj(p + "outer-independent-terminal-audit.json")
        expected_outer = [
            obj(p + "actual-owner-kernel.json")["kernel"],
            owner,
            {k: api[k] for k in ["pid", "start_ticks", "boot_id", "session"]},
            {
                k: ready["collector"][k]
                for k in ["pid", "start_ticks", "boot_id", "session"]
            },
        ]
        need(
            sha(raw(p + "launcher.source.py"))
            == cfg["outer_launcher_source_sha256"]
            == "0a1db5cc0182dd3dcb5d967a8fe3d84633c1770e04d63be91e8b1225d4a3461b",
            "original independent outer launcher source",
        )
        need(
            outer["independently_captured_sessions"]
            == outer_terminal["captured_sessions"]
            == expected_outer
            and outer_terminal["remaining_sessions"]
            == [{"owner": session, "members": []} for session in expected_outer]
            and outer["original_owner_exit"] == 1
            and outer["fired"] is False
            and outer["no_restart"] is True
            and outer["cleanup_errors"] == outer_terminal["cleanup_errors"] == []
            and outer_terminal["owner_identity_still_live"] is False,
            "original four-session/collector terminal evidence",
        )
        total = obj(p + "run/phase-total-elapsed.json")
        watchdog = obj(p + "run/phase-watchdog.json")
        need(
            total["budget_s"] == watchdog["budget_s"] == phase["rpc_budget_s"] == 180
            and total["watchdog_fired"] is False
            and watchdog["fired"] is False
            and total["elapsed_gate_passed"] is True
            and total["probe_entry_monotonic_ns"]
            <= metadata["sent_monotonic_ns"]
            <= metadata["received_monotonic_ns"]
            <= total["probe_completed_monotonic_ns"]
            and total["probe_completed_monotonic_ns"]
            - total["probe_entry_monotonic_ns"]
            <= 180_000_000_000
            and watchdog["deadline_monotonic_ns"]
            == total["probe_entry_monotonic_ns"] + 180_000_000_000,
            "original phase/watchdog monotonic budget",
        )
    return {
        "classification": "REAL_RUNTIME_ORACLE_FAILED_PARTIAL_UNQUALIFIED"
        if oracle_failure
        else "PARTIAL_REAL_RUNTIME_TRACE_UNQUALIFIED",
        "runner_success": False,
        "raw_records": 168 if oracle_failure else 100,
        "request_mappings": 1,
        "projection_facts": 2,
        "upload_facts": 164 if oracle_failure else 96,
        "ranks": ranks,
        "HTTP_response": 200 if oracle_failure else None,
        "model_task_passed": False if oracle_failure else None,
        "HTTP_prompt_tokens": 1201 if oracle_failure else None,
        "HTTP_completion_tokens": 81 if oracle_failure else None,
        "HTTP_finish_reason": "stop" if oracle_failure else None,
        "observed_HTTP_elapsed_s": http_elapsed,
        "compression_causality_established": False,
        "native_acceptances_after_HTTP_completed_read": late_acceptances,
        "native_fact_HTTP_clock_and_phase_accept_boundaries_verified": True
        if oracle_failure
        else None,
        "final_durable_ACK": None,
        "durable_ACK_status": "unverified",
        "hardware_result": False,
        "GPU_semantic_qualification": None,
        "KV_MOD_semantic_obligation_satisfied": None,
        "lost_requests": None,
        "duplicate_requests": None,
        "durable_join": None,
        "collector_terminal_identity_independently_verified": True
        if oracle_failure
        else None,
        "source_peers_recorded_terminal": True,
        "recorded_NPU_devices_clear": [3, 6],
        "tokenizer_reexecuted": False,
        "model_and_wheel_bytes_rehashed": False,
        "original_RPC_socket_timeout_s": 180 if oracle_failure else 30,
        "KV_tensor_equivalence": None,
        "attention_consumption": None,
        "full_quality": None,
        "full_objective_satisfied": None,
        "formal_result": False,
    }


def verify_archive(manifest, archive):
    return inspect(load_archive(manifest, archive))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_archive(args.manifest, args.archive), indent=2))


if __name__ == "__main__":
    main()
