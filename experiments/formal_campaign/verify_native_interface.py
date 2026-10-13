"""Replay the exact ee62 generic native interface archive; never KV semantics."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import re
import tarfile
import tempfile
from pathlib import Path

COLLECTOR_SHA = "ee62c51444acde7b813c33ea4c2b20ab07248ea050753199cbfc79d73f1c5075"
HOST_REV = "a4bdbe74c1bdc1228e3cc19c61887225d35f16f8"
ASCEND_REV = "fcbb827af84f793939bf03d01a1dfe0338a0164c"
HOST_WHEEL = "a55e4e98b44f789fed78b87ed826ba33ed5cf70ac0d385f6e2c8c644c4c67eb7"
ASCEND_WHEEL = "be5a69b8dc2dd9a77144657a6d394aa7079e95054aef54dda41f260b0af6eb86"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def need(condition, message):
    if not condition:
        raise ValueError(message)


def inspect(files):
    def raw(name):
        need(name in files, "missing raw file: " + name)
        return files[name]

    def obj(name):
        return json.loads(raw(name))

    cfg = obj("r2/owner-config.json")
    recipe = obj("r2/recipe.json")
    need(
        cfg["formal_result"] is False
        and cfg["scope"] == "native-request-upload-transport-only",
        "runtime scope",
    )
    need(
        sha(raw("r2/owner.source.py")) == cfg["owner_source_sha256"],
        "frozen owner source",
    )
    need(
        cfg["owner_execution_path"].endswith("/r2/owner.source.py")
        or cfg["owner_execution_path"].endswith("-r2/owner.source.py"),
        "owner execution is not frozen snapshot",
    )
    need(sha(raw("r2/recipe.json")) == cfg["recipe_sha256"], "frozen recipe bytes")
    need(
        recipe["frozen_monotonic_ns"] < cfg["frozen_monotonic_ns"],
        "request preregistration chronology",
    )
    artifacts = cfg["wheel_artifacts"]
    need(
        set(artifacts)
        == {"host", "ascend", "mod", "manager", "torch", "torch_npu", "triton"},
        "seven exact wheel roles",
    )
    need(
        artifacts["host"]["revision"] == HOST_REV
        and artifacts["host"]["sha256"] == HOST_WHEEL,
        "exact Host tuple",
    )
    need(
        artifacts["ascend"]["revision"] == ASCEND_REV
        and artifacts["ascend"]["sha256"] == ASCEND_WHEEL,
        "exact Ascend tuple",
    )
    need(
        obj("r2/installed-source-audit.json")["artifacts"] == artifacts,
        "installed wheel provenance differs",
    )
    need(
        len(cfg["model_files"]) == 14
        and cfg["physical_devices"] == [3, 6]
        and cfg["runtime_devices"] == [0, 1],
        "model/device freeze",
    )
    need(
        cfg["env"]["HOME"] == cfg["env"]["TRITON_HOME"] == "/root",
        "cache resolver closure",
    )
    need(
        not any(
            k in cfg["env"]
            for k in (
                "VLLM_ECPA_PLAN_ID",
                "VLLM_ECPA_LAUNCH_ID",
                "VLLM_HUST_EXT_EVIDENCE_PATH",
                "ASCEND_RT_VISIBLE_DEVICES",
                "CUDA_VISIBLE_DEVICES",
                "NPU_VISIBLE_DEVICES",
            )
        ),
        "externally minted IDs or visibility",
    )
    source_map = obj("r2/source-snapshot-map.json")
    need(len(source_map) == len(cfg["sources"]), "source snapshot closure")
    for item, original in zip(source_map, cfg["sources"], strict=True):
        need(
            {k: item[k] for k in original} == original
            and sha(raw(item["archived_path"])) == original["sha256"],
            "source snapshot differs from prelaunch bytes",
        )
    source_by_path = {x["path"]: x["sha256"] for x in source_map}
    source_by_role = {x["role"]: x for x in source_map}
    source = raw(source_by_role["collector"]["archived_path"])
    need(sha(source) == COLLECTOR_SHA, "exact runtime ee62 collector snapshot required")
    for role in (
        "host-native-collector",
        "host-native-bootstrap",
        "host-native-observer",
        "ascend-gpu-model-runner",
        "host-input-processor",
        "host-process-evidence",
    ):
        need(role in source_by_role, "native source closure")
    need(
        source_by_role["host-native-collector"]["sha256"] == COLLECTOR_SHA,
        "installed collector source",
    )
    native_sources = cfg["native_source_files"]
    need(
        all(source_by_path.get(x["path"]) == x["sha256"] for x in native_sources),
        "native source registrations",
    )

    need(
        len(recipe["phases"]) == 1 and recipe["formal_result"] is False,
        "single candidate phase",
    )
    phase = recipe["phases"][0]
    client, nonce = phase["client_request_id"], phase["challenge_nonce"]
    need(
        re.fullmatch("[0-9a-f]{32}", client) and re.fullmatch("[0-9a-f]{32}", nonce),
        "public 128-bit request/challenge",
    )
    expected = "ECPA-CHALLENGE-" + nonce
    need(
        phase["external_request_id"]
        == phase["expected_response_id"]
        == "chatcmpl-" + client,
        "external request recipe",
    )
    need(
        phase["headers"]
        == {"Content-Type": "application/json", "X-Request-Id": client},
        "frozen request headers",
    )
    need(
        phase["payload"]["request_id"] == client
        and phase["payload"]["messages"]
        == [{"role": "user", "content": "Reply exactly " + expected}],
        "nonce recipe",
    )
    need(
        phase["response_oracle"]
        == {
            "expected": expected,
            "strip_outer_whitespace": True,
            "finish_reason": "stop",
        },
        "exact task oracle",
    )
    need(
        raw("r2/run/probe/request.bin") == canonical(phase["payload"])
        and obj("r2/run/probe/headers.json") == phase["headers"],
        "actual HTTP request differs",
    )
    response = obj("r2/run/probe/response.bin")
    need(
        response["id"] == phase["expected_response_id"]
        and response["model"] == phase["payload"]["model"]
        and response["usage"]["completion_tokens"] > 0,
        "actual response identity/model/generation",
    )
    need(
        response["choices"][0]["message"]["content"].strip() == expected
        and response["choices"][0]["finish_reason"] == "stop",
        "actual nonce task oracle failed",
    )
    client_status = obj("r2/run/probe/result.json")
    need(
        client_status["status"] == 200
        and client_status["rpc_task_passed"] is True
        and client_status["response_sha256"] == sha(raw("r2/run/probe/response.bin")),
        "actual client HTTP status/task/bytes",
    )
    posts = re.findall(
        r'"POST /v1/chat/completions HTTP/1\.1" (\d{3}) ',
        raw("r2/run/backend.stdout").decode(),
    )
    need(posts == ["200"], "actual single backend POST status")

    receipt = obj("r2/run/native-binding.json")
    handoff = raw("r2/run/handoff-raw.json")
    need(
        receipt == {**json.loads(handoff), "binding_sha256": sha(handoff)},
        "raw native handoff diverges from receipt",
    )
    owner = obj("r2/run/launcher-kernel-identity.json")
    need(
        receipt["publisher"] == owner
        and receipt["manager_source_sha256"] == cfg["manager_source_sha256"],
        "owned Manager binding",
    )
    native = receipt["environment"]
    spec = obj("r2/run/collector-spec.json")
    phase5 = {
        k: phase[k]
        for k in (
            "phase_id",
            "client_request_id",
            "challenge_nonce",
            "external_request_id",
            "expected_ranks",
        )
    }
    need(
        spec["phases"] == [phase5]
        and spec["native_plan_id"] == native["VLLM_ECPA_PLAN_ID"]
        and spec["native_launch_id"] == native["VLLM_ECPA_LAUNCH_ID"],
        "collector preregistration/source phase",
    )
    peers = obj("r2/run/actual-owned-source-peers.json")
    need(
        peers == spec["senders"] and len({x["process"]["pid"] for x in peers}) == 3,
        "owned API/two-rank registration",
    )
    need(
        {(x["process"]["role"], x["process"]["ordinal"]) for x in peers}
        == {("api-server", 0), ("worker", 0), ("worker", 1)},
        "exact role set",
    )
    journal_name = "r2/" + Path(native["VLLM_HUST_EXT_EVIDENCE_PATH"]).name
    host_events = [json.loads(line) for line in raw(journal_name).splitlines()]

    def validate_registered_peers(
        attempt,
        config,
        binding,
        registered,
        actual_peers,
        original_events,
        actual_owner,
    ):
        need(
            binding["publisher"] == actual_owner
            and binding["manager_source_sha256"] == config["manager_source_sha256"],
            "actual Manager source/kernel binding",
        )
        need(
            actual_peers == registered["senders"]
            and registered["native_plan_id"]
            == binding["environment"]["VLLM_ECPA_PLAN_ID"]
            and registered["native_launch_id"]
            == binding["environment"]["VLLM_ECPA_LAUNCH_ID"],
            "original source registration/native scope",
        )
        need(
            len(actual_peers) == 3
            and len({x["process"]["pid"] for x in actual_peers}) == 3
            and {(x["process"]["role"], x["process"]["ordinal"]) for x in actual_peers}
            == {("api-server", 0), ("worker", 0), ("worker", 1)},
            "original API/two-worker role set",
        )
        snapshots = obj(attempt + "/source-snapshot-map.json")
        need(len(snapshots) == len(config["sources"]), "source closure incomplete")
        for snapshot, original in zip(snapshots, config["sources"], strict=True):
            need(
                {k: snapshot[k] for k in original} == original
                and sha(raw(snapshot["archived_path"])) == original["sha256"],
                "original source snapshot binding",
            )
        frozen_sources = {x["path"]: x["sha256"] for x in config["sources"]}
        need(
            all(
                frozen_sources.get(x["path"]) == x["sha256"]
                for x in config["native_source_files"]
            ),
            "original native source closure",
        )
        for peer in actual_peers:
            p = peer["process"]
            need(
                peer["source_files"] == config["native_source_files"]
                and p["assignment_source"] == "host"
                and p["start_identity"]
                == f"pid:{p['pid']}:start_ticks:{p['start_ticks']}"
                and p["boot_id"] == actual_owner["boot_id"]
                and p["start_ticks"] >= actual_owner["start_ticks"],
                "native peer source/kernel epoch",
            )
            need(
                any(
                    r.get("event") == "invoked"
                    and r.get("entry_point", {}).get("name") == "kv_materialization"
                    and r.get("plan_id") == registered["native_plan_id"]
                    and r.get("launch_id") == registered["native_launch_id"]
                    and all(
                        r.get("process", {}).get(k) == v
                        for k, v in p.items()
                        if k not in {"boot_id", "session", "start_ticks"}
                    )
                    for r in original_events
                ),
                "registered peer lacks original Host source event",
            )

    validate_registered_peers("r2", cfg, receipt, spec, peers, host_events, owner)

    descriptor = obj("r2/run/collector-launcher-descriptor.json")
    ready = obj("r2/run/collector-ready.bin")
    need(
        {k: descriptor[k] for k in ready} == ready
        and descriptor["launcher_observed_identity"] == ready["collector"]
        and ready["collector_source_sha256"] == COLLECTOR_SHA
        and ready["spec_sha256"] == sha(raw("r2/run/collector-spec.json")),
        "independently owned collector startup",
    )
    argv = obj("r2/run/collector-launch-argv.json")
    need(
        descriptor["launcher_observed_cmdline_sha256"]
        == sha(b"\0".join(x.encode() for x in argv) + b"\0"),
        "collector actual command fingerprint",
    )
    directory = obj("r2/run/collector-directory-identity.json")
    need(
        directory["actual_mode"] == 0o700
        and directory["device"] == ready["archive_identity"]["directory_device"]
        and directory["inode"] == ready["archive_identity"]["directory_inode"],
        "actual private archive directory",
    )
    for label in ("before", "after"):
        auth = obj("r2/run/probe/collector-" + label + ".json")
        status_raw = base64.b64decode(auth["status_raw_base64"], validate=True)
        need(
            sha(status_raw) == auth["status_raw_sha256"]
            and json.loads(status_raw) == auth["status"],
            "authenticated raw status divergence",
        )
        status = auth["status"]
        need(
            auth["kernel_peer"]
            == {"pid": ready["collector"]["pid"], "uid": directory["uid"]},
            "actual kernel collector peer",
        )
        need(
            status["collector"] == ready["collector"]
            and status["socket_identity"] == ready["socket_identity"]
            and status["socket_path"] == ready["socket_path"]
            and status["archive_identity"] == ready["archive_identity"]
            and status["collector_source_sha256"] == COLLECTOR_SHA
            and status["spec_sha256"] == ready["spec_sha256"]
            and status["failed"] is False
            and status["formal_producer_registration"] is False,
            "authenticated status/source ownership",
        )
    after = obj("r2/run/probe/collector-after.json")["status"]
    native_raw = raw("r2/run/native-raw.jsonl")
    events = [json.loads(line) for line in native_raw.splitlines()]
    need(
        events[0]["collector_source_sha256"] == COLLECTOR_SHA
        and events[0]["collector"] == ready["collector"]
        and events[0]["archive_identity"] == ready["archive_identity"],
        "exact ee62 raw source/owner; legacy compatibility is insufficient",
    )
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src, sp, jp = (
            root / "exact_collector.py",
            root / "spec.json",
            root / "raw.jsonl",
        )
        src.write_bytes(source)
        sp.write_bytes(raw("r2/run/collector-spec.json"))
        sp.chmod(0o600)
        jp.write_bytes(native_raw)
        module_spec = importlib.util.spec_from_file_location(
            "ecpa_exact_ee62_archive", src
        )
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        proof = module.verify_journal(
            sp, jp, acknowledged_prefix=after.get("acknowledged_prefix")
        )
    need(
        proof["native_chronology_status"] == "verified"
        and proof["durable_ACK_status"] == "verified-authenticated-prefix"
        and type(proof["complete_two_rank_transport_phases"]) is int
        and proof["complete_two_rank_transport_phases"] == 1
        and proof["native_API_mappings"] == 1,
        "durable exact-source chronology/two-rank proof incomplete",
    )
    counts = {0: 0, 1: 0}
    runtime = None
    for e in events[1:]:
        fact = json.loads(base64.b64decode(e["raw_base64"]))
        if fact["schema"] == "ecpa-native-request-id-mapping/v1":
            need(
                fact["external_request_id"] == response["id"],
                "native external response join",
            )
            runtime = fact["runtime_request_id"]
        else:
            need(
                fact["runtime_request_id"] == runtime
                and fact["device"] == "npu:" + str(fact["process"]["ordinal"]),
                "native actual runtime/rank/device join",
            )
            counts[fact["process"]["ordinal"]] += 1

    def cleanup(attempt, actual_owner, actual_peers, original_host_events):
        terminal = obj(attempt + "/run/terminal-process-audit.json")
        api = next(
            x["process"] for x in actual_peers if x["process"]["role"] == "api-server"
        )
        api_owner = {k: api[k] for k in ("pid", "start_ticks", "boot_id", "session")}
        expected_sessions = {canonical(actual_owner), canonical(api_owner)}
        need(
            {canonical(x) for x in terminal["captured_sessions"]} == expected_sessions
            and len(terminal["captured_sessions"]) == 2,
            "original owned launcher/API session set",
        )
        need(
            {canonical(x["owner"]) for x in terminal["remaining_sessions"]}
            == expected_sessions
            and len(terminal["remaining_sessions"]) == 2
            and all(not x["members"] for x in terminal["remaining_sessions"]),
            "actual owned session terminal coverage",
        )
        need(
            terminal["wall_ns"] > max(r["observed_at_ns"] for r in original_host_events)
            and not terminal["backend_port"]["open"]
            and terminal["backend_port"]["port"] == 29493,
            "actual terminal observer/port",
        )
        expected_processes = {x["process"]["pid"]: x["process"] for x in actual_peers}
        need(
            {x["source_process"]["pid"] for x in terminal["source_peers"]}
            == set(expected_processes)
            and len(terminal["source_peers"]) == 3,
            "original source peer terminal coverage",
        )
        for x in terminal["source_peers"]:
            p = expected_processes[x["source_process"]["pid"]]
            need(
                x["source_process"] == p
                and x["expected_kernel"]
                == {k: p[k] for k in ("pid", "start_ticks", "boot_id", "session")}
                and x["observed_kernel"] is None
                and x["same_identity_live"] is False
                and x["different_live_identity"] is False,
                "actual source peer PID/start/boot cleanup",
            )
        npu = raw(attempt + "/run/terminal-npu-smi.txt").decode()
        need(
            set(re.findall(r"No running processes found in NPU (\d+)", npu))
            == {"3", "6"}
            and set(re.findall(r"^\|\s*(\d+)\s+910B2\s*\|", npu, re.M)) == {"3", "6"}
            and not re.search(r"^\|\s*\d+\s+\d+\s*\|\s*\d+\s*\|", npu, re.M),
            "actual two-card no-running-process terminal raw",
        )
        return terminal

    terminal = cleanup("r2", owner, peers, host_events)
    r1_binding = obj("r1/run/native-binding.json")
    r1_owner = obj("r1/run/launcher-kernel-identity.json")
    need(
        r1_binding["publisher"] == r1_owner
        and r1_binding
        == {
            **json.loads(raw("r1/run/handoff-raw.json")),
            "binding_sha256": sha(raw("r1/run/handoff-raw.json")),
        },
        "original failed native binding",
    )
    r1_peers = obj("r1/run/actual-owned-source-peers.json")
    r1_events = [
        json.loads(line)
        for line in raw(
            "r1/" + Path(r1_binding["environment"]["VLLM_HUST_EXT_EVIDENCE_PATH"]).name
        ).splitlines()
    ]
    r1_spec = obj("r1/run/collector-spec.json")
    validate_registered_peers(
        "r1",
        obj("r1/owner-config.json"),
        r1_binding,
        r1_spec,
        r1_peers,
        r1_events,
        r1_owner,
    )
    cleanup("r1", r1_owner, r1_peers, r1_events)
    need(
        terminal["wall_ns"] > max(r["observed_at_ns"] for r in host_events)
        and not terminal["backend_port"]["open"]
        and all(not x["members"] for x in terminal["remaining_sessions"]),
        "terminal observer/owned sessions/port incomplete",
    )
    need(
        {x["source_process"]["pid"] for x in terminal["source_peers"]}
        == {x["process"]["pid"] for x in peers}
        and all(
            x["observed_kernel"] is None and x["same_identity_live"] is False
            for x in terminal["source_peers"]
        ),
        "actual original source peer cleanup",
    )
    need(
        obj("r1/run/result.json")["passed"] is False
        and b"collector directory is not private" in raw("r1/run/collector.stderr")
        and "r1/run/probe/response.bin" not in files,
        "original failed attempt not retained",
    )
    return {
        "classification": "REAL_NATIVE_REQUEST_UPLOAD_TRANSPORT_NONFORMAL",
        "exact_collector_source_sha256": COLLECTOR_SHA,
        "native_API_mappings": 1,
        "two_rank_upload_counts": counts,
        "native_request_upload_transport_join": True,
        "actual_hardware_transport_observed": True,
        "response_sha256": sha(raw("r2/run/probe/response.bin")),
        "completion_tokens": response["usage"]["completion_tokens"],
        "durable_ACK_status": proof["durable_ACK_status"],
        "native_chronology_status": proof["native_chronology_status"],
        "original_failed_attempt_retained": True,
        "producer_registration_classification": "CPU_REVIEW_CANDIDATE_ONLY",
        "formal_result": False,
        "KV_MOD_semantic_obligation_satisfied": None,
        "kv_tensor_equivalence": None,
        "attention_consumed_observed_tensor": None,
        "full_generation_quality": None,
        "lost_requests": None,
        "duplicate_requests": None,
        "full_objective_satisfied": None,
    }


def verify_archive(manifest_path, archive_path):
    manifest = json.loads(manifest_path.read_bytes())
    need(
        manifest["schema"] == "ecpa-native-interface-archive/v1"
        and sha(archive_path.read_bytes()) == manifest["archive_sha256"],
        "archive digest/schema",
    )
    files = {}
    with tarfile.open(archive_path, "r:gz") as archive:
        for entry in archive.getmembers():
            need(
                entry.isfile()
                and not Path(entry.name).is_absolute()
                and ".." not in Path(entry.name).parts
                and entry.name not in files,
                "unsafe/repeated archive member",
            )
            files[entry.name] = archive.extractfile(entry).read()
    need(
        set(files) == set(manifest["files"])
        and all(sha(data) == manifest["files"][name] for name, data in files.items()),
        "archive raw member inventory",
    )
    need(
        sha(files["r1/owner-config.json"]) == manifest["r1_owner_config_sha256"]
        and sha(files["r2/owner-config.json"]) == manifest["r2_owner_config_sha256"]
        and sha(files["r2/recipe.json"]) == manifest["r2_recipe_sha256"]
        and manifest["runtime_collector_source_sha256"] == COLLECTOR_SHA,
        "manifest frozen input/source bindings",
    )
    return inspect(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_archive(args.manifest, args.archive), indent=2))


if __name__ == "__main__":
    main()
