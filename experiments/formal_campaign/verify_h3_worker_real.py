"""Independently inspect archived worker RPC/relaunch evidence, never formal H3."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import tarfile
from datetime import datetime
from pathlib import Path, PurePosixPath

ARMS = ("vanilla-vllm-entry-points", "manual-integration", "ecpa")
CONTRACTS = {
    "vanilla-vllm-entry-points": "entry-points-unmanaged",
    "manual-integration": "explicit-manual-hooks",
    "ecpa": "manager-controlled-activation",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def need(condition, message):
    if not condition:
        raise ValueError(message)


def unpack(data):
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            need(
                not path.is_absolute() and ".." not in path.parts, "unsafe archive path"
            )
            need(member.isfile(), "archive must contain only regular files")
            need(member.size <= 64 * 1024 * 1024, "oversize archive member")
            need(member.name not in files, "duplicate archive member")
            files[member.name] = archive.extractfile(member).read()
    return files


def inspect(files, prefix, task_expected):
    def raw(name):
        return files[f"{prefix}/{name}"]

    def read(name):
        return json.loads(raw(name))

    campaign, freeze = read("campaign.json"), read("freeze.json")
    need(
        digest(raw("campaign.json")) == freeze["campaign_sha256"],
        "campaign bytes changed",
    )
    need(
        campaign["formal_result"] is False
        and campaign["original_manager_cell_completed"] is False,
        "formal scope promoted",
    )
    need(
        campaign["classification"] == "QUALIFIED_NONFORMAL",
        "qualification scope changed",
    )
    need(
        campaign["policy"]["signal"] == "SIGKILL"
        and campaign["policy"]["relaunches"] == 1,
        "fault policy changed",
    )
    need(
        {a["id"] for a in campaign["arms"]} == set(ARMS) and len(campaign["arms"]) == 3,
        "three arms required",
    )
    need(
        freeze["manager_source_commit"] == "0a6fdbc7784a0db0a92fc50615f5ca3efbf5f966",
        "runtime wheel revision changed",
    )
    excluded = (
        read("publication-exclusions.json")
        if f"{prefix}/publication-exclusions.json" in files
        else {"private_retained": {}}
    )
    for name, expected in freeze["files_sha256"].items():
        if name in excluded["private_retained"]:
            need(
                not task_expected and name == "cpu-preflight/campaign.json",
                "unexpected hidden input",
            )
            need(
                excluded["private_retained"][name]["sha256"] == expected,
                "private input hash changed",
            )
        else:
            need(digest(raw(name)) == expected, "frozen input bytes changed: " + name)
    for key in ("lost_requests", "duplicate_requests", "full_objective_satisfied"):
        need(freeze[key] is None, "unknown objective promoted")
    need(
        read("preflight.json")["passed"] and read("device-init-probe.json")["passed"],
        "input/device audit failed",
    )
    audit_input = read("preflight.json")
    need(
        audit_input["manager"]["commit"] == freeze["manager_source_commit"]
        and audit_input["manager"]["dirty"] == "",
        "runtime Manager checkout changed",
    )
    expected_wheels = {
        "vllm": "a850a238b7ac0b6fdb9fd0ceb833dd843c0242570977b0f14fae482fe8d3d551",
        "vllm-ascend": (
            "16438dc60e86c7bc4741a3520d80d5f9de54676daabe2035ebff0d6b2dceefcf"
        ),
        "vllm-kv-materialization": (
            "581caaff07a610bfc3ce9280c315e9548b532fb119731d14fff002aea6825b1c"
        ),
        "vllm-hust-ext": (
            "0498efa84fa0739abc924f9680764ec3ba88c0ab9eaf5574906038cb0a1f2358"
        ),
    }
    for name, expected in expected_wheels.items():
        need(
            audit_input["wheels"][name]["sha256"] == expected
            and audit_input["wheels"][name]["mismatches"] == [],
            "exact installed wheel input changed",
        )
    if task_expected:
        need(
            freeze["runner_source_commit"] == "aef46c09b6c574ad42945f331a0dc68f9a19b2f2"
            and freeze["runtime_manager_and_runner_are_distinct"] is True,
            "runner/runtime source distinction lost",
        )
    frozen_ns = int(datetime.fromisoformat(freeze["frozen_utc"]).timestamp() * 1e9)
    rows = []
    response_ids = set()
    phase_worker_ids = set()
    terminal_expected = set()
    final_journal_hashes = {}
    captured_sessions = {}
    latest_host_wall_ns = 0
    for arm in campaign["arms"]:
        name = arm["id"]
        need(
            arm["activation_contract"] == CONTRACTS[name]
            and arm["env"]["ECPA_ACTIVATION_CONTRACT"] == CONTRACTS[name],
            "arm activation contract changed",
        )
        flags = set(arm["argv"]) & {
            "--disable-ecpa-manager",
            "--enable-entrypoints",
            "--manual-hooks",
        }
        expected_flags = (
            set()
            if name == "ecpa"
            else {
                "--disable-ecpa-manager",
                "--manual-hooks"
                if name == "manual-integration"
                else "--enable-entrypoints",
            }
        )
        need(flags == expected_flags, "native activation flags changed")
        need(
            arm["argv"][arm["argv"].index("--tensor-parallel-size") + 1] == "2",
            "actual TP2 launch missing",
        )
        port = arm["argv"][arm["argv"].index("--port") + 1]
        need(
            arm["probe"]["url"] == f"http://127.0.0.1:{port}/v1/chat/completions",
            "probe not bound to actual launch port",
        )
        result = read(f"{name}/result.json")
        need(
            result["passed"] and result["cleanup_errors"] == [], "runner/cleanup failed"
        )
        need(
            result["campaign_sha256"] == digest(raw("campaign.json")),
            "result campaign mismatch",
        )
        need(
            raw(f"{name}/campaign.json") == raw("campaign.json"),
            "arm campaign mismatch",
        )
        need(
            result["formal_result"] is False
            and result["original_manager_cell_completed"] is False,
            "arm scope promoted",
        )
        for key in ("lost_requests", "duplicate_requests", "full_objective_satisfied"):
            need(result[key] is None, "arm objective promoted")
        for source in arm["sources"]:
            need(
                digest(raw(f"{name}/{source['role']}.source")) == source["sha256"],
                "launch source bytes changed",
            )
        observed = [e for e in result["events"] if e["kind"] == "worker-observed"]
        faults = [e for e in result["events"] if e["kind"] == "signal-delivered"]
        exits = [e for e in result["events"] if e["kind"] == "target-exited"]
        need(
            len(observed) == 2 and len(faults) == 1 and len(exits) == 1,
            "two starts/one fault required",
        )
        need([e["phase"] for e in observed] == [0, 1], "phase order changed")
        need(
            faults[0]["identity"] == observed[0]["identity"]
            and faults[0]["process_epoch"] == observed[0]["process_epoch"],
            "fault target differs",
        )
        need(
            observed[0]["monotonic_ns"]
            < faults[0]["monotonic_ns"]
            < exits[0]["monotonic_ns"]
            < observed[1]["monotonic_ns"],
            "fault/relaunch order changed",
        )
        need(
            observed[0]["identity"] != observed[1]["identity"]
            and observed[0]["process_epoch"] != observed[1]["process_epoch"],
            "worker identity/epoch reused",
        )
        arm_native = []
        for phase in range(2):
            spec = arm["phases"][phase]
            argv = read(f"{name}/phase{phase}.launch-argv.json")
            if name == "ecpa":
                receipt = read(f"{name}/phase{phase}.native-binding.json")
                need(
                    digest(raw(f"{name}/phase{phase}.handoff-unvalidated.json"))
                    == receipt["binding_sha256"],
                    "native raw body hash changed",
                )
                native_body = read(f"{name}/phase{phase}.handoff-unvalidated.json")
                need(
                    {k: v for k, v in receipt.items() if k != "binding_sha256"}
                    == native_body,
                    "native receipt differs from raw canonical body",
                )
                need(
                    receipt["publisher"] in observed[phase]["ownership_sessions"]
                    and receipt["publisher"]["session"] == receipt["publisher"]["pid"],
                    "native publisher is not captured owned Manager/session",
                )
                need(
                    receipt["manager_source_sha256"] == arm["manager_source_sha256"],
                    "native Manager source changed",
                )
                need(
                    receipt["published_wall_ns"] > frozen_ns,
                    "native receipt predates freeze",
                )
                terminal_expected.add(
                    (receipt["publisher"]["pid"], receipt["publisher"]["start_ticks"])
                )
                env = receipt["environment"]
                arm_native.append(
                    (env["VLLM_ECPA_PLAN_ID"], env["VLLM_ECPA_LAUNCH_ID"])
                )
                plan_id, launch_id = arm_native[-1]
                journal = Path(env["VLLM_HUST_EXT_EVIDENCE_PATH"]).name
                expected_argv = [
                    spec["handoff_path"] if v == "@native_phase_socket@" else v
                    for v in arm["argv"]
                ]
                need(
                    not any(
                        k in arm["env"]
                        for k in (
                            "VLLM_ECPA_PLAN_ID",
                            "VLLM_ECPA_LAUNCH_ID",
                            "VLLM_HUST_EXT_EVIDENCE_PATH",
                        )
                    ),
                    "native IDs supplied externally",
                )
            else:
                plan_id, launch_id = arm["plan_id"], spec["launch_id"]
                journal = Path(spec["evidence_path"]).name
                expected_argv = arm["argv"]
            need(argv == expected_argv, "launch argv changed")
            full = raw(journal)
            need(
                full.startswith(raw(f"{name}/phase{phase}.evidence.jsonl")),
                "early snapshot not a full-journal prefix",
            )
            final_journal_hashes[journal] = digest(full)
            records = [json.loads(line) for line in full.splitlines()]
            latest_host_wall_ns = max(
                latest_host_wall_ns, max(row["observed_at_ns"] for row in records)
            )
            for row in records:
                proc = row["process"]
                terminal_expected.add(
                    (proc["pid"], int(proc["start_identity"].rsplit(":", 1)[1]))
                )
            for owner in observed[phase]["ownership_sessions"]:
                captured_sessions[owner["pid"]] = owner
            expected_entry = {
                "group": "vllm.general_plugins",
                "name": "kv_materialization",
                "value": "vllm_kv_materialization.plugin:register_plugin",
            }
            phase_workers = {}
            for row in records:
                proc = row["process"]
                if (
                    row["event"] == "invoked"
                    and proc["role"] == "worker"
                    and proc["assignment_source"] == "host"
                    and row["entry_point"] == expected_entry
                    and row["plan_id"] == plan_id
                    and row["launch_id"] == launch_id
                ):
                    need(
                        row["observed_at_ns"] > frozen_ns, "rank record predates freeze"
                    )
                    ordinal = proc["ordinal"]
                    start = proc["start_identity"]
                    need(
                        start.startswith(f"pid:{proc['pid']}:start_ticks:"),
                        "rank start identity malformed",
                    )
                    ticks = int(start.rsplit(":", 1)[1])
                    need(
                        ticks > 0 and proc["process_epoch"] > 0,
                        "rank identity/epoch invalid",
                    )
                    key = (proc["pid"], ticks, proc["process_epoch"])
                    phase_workers.setdefault(ordinal, set()).add(key)
            need(
                set(phase_workers) == {0, 1}
                and all(len(keys) == 1 for keys in phase_workers.values()),
                "both real same-phase MOD TP2 workers required",
            )
            rank_keys = [next(iter(phase_workers[i])) for i in (0, 1)]
            need(
                len({k[0] for k in rank_keys}) == 2
                and len({k[2] for k in rank_keys}) == 2,
                "two ranks reuse PID/epoch",
            )
            need(
                not (set(rank_keys) & phase_worker_ids),
                "worker identity reused across starts",
            )
            phase_worker_ids.update(rank_keys)
            event = observed[phase]
            need(
                event["raw"] in records, "selected worker absent from final raw journal"
            )
            worker = event["raw"]["process"]
            need(
                (
                    worker["pid"],
                    event["identity"]["start_ticks"],
                    worker["process_epoch"],
                )
                == rank_keys[0],
                "fault target differs from same-phase MOD worker0",
            )
            need(
                worker["role"] == "worker"
                and worker["assignment_source"] == "host"
                and worker["ordinal"] == 0,
                "target is not real Host worker0",
            )
            need(
                worker["pid"] == event["identity"]["pid"]
                and worker["process_epoch"] == event["process_epoch"],
                "target identity changed",
            )
            expected_start = (
                f"pid:{worker['pid']}:start_ticks:{event['identity']['start_ticks']}"
            )
            need(
                worker["start_identity"] == expected_start,
                "start identity changed",
            )
            need(
                event["raw"]["plan_id"] == plan_id
                and event["raw"]["launch_id"] == launch_id,
                "native/fixed phase binding mismatch",
            )
            need(
                event["raw"]["observed_at_ns"] > frozen_ns,
                "worker evidence predates freeze",
            )
            need(
                event["identity"]["session"]
                in {s["pid"] for s in event["ownership_sessions"]},
                "worker session not captured",
            )
            attempts = read(f"{name}/phase{phase}.probe-attempts.json")
            accepted = [a for a in attempts if a["accepted"]]
            need(
                len(accepted) == 1 and attempts[-1] == accepted[0],
                "one terminal accepted response required",
            )
            attempt = accepted[0]
            response = read(f"{name}/{attempt['response_path']}")
            need(
                attempt["status"] == 200
                and response["model"] == arm["probe"]["payload"]["model"]
                and response["usage"]["completion_tokens"] > 0
                and response["choices"],
                "completed generation RPC missing",
            )
            need(
                read(f"{name}/phase{phase}.request.json") == arm["probe"]["payload"],
                "frozen prompt changed",
            )
            need(
                attempt["monotonic_ns"] < event["monotonic_ns"],
                "completed response does not precede fault eligibility",
            )
            need(
                response["id"] not in response_ids,
                "response reused across backend starts",
            )
            response_ids.add(response["id"])
            # This is a consistency check under the API server's clock, not a
            # client completion timestamp or a challenge/authority binding.
            created = response["created"]
            need(
                type(created) is int
                and (created + 1) * 1_000_000_000 >= event["raw"]["observed_at_ns"],
                "API response clock predates phase worker evidence",
            )
            if phase == 0:
                need(
                    created * 1_000_000_000 < observed[1]["raw"]["observed_at_ns"],
                    "API response clock belongs to later launch phase",
                )
            content = response["choices"][0]["message"]["content"]
            exact = (
                isinstance(content, str)
                and content.strip() == "ECPA-WORKER-READY"
                and response["choices"][0]["finish_reason"] == "stop"
            )
            need(exact is task_expected, "unexpected task-oracle result")
            if task_expected:
                need(
                    arm["probe"]["response_oracle"]
                    == {
                        "type": "exact-message-content",
                        "expected": "ECPA-WORKER-READY",
                        "strip_outer_whitespace": True,
                        "finish_reason": "stop",
                    },
                    "oracle not frozen exactly",
                )
                need(
                    attempt["task_oracle_status"] == "passed"
                    and attempt["rpc_lifecycle_ready"] is True,
                    "frozen oracle not accepted",
                )
                need(
                    arm["env"]["HOME"] == "/root"
                    and arm["env"]["TRITON_HOME"] == "/root"
                    and "TRITON_CACHE_DIR" in arm["env"],
                    "cache environment closure missing",
                )
            rows.append(
                {
                    "arm": name,
                    "phase": phase,
                    "worker_pid": worker["pid"],
                    "process_epoch": worker["process_epoch"],
                    "rpc_generation": True,
                    "exact_task": exact,
                }
            )
        need(
            arm_native[0][0] == arm_native[1][0]
            and arm_native[0][1] != arm_native[1][1],
            "native plan changed or launch reused",
        ) if arm_native else None
    audit = read("late-terminal-process-audit.json")
    need(
        audit["classification"] == "late-read-only-observer-not-preregistered"
        and audit["formal_result"] is False,
        "terminal observer scope changed",
    )
    need(
        audit["observer_source_sha256"]
        == digest(raw("late-terminal-process-observer.py")),
        "terminal observer source changed",
    )
    need(
        audit["journal_sha256"] == final_journal_hashes,
        "terminal observer journal binding changed",
    )
    need(
        {(r["pid"], r["start_ticks"]) for r in audit["rows"]} == terminal_expected
        and len(audit["rows"]) == len(terminal_expected),
        "terminal identities missing or duplicate",
    )
    need(
        all(r["expected_identity_alive"] is False for r in audit["rows"]),
        "expected terminal process survived",
    )
    for row in audit["rows"]:
        proc = row["observed_proc"]
        need(
            proc is None
            or proc["state"] == "Z"
            or proc["start_ticks"] != row["start_ticks"],
            "terminal proc contradicts identity exit",
        )
    need(
        {r["pid"]: r for r in audit["captured_ownership_sessions"]} == captured_sessions
        and audit["live_members_of_captured_sessions"] == [],
        "captured session cleanup incomplete",
    )
    need(
        all(r["boot_id"] == audit["boot_id"] for r in captured_sessions.values()),
        "terminal boot identity differs",
    )
    need(
        audit["wall_ns"] > latest_host_wall_ns,
        "terminal observer predates launch evidence",
    )
    if task_expected:
        cache = read("cache-policy.json")
        need(
            cache["HOME"] == "/root" and cache["TRITON_HOME"] == "/root",
            "frozen cache roots changed",
        )
        need(set(cache["arms"]) == set(ARMS), "cache arm policy incomplete")
        need(
            len({a["env"]["TRITON_CACHE_DIR"] for a in campaign["arms"]}) == 3,
            "cache shared across arms",
        )
        cache_terminal = read("cache-terminal-manifest.json")
        need(
            cache_terminal["compiled_cache_files_published"] is False,
            "compiled-cache publication scope changed",
        )
        for arm in campaign["arms"]:
            entry = cache["arms"][arm["id"]]
            need(
                entry["path"] == arm["env"]["TRITON_CACHE_DIR"]
                and entry["mode"] == "0o700"
                and entry["uid"] == 0
                and entry["initial_files"] == [],
                "frozen per-arm cold cache identity changed",
            )
            terminal_entry = cache_terminal["arms"][arm["id"]]
            need(
                all(
                    terminal_entry[k] == entry[k]
                    for k in ("path", "uid", "mode", "device", "inode")
                ),
                "terminal cache identity differs from frozen directory",
            )
            need(
                any(
                    path.endswith("/npu_utils.so")
                    and meta["bytes"] > 0
                    and len(meta["sha256"]) == 64
                    for path, meta in terminal_entry["files"].items()
                ),
                "generated async loader cache artifact missing",
            )
    need(
        "No running processes found in NPU 3" in raw("terminal-npu-smi.txt").decode()
        and "No running processes found in NPU 6"
        in raw("terminal-npu-smi.txt").decode(),
        "devices not clean",
    )
    return {
        "classification": "QUALIFIED_NONFORMAL",
        "formal_result": False,
        "original_manager_cell_completed": False,
        "generation_backend_starts": 6,
        "owned_worker_faults": 3,
        "task_oracle_status": "passed" if task_expected else "task_oracle_failed",
        "lost_requests": None,
        "duplicate_requests": None,
        "full_objective_satisfied": None,
        "rows": rows,
    }


def verify_archive(path, manifest):
    data = path.read_bytes()
    need(digest(data) == manifest["archive_sha256"], "archive digest changed")
    files = unpack(data)
    need(
        {name: digest(body) for name, body in files.items()}
        == manifest["files_sha256"],
        "archive inventory changed",
    )
    return inspect(files, manifest["prefix"], manifest["task_expected"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    print(
        json.dumps(
            verify_archive(args.manifest.parent / manifest["archive"], manifest),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
