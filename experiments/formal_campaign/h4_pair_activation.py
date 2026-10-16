"""Actual two-MOD loader activation for the original H4 lifecycle cost scope.

This launches neither H3 native collectors nor a semantic public-release gate.
An existing selected-KV full semantic Plan is never edited or claimed fulfilled.
The independent H4 source contract requires each real installed EP's original
loader invocation in all actual API/scheduler/TP2 worker epochs.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
import uuid
from dataclasses import asdict
from pathlib import Path

IDS = ("org.vllm-hust.ascend-kvcompress", "org.vllm-hust.request-lifecycle-profiler")
EPS = {
    "ascend_kvcompress": "vllm_ascend_kvcompress.plugin:register",
    "request_lifecycle_profiler": (
        "vllm_request_lifecycle_profiler.plugin:register_plugin"
    ),
}
SLOTS = {("api-server", 0), ("engine-core-scheduler", 0), ("worker", 0), ("worker", 1)}
SCHEMA = "ecpa-h4-actual-pair-lifecycle-activation/v1"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def reference(path):
    return {"path": str(path), "sha256": sha(Path(path).read_bytes())}


def checked(ref):
    require(set(ref) == {"path", "sha256"}, "exact artifact reference required")
    p = Path(ref["path"])
    require(
        p.is_absolute() and p.resolve() == p and not p.is_symlink(),
        "canonical original artifact required",
    )
    raw = p.read_bytes()
    require(
        sha(raw) == ref["sha256"].removeprefix("sha256:"),
        "source/input artifact changed",
    )
    return raw


def save(path, value):
    raw = value if isinstance(value, bytes) else canonical(value)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    return reference(path)


def descendant(pid, ancestor):
    seen = set()
    while pid > 1 and pid not in seen:
        if pid == ancestor:
            return True
        seen.add(pid)
        pid = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1])
    return False


def direct_child(process, identity):
    children = []
    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        try:
            stat = (p / "stat").read_text().rsplit(")", 1)[1].split()
            if int(stat[1]) == process.pid and stat[0] != "Z":
                children.append(identity(int(p.name)))
        except (OSError, ValueError):
            continue
    require(len(children) == 1, "Manager must own one actual Host child")
    return children[0]


def source_owned_roster(raw, launch, host, identity, *, descendant_check=descendant):
    from vllm_hust_ext.host_evidence import parse_host_event

    require(raw.endswith(b"\n"), "incomplete original Host journal tail")
    roster = {name: {} for name in EPS}
    for line in raw.splitlines():
        event = parse_host_event(line)
        require(
            event["plan_id"] == launch["VLLM_ECPA_PLAN_ID"]
            and event["launch_id"] == launch["VLLM_ECPA_LAUNCH_ID"],
            "mixed original Host launch",
        )
        ep = event["entry_point"]
        if ep["name"] not in EPS:
            continue
        require(
            ep
            == {
                "group": "vllm.general_plugins",
                "name": ep["name"],
                "value": EPS[ep["name"]],
            },
            "actual owning EP differs",
        )
        require(event["event"] != "failed", "actual selected MOD loader failed")
        process = event["process"]
        k = identity(process["pid"])
        require(
            process["assignment_source"] == "host"
            and process["start_identity"]
            == f"pid:{k['pid']}:start_ticks:{k['start_ticks']}"
            and descendant_check(k["pid"], host["pid"]),
            "original Host role is not this live process tree",
        )
        if (
            event["event"] == "invoked"
            and event["observation_kind"] == "loader_lifecycle"
        ):
            slot = (process["role"], process["ordinal"])
            if slot in roster[ep["name"]]:
                require(
                    roster[ep["name"]][slot]["process"] == process,
                    "original role epoch changed",
                )
            roster[ep["name"]][slot] = {
                "process": process,
                "kernel": k,
                "event_id": event["event_id"],
            }
    for name in EPS:
        require(
            roster[name].keys() >= SLOTS,
            "two-MOD loader slot coverage incomplete: " + name,
        )
    for slot in SLOTS:
        require(
            roster["ascend_kvcompress"][slot]["process"]
            == roster["request_lifecycle_profiler"][slot]["process"],
            "different MODs bound different actual role epochs",
        )
    require(
        roster["ascend_kvcompress"][("api-server", 0)]["kernel"] == host
        and len({roster["ascend_kvcompress"][s]["kernel"]["pid"] for s in SLOTS}) == 4,
        "actual API/TP2 workers/scheduler are not four distinct epochs",
    )
    return {
        name: {f"{role}/{ordinal}": value for (role, ordinal), value in rows.items()}
        for name, rows in roster.items()
    }


class PeerListener:
    def __init__(self, listener, output, identity):
        self.listener, self.output, self.identity = listener, output, identity

    def gettimeout(self):
        return self.listener.gettimeout()

    def accept(self):
        connection, address = self.listener.accept()
        pid, uid, gid = struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        save(
            self.output / "original-Manager-peer.json",
            {
                "pid": pid,
                "uid": uid,
                "gid": gid,
                "kernel": self.identity(pid),
                "receiver_kernel": self.identity(os.getpid()),
                "wall_ns": time.time_ns(),
            },
        )
        return connection, address


def snapshot_original(path, output, name):
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        "original journal changed during byte snapshot",
    )
    ref = save(output / name, raw)
    return raw, {
        "original_path": str(path),
        "original_identity": {
            "device": after.st_dev,
            "inode": after.st_ino,
            "mode": after.st_mode & 0o777,
            "uid": after.st_uid,
            "size": after.st_size,
            "mtime_ns": after.st_mtime_ns,
        },
        "byte_exact_snapshot": ref,
        "original_sha256": sha(raw),
        "classification": (
            "snapshot of actual original callback bytes; "
            "snapshot is not the original receipt path"
        ),
    }


def compile_original_lifecycle_plan(bundles):
    """Compile a new original H4 loader scope, never downscope a semantic Plan."""
    import importlib.metadata

    from packaging.version import Version
    from vllm_hust_ext.ecpa_model import (
        EvidenceObligation,
        HostCompatibility,
        Plan,
        PredecessorSnapshot,
        content_id,
    )
    from vllm_hust_ext.plan_artifact import parse_plan_artifact, plan_artifact_bytes
    from vllm_hust_ext.semantic_runtime_binding import installed_plugin_identities

    ordered = sorted(bundles, key=lambda b: b.bundle_id)
    require(
        tuple(b.bundle_id for b in ordered) == IDS,
        "original H4 pair needs exactly both actual MODs",
    )
    plugins, snapshots = installed_plugin_identities(ordered)
    claims, obligations, ownership = [], [], []
    for bundle, plugin in zip(ordered, plugins, strict=True):
        for claim in bundle.manifest.resource_claims:
            claims.append(
                {
                    "scope": claim.scope,
                    "resource": claim.resource,
                    "owner": plugin.id,
                    "mode": claim.mode,
                }
            )
        for role, ordinals in [
            ("api-server", (0,)),
            ("engine-core-scheduler", (0,)),
            ("worker", (0, 1)),
        ]:
            body = {
                "scope": "original-H4-lifecycle-only",
                "plugin_id": plugin.id,
                "role": role,
                "ordinals": list(ordinals),
                "event": "invoked",
            }
            obligation = EvidenceObligation(
                content_id("h4-original-loader-obligation", body),
                role,
                "invoked",
                ordinals,
            )
            obligations.append(obligation)
            ownership.append(
                {
                    "obligation_id": obligation.obligation_id,
                    "plugin_id": plugin.id,
                    "bundle_id": bundle.bundle_id,
                    "entry_point": next(
                        {"group": e.group, "name": e.name, "value": e.value}
                        for e in bundle.entry_points
                        if e.group == "vllm.general_plugins" and e.name in EPS
                    ),
                }
            )
    for claim in claims:
        same = [
            c
            for c in claims
            if (c["scope"], c["resource"]) == (claim["scope"], claim["resource"])
        ]
        require(
            len(same) == 1 or all(c["mode"] == "shared" for c in same),
            "actual pair is not unconditionally resource compatible",
        )
    host = HostCompatibility(
        "vllm",
        Version(importlib.metadata.version("vllm")).public,
        "ascend",
        "cp312-cp312-linux_aarch64-Ascend910B2-TP2",
    )
    plan = Plan(
        tuple(plugins),
        host,
        (),
        tuple(obligations),
        PredecessorSnapshot(0, None, {}),
    )
    parse_plan_artifact(plan_artifact_bytes(plan))
    return {
        "schema": "ecpa-original-h4-lifecycle-scope/v1",
        "origin": "issue62-original-control-plane-cost-scope",
        "execution_plan": json.loads(plan_artifact_bytes(plan)),
        "obligation_ownership": ownership,
        "manifest_resource_claims": claims,
        "resource_authority_scope": (
            "Loader evidence Plan requests no transactional resource authority. "
            "Original manifest claims above retain their exact modes; the actual "
            "Manager generic planner independently admits those manifest resources."
        ),
        "enabled_bundles": snapshots,
        "existing_selected_KV_semantic_Plan_used_as_base": False,
        "native_KV_completion_claim": False,
        "public_release_claim": False,
    }


def prelaunch_phase(spec_path, expected_sha256, arm, phase):
    """Actual readonly/preparation operations measured by original H4 bins."""
    from vllm_hust_ext.discovery import discover_bundles
    from vllm_hust_ext.semantic_runtime_binding import installed_plugin_identities

    raw = spec_path.read_bytes()
    require(
        sha(raw) == expected_sha256.removeprefix("sha256:"),
        "registered H4 config changed",
    )
    spec = json.loads(raw)
    bundles = discover_bundles(IDS)
    require(
        tuple(b.bundle_id for b in bundles) == IDS, "actual two-MOD discovery differs"
    )
    if phase == "discovery":
        result = {
            "actual_bundles": [
                {
                    "id": b.bundle_id,
                    "distribution": b.distribution_name,
                    "version": b.distribution_version,
                }
                for b in bundles
            ]
        }
    elif phase == "validation":
        plugins, snapshots = installed_plugin_identities(bundles)
        require(
            snapshots == spec["installed_bundle_snapshots"]
            and [asdict(p) for p in plugins] == spec["plugin_identities"],
            "actual installed pair differs",
        )
        for ref in [
            *spec["source_refs"],
            *spec["input_artifact_refs"],
            spec["manager_config"],
            spec["kv_baseline_profile"],
        ]:
            checked(ref)
        result = {
            "actual_installed_sources_checked": len(spec["source_refs"]),
            "both_MODs_validated": True,
        }
    elif phase == "planning":
        result = compile_original_lifecycle_plan(bundles)
        require(
            result == spec["original_h4_lifecycle_scope"],
            "independent original H4 scope changed",
        )
    elif phase == "rendering":
        result = {
            "actual_frozen_Host_argv": spec["host_commands"][arm],
            "configured_environment": spec["environment"],
            "scope": spec["scope"],
        }
    elif phase == "evidence_setup":
        run = Path(os.environ["ECPA_H4_RUN_DIRECTORY"])
        require(
            run.resolve() == run and run.is_relative_to(Path(spec["output_root"])),
            "actual H4 run directory required",
        )
        result = {
            "scope": spec["scope"],
            "config_sha256": sha(raw),
            "actual_source": reference(Path(__file__).resolve()),
            "prepared_monotonic_ns": time.monotonic_ns(),
            "live_process_or_native_completion_claim": False,
        }
        save(run / "actual-evidence-setup.json", result)
    else:
        raise ValueError("unsupported actual H4 prelaunch phase")
    print(json.dumps(result, sort_keys=True))
    return 0


def validate_registered_commands(spec, wrapper_argv=None):
    """Only the real installed Host and admitted baseline source are executable."""
    require(spec["python"] == sys.executable, "actual selected interpreter differs")
    repo = Path(spec["manager_repository_root"])
    require(
        repo.is_absolute() and repo.resolve() == repo,
        "canonical admitted Manager repository required",
    )
    actual_wrapper = repo / "experiments/formal_campaign/h4_pair_activation.py"
    require(
        actual_wrapper.resolve() == Path(__file__).resolve(),
        "H4 wrapper is not the canonical admitted Manager source",
    )
    if wrapper_argv is not None:
        require(
            len(wrapper_argv) == 8
            and wrapper_argv[:2] == [sys.executable, str(actual_wrapper)]
            and wrapper_argv[2] == "--config"
            and wrapper_argv[4] == "--config-sha256"
            and wrapper_argv[6] == "--arm",
            "exact source-owned wrapper argv required",
        )
    baseline = repo / "experiments/formal_campaign/h3_dynamic_host.py"
    for arm, argv in spec["host_commands"].items():
        if arm == "ecpa":
            require(
                argv[:4]
                == [sys.executable, "-m", "vllm.entrypoints.cli.main", "serve"],
                "ECPA must launch real installed vLLM CLI",
            )
            require(
                not any(
                    f in argv
                    for f in (
                        "--disable-ecpa-manager",
                        "--manual-hooks",
                        "--enable-entrypoints",
                    )
                ),
                "Manager arm cannot use baseline activation",
            )
        else:
            prefix = [
                sys.executable,
                str(baseline),
                "baseline",
                "serve",
                "--disable-ecpa-manager",
                "--manual-hooks"
                if arm == "manual-integration"
                else "--enable-entrypoints",
            ]
            require(
                argv[: len(prefix)] == prefix,
                "baseline must use actual admitted independent Host activation flags",
            )
        require(
            argv.count("--tensor-parallel-size") == 1
            and argv[argv.index("--tensor-parallel-size") + 1] == "2"
            and argv.count("--port") == 1
            and spec["health_url"]
            == "http://127.0.0.1:" + argv[argv.index("--port") + 1] + "/health",
            "actual TP2 Host/loopback endpoint differs",
        )


def execute(spec_path, arm, expected_sha256):
    from vllm_hust_ext.discovery import discover_bundles
    from vllm_hust_ext.runtime_evidence import _EVIDENCE_ENVIRONMENT, _PATH_ENV, _SINK
    from vllm_hust_ext.runtime_phase_handoff import (
        accept_native_binding,
        bind_receiver,
        manager_source_digests,
        process_identity,
    )
    from vllm_hust_ext.semantic_runtime_binding import installed_plugin_identities

    spec_raw = spec_path.read_bytes()
    require(
        sha(spec_raw) == expected_sha256.removeprefix("sha256:"),
        "registered H4 activation config bytes changed",
    )
    spec = json.loads(spec_raw)
    validate_registered_commands(spec)
    require(
        spec["schema"] == SCHEMA
        and spec["scope"] == "compatible-resource-pair.lifecycle-only"
        and spec["enabled_bundles"] == list(IDS),
        "only actual independent original H4 lifecycle scope is implemented",
    )
    run = Path(os.environ["ECPA_H4_RUN_DIRECTORY"])
    require(
        run.is_absolute()
        and run.resolve() == run
        and run.is_relative_to(Path(spec["output_root"]))
        and run.is_dir()
        and not run.is_symlink(),
        "actual registered H4 run directory required",
    )
    output = run / "activation"
    output.mkdir(mode=0o700, exist_ok=False)
    save(output / "spec.json", spec_raw)
    save(output / "source.py", Path(__file__).read_bytes())
    bundles = discover_bundles(IDS)
    plugins, snapshots = installed_plugin_identities(bundles)
    require(
        snapshots == spec["installed_bundle_snapshots"],
        "actual two installed artifacts differ",
    )
    actual_plugins = [asdict(p) for p in plugins]
    require(
        actual_plugins == spec["plugin_identities"],
        "actual two PluginIdentities differ",
    )
    require(
        compile_original_lifecycle_plan(bundles) == spec["original_h4_lifecycle_scope"],
        "original independent H4 loader scope differs",
    )
    for ref in [*spec["source_refs"], *spec["input_artifact_refs"]]:
        checked(ref)
    checked(spec["manager_config"])
    checked(spec["kv_baseline_profile"])
    for b in bundles:
        matches = [
            e
            for e in b.entry_points
            if e.group == "vllm.general_plugins"
            and e.name in EPS
            and e.value == EPS[e.name]
        ]
        require(
            len(matches) == 1
            and matches[0].dist.metadata["Name"] == b.distribution_name
            and matches[0].dist.version == b.distribution_version,
            "EP does not belong to admitted actual distribution",
        )
    save(
        output / "actual-installed-source-admission.json",
        {
            "bundles": snapshots,
            "plugins": actual_plugins,
            "source_refs": spec["source_refs"],
            "scope": spec["scope"],
            "selected_KV_full_semantic_Plan_fulfilled": False,
        },
    )
    env = dict(spec["environment"])
    for k in _EVIDENCE_ENVIRONMENT:
        env.pop(k, None)
    env.pop("ECPA_H4_RUN_DIRECTORY", None)
    env["TRITON_CACHE_DIR"] = str(output / "triton-cache")
    manager = host = listener = process = None
    epoch = None
    tracked = {}
    lock = threading.RLock()
    stop = threading.Event()
    deadline = time.monotonic() + spec["owner_timeout_s"]
    previous_handlers = {}
    result = {
        "schema": "ecpa-h4-original-lifecycle-activation-guard/v1",
        "passed": False,
        "arm": arm,
        "scope": spec["scope"],
        "formal_result": False,
        "activation_guard_only": True,
        "native_KV_completion_claim": False,
        "public_release_claim": False,
    }

    def stopping(signum, frame):
        stop.set()

    def collect():
        candidates = {}
        for p in Path("/proc").iterdir():
            if p.name.isdigit():
                try:
                    k = process_identity(int(p.name))
                    pp = int((p / "stat").read_text().rsplit(")", 1)[1].split()[1])
                    candidates[k["pid"]] = (k, pp)
                except (OSError, ValueError):
                    continue
        with lock:
            for pid, (k, _) in candidates.items():
                current = pid
                seen = set()
                while current in candidates and current not in seen:
                    if current == os.getpid():
                        if pid != current:
                            tracked[pid] = k
                        break
                    seen.add(current)
                    current = candidates[current][1]

    def exact_signal(k, sig):
        fd = os.pidfd_open(k["pid"])
        try:
            require(process_identity(k["pid"]) == k, "cleanup epoch changed")
            signal.pidfd_send_signal(fd, sig)
        finally:
            os.close(fd)

    def kill(sig):
        collect()
        with lock:
            kernels = list(tracked.values())
        for k in kernels:
            with contextlib.suppress(OSError, ValueError):
                exact_signal(k, sig)

    def monitor():
        while not stop.wait(0.2):
            collect()
            if time.monotonic() >= deadline:
                result["timed_out"] = True
                stop.set()
                kill(signal.SIGKILL)
                return

    for sig in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[sig] = signal.signal(sig, stopping)
    watcher = threading.Thread(target=monitor, daemon=True)
    watcher.start()
    try:
        host_argv = list(spec["host_commands"][arm])
        if arm == "ecpa":
            env.pop("ECPA_ACTIVATION_PROFILE_PATH", None)
            env.pop("ECPA_ACTIVATION_PROFILE_SHA256", None)
            env["VLLM_HUST_EXT_CONFIG"] = spec["manager_config"]["path"]
            control_root = Path(spec["private_control_root"])
            require(
                control_root.is_absolute()
                and control_root.resolve() == control_root
                and control_root.is_relative_to(Path(spec["output_root"])),
                "private Manager handoff control root differs",
            )
            control_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            private = control_root / sha(str(run).encode())[:16]
            private.mkdir(mode=0o700, exist_ok=False)
            sock = private / "manager.sock"
            require(
                len(str(sock).encode()) < 108,
                "actual Manager socket path exceeds Unix bound",
            )
            listener = bind_receiver(sock, 25)
            argv = [
                sys.executable,
                str(Path(sys.executable).parent / "vllm-hust-ext"),
                "run",
                "--phase-binding-socket",
                str(sock),
                "--",
                *host_argv,
            ]
        else:
            env.pop("VLLM_HUST_EXT_CONFIG", None)
            env.pop("VLLMHUST_EXT_ENABLED_BUNDLES", None)
            env["ECPA_ACTIVATION_PROFILE_PATH"] = spec["kv_baseline_profile"]["path"]
            env["ECPA_ACTIVATION_PROFILE_SHA256"] = spec["kv_baseline_profile"][
                "sha256"
            ]
            env["VLLM_ECPA_PLAN_ID"] = spec["ordinary_native_plan_id"]
            env["VLLM_ECPA_LAUNCH_ID"] = str(uuid.uuid4())
            env["VLLM_ECPA_EVIDENCE_SINK"] = _SINK
            env["VLLM_ECPA_EVIDENCE_STRICT"] = "1"
            original = output / "original-baseline-Host.events.jsonl"
            save(original, b"")
            env[_PATH_ENV] = str(original)
            argv = host_argv
        from experiments.formal_campaign.h3_runtime_source_closure import (
            verify_runtime_source_closure,
        )

        runtime_closure = verify_runtime_source_closure(
            {"argv": host_argv, "cwd": str(output), "environment": env},
            spec["fixed_identity"],
            spec["repositories"],
            spec["runtime_wheels"],
        )
        save(output / "actual-runtime-source-closure.json", runtime_closure)
        save(
            output / "actual-launch-intent.json",
            {
                "argv": argv,
                "environment": env,
                "caller_kernel": process_identity(os.getpid()),
            },
        )
        wall = time.time_ns()
        with (
            (output / "child.stdout").open("xb") as stdout,
            (output / "child.stderr").open("xb") as stderr,
        ):
            process = subprocess.Popen(
                argv, cwd=output, env=env, stdout=stdout, stderr=stderr
            )
        epoch = process_identity(process.pid)
        tracked[process.pid] = epoch
        save(output / "actual-owned-Popen-kernel.json", epoch)
        if arm == "ecpa":
            manager = epoch
            handoff = accept_native_binding(
                PeerListener(listener, output, process_identity),
                sock,
                manager,
                wall,
                manager_source_digests(),
                output / "original-Manager-handoff.bin",
            )
            save(output / "authentic-Manager-handoff.json", handoff)
            launch = handoff["environment"]
            original = Path(launch[_PATH_ENV])
        else:
            launch = {k: env[k] for k in _EVIDENCE_ENVIRONMENT}
            save(
                output / "baseline-owned-context.json",
                {
                    "origin": "host-baseline",
                    "publisher": epoch,
                    "environment": launch,
                    "Manager_handoff_or_ACK_claim": False,
                },
            )
        require(
            launch["VLLM_ECPA_PLAN_ID"] == spec["ordinary_native_plan_id"],
            "actual original H4 Plan differs",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        while not stop.is_set():
            require(
                process.poll() is None, "actual Host/Manager exited during activation"
            )
            try:
                with opener.open(spec["health_url"], timeout=2) as response:
                    if response.status == 200:
                        break
            except OSError:
                pass
            stop.wait(0.2)
        require(not stop.is_set(), "activation stopped before ready")
        host = direct_child(process, process_identity) if arm == "ecpa" else epoch
        actual_argv = [
            b.decode()
            for b in Path(f"/proc/{host['pid']}/cmdline").read_bytes().split(b"\0")
            if b
        ]
        require(actual_argv == host_argv, "actual Host command differs")
        raw, original_ref = snapshot_original(
            original, output, "ready-Host-byte-snapshot.jsonl"
        )
        roster = source_owned_roster(raw, launch, host, process_identity)
        result.update(
            passed=True,
            actual_host=host,
            actual_manager=manager,
            native_launch=launch,
            actual_roster=roster,
            ready_original_journal=original_ref,
            ready_monotonic_ns=time.monotonic_ns(),
        )
        save(output / "activation-ready.json", result)
        print(
            json.dumps(
                {
                    "activation_ready": True,
                    "path": str(output / "activation-ready.json"),
                }
            ),
            flush=True,
        )
        while not stop.wait(0.2):
            require(
                process.poll() is None,
                "actual Host/Manager exited before H4 runner cleanup",
            )
            for rows in roster.values():
                for row in rows.values():
                    require(
                        process_identity(row["kernel"]["pid"]) == row["kernel"],
                        "actual Host role changed during cost measurement",
                    )
        require(not result.get("timed_out"), "H4 owner deadline exceeded")
    except BaseException:  # noqa: BLE001 -- preserve failure and always clean owned epochs
        result["passed"] = False
        result["error"] = traceback.format_exc()
    finally:
        if process is not None:
            try:
                collect()
                if host is not None:
                    raw, original_ref = snapshot_original(
                        original, output, "final-Host-byte-snapshot.jsonl"
                    )
                    # Keep original callback bytes even if a server has already
                    # failed. A failed final live check never becomes success.
                    result["final_original_journal"] = original_ref
                    if process.poll() is None:
                        result["final_live_roster"] = source_owned_roster(
                            raw, launch, host, process_identity
                        )
                save(
                    output / "actual-owned-epochs-before-cleanup.json",
                    list(tracked.values()),
                )
            except BaseException:  # noqa: BLE001 -- preserve original failure bytes
                result["passed"] = False
                result["final_snapshot_error"] = traceback.format_exc()
            kill(signal.SIGTERM)
            end = time.monotonic() + 12
            while time.monotonic() < end:
                live = []
                for k in list(tracked.values()):
                    try:
                        if process_identity(k["pid"]) == k:
                            live.append(k)
                    except (OSError, ValueError):
                        pass
                if not live:
                    break
                time.sleep(0.1)
            kill(signal.SIGKILL)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                result["passed"] = False
            remaining = []
            for k in list(tracked.values()):
                try:
                    if process_identity(k["pid"]) == k:
                        remaining.append(k)
                except (OSError, ValueError):
                    pass
            result["remaining_exact_epochs"] = remaining
            if remaining:
                result["passed"] = False
        stop.set()
        watcher.join(timeout=2)
        if listener is not None:
            listener.close()
        for sig, old in previous_handlers.items():
            signal.signal(sig, old)
        save(output / "activation-guard-receipt.json", result)
    return result


def _registered_inputs(run_dir, definition):
    argv = definition["server_command"]
    require(
        argv.count("--config")
        == argv.count("--config-sha256")
        == argv.count("--arm")
        == 1,
        "registered actual H4 wrapper argv required",
    )
    spec_path = Path(argv[argv.index("--config") + 1])
    expected = argv[argv.index("--config-sha256") + 1].removeprefix("sha256:")
    raw = spec_path.read_bytes()
    require(sha(raw) == expected, "registered H4 activation spec changed")
    spec = json.loads(raw)
    arm = argv[argv.index("--arm") + 1]
    validate_registered_commands(spec, argv)
    root = Path(run_dir) / "activation"
    require(
        (root / "spec.json").read_bytes() == raw,
        "runtime H4 source spec differs from registered bytes",
    )
    return root, spec, arm


def verify_live_activation(run_dir, definition, expected_root):
    """Fresh independent parent-side check before original H4 measurements."""
    from vllm_hust_ext.discovery import discover_bundles
    from vllm_hust_ext.runtime_phase_handoff import (
        manager_source_digests,
        process_identity,
    )
    from vllm_hust_ext.semantic_runtime_binding import installed_plugin_identities

    root, spec, arm = _registered_inputs(run_dir, definition)
    require(
        process_identity(expected_root["pid"]) == expected_root,
        "actual H4 wrapper epoch gone or reused",
    )
    argv = [
        v.decode()
        for v in Path(f"/proc/{expected_root['pid']}/cmdline").read_bytes().split(b"\0")
        if v
    ]
    require(
        argv == definition["server_command"],
        "actual H4 wrapper did not execute registered command",
    )
    require(
        json.loads((root / "actual-launch-intent.json").read_bytes())["caller_kernel"]
        == expected_root,
        "wrapper observation differs from actual external Popen",
    )
    ready = json.loads((root / "activation-ready.json").read_bytes())
    require(
        ready["schema"] == "ecpa-h4-original-lifecycle-activation-guard/v1"
        and ready["arm"] == arm
        and ready["scope"] == spec["scope"]
        and ready["passed"],
        "actual H4 loader activation not ready",
    )
    plugins, snapshots = installed_plugin_identities(discover_bundles(IDS))
    require(
        snapshots == spec["installed_bundle_snapshots"]
        and [asdict(p) for p in plugins] == spec["plugin_identities"],
        "actual H4 source artifacts changed",
    )
    require(
        compile_original_lifecycle_plan(discover_bundles(IDS))
        == spec["original_h4_lifecycle_scope"],
        "independent original H4 loader scope changed",
    )
    for ref in [*spec["source_refs"], *spec["input_artifact_refs"]]:
        checked(ref)
    host = ready["actual_host"]
    require(
        process_identity(host["pid"]) == host
        and descendant(host["pid"], expected_root["pid"]),
        "actual Host is not this current wrapper child tree",
    )
    actual_host_argv = [
        v.decode()
        for v in Path(f"/proc/{host['pid']}/cmdline").read_bytes().split(b"\0")
        if v
    ]
    require(
        actual_host_argv == spec["host_commands"][arm], "actual Host command differs"
    )
    launch = ready["native_launch"]
    original = Path(ready["ready_original_journal"]["original_path"])
    meta = original.stat()
    old = ready["ready_original_journal"]["original_identity"]
    require(
        meta.st_dev == old["device"]
        and meta.st_ino == old["inode"]
        and meta.st_uid == os.getuid()
        and not meta.st_mode & 0o077,
        "original Host journal inode/owner changed",
    )
    ready_raw = checked(ready["ready_original_journal"]["byte_exact_snapshot"])
    raw = original.read_bytes()
    require(raw.startswith(ready_raw), "original Host callback prefix changed")
    roster = source_owned_roster(raw, launch, host, process_identity)
    require(roster == ready["actual_roster"], "actual original loader roster changed")
    publisher = json.loads((root / "actual-owned-Popen-kernel.json").read_bytes())
    require(
        process_identity(publisher["pid"]) == publisher
        and descendant(publisher["pid"], expected_root["pid"]),
        "actual owned publisher changed",
    )
    if arm == "ecpa":
        handoff = json.loads((root / "authentic-Manager-handoff.json").read_bytes())
        raw_handoff = (root / "original-Manager-handoff.bin").read_bytes()
        original_record = json.loads(raw_handoff)
        peer = json.loads((root / "original-Manager-peer.json").read_bytes())
        require(
            ready["actual_manager"]
            == publisher
            == original_record["publisher"]
            == peer["kernel"]
            and peer["receiver_kernel"] == expected_root
            and peer["pid"] == publisher["pid"]
            and peer["uid"] == os.getuid()
            and handoff == {**original_record, "binding_sha256": sha(raw_handoff)}
            and original_record["manager_source_sha256"] == manager_source_digests()
            and original_record["environment"] == launch,
            "actual original Manager handoff/peer/source binding differs",
        )
        require(
            direct_child(
                type("ObservedManager", (), {"pid": publisher["pid"]})(),
                process_identity,
            )
            == host,
            "actual Manager no longer supervises this Host",
        )
    else:
        context = json.loads((root / "baseline-owned-context.json").read_bytes())
        require(
            context["origin"] == "host-baseline"
            and context["publisher"] == host == publisher
            and context["environment"] == launch
            and not context["Manager_handoff_or_ACK_claim"],
            "baseline cannot claim a Manager handoff",
        )
    return {
        "schema": "ecpa-h4-independent-live-pair-observation/v1",
        "wrapper": expected_root,
        "actual_host": host,
        "actual_manager": ready["actual_manager"],
        "roster": roster,
        "ready_receipt": reference(root / "activation-ready.json"),
        "original_journal": ready["ready_original_journal"],
        "observed_monotonic_ns": time.monotonic_ns(),
        "formal_result": False,
    }


def verify_archived_activation(
    run_dir, definition, expected_root, resource_archive=None
):
    """Recompute loader raw bytes and join independent externally sampled epochs.

    Stopped processes are never called live. No callback is relabeled, and no
    native selected-KV completion or public release is inferred.
    """
    root, spec, arm = _registered_inputs(run_dir, definition)
    require(
        resource_archive is not None,
        "independent source-owned resource epoch archive required",
    )
    resources = json.loads(Path(resource_archive).read_bytes())
    require(
        resources["root"] == expected_root and resources["samples"],
        "external H4 wrapper/kernel archive differs",
    )
    ready = json.loads((root / "activation-ready.json").read_bytes())
    final = json.loads((root / "activation-guard-receipt.json").read_bytes())
    require(
        final["passed"]
        and not final.get("timed_out")
        and final["remaining_exact_epochs"] == []
        and ready["arm"] == final["arm"] == arm
        and ready["actual_host"] == final["actual_host"]
        and ready["native_launch"] == final["native_launch"],
        "actual H4 activation failed/changed epoch/cleanup incomplete",
    )
    require(
        json.loads((root / "actual-launch-intent.json").read_bytes())["caller_kernel"]
        == expected_root,
        "archived wrapper differs from independently sampled Popen",
    )
    host = ready["actual_host"]
    required = {
        row["kernel"]["pid"]: row["kernel"]
        for rows in ready["actual_roster"].values()
        for row in rows.values()
    }
    if ready["actual_manager"] is not None:
        required[ready["actual_manager"]["pid"]] = ready["actual_manager"]
    chosen = None
    for sample in resources["samples"]:
        members = {r["pid"]: r for r in sample["members"]}
        if all(
            pid in members
            and {k: members[pid][k] for k in ("pid", "start_ticks", "session")}
            | {"boot_id": expected_root["boot_id"]}
            == kernel
            for pid, kernel in required.items()
        ):
            chosen = members
            break
    require(
        chosen is not None,
        "actual pair roles lack one coherent independent external epoch sample",
    )

    def observed_ancestor(pid, ancestor):
        seen = set()
        while pid in chosen and pid not in seen:
            if pid == ancestor:
                return True
            seen.add(pid)
            pid = chosen[pid]["ppid"]
        return False

    require(
        all(observed_ancestor(pid, expected_root["pid"]) for pid in required),
        "archived pair is outside independently observed wrapper tree",
    )
    if ready["actual_manager"] is not None:
        require(
            chosen[host["pid"]]["ppid"] == ready["actual_manager"]["pid"],
            "archived API not original Manager child",
        )
    from vllm_hust_ext.ecpa_model import PluginIdentity
    from vllm_hust_ext.plan_artifact import parse_plan_artifact

    typed = parse_plan_artifact(
        canonical(spec["original_h4_lifecycle_scope"]["execution_plan"]) + b"\n"
    )
    require(
        typed.plan.plugins
        == tuple(PluginIdentity(**p) for p in spec["plugin_identities"])
        and all(o.event == "invoked" for o in typed.plan.obligations),
        "archived original H4 scope ownership changed",
    )
    if arm == "ecpa":
        raw_handoff = (root / "original-Manager-handoff.bin").read_bytes()
        record = json.loads(raw_handoff)
        handoff = json.loads((root / "authentic-Manager-handoff.json").read_bytes())
        peer = json.loads((root / "original-Manager-peer.json").read_bytes())
        runtime_closure = json.loads(
            (root / "actual-runtime-source-closure.json").read_bytes()
        )
        payload = runtime_closure["actual_runtime"]["distributions"]["manager"][
            "payload"
        ]
        expected_sources = {
            Path(path).name: digest
            for path, digest in payload.items()
            if "/vllm_hust_ext/" in path
            and Path(path).name
            in {
                "cli.py",
                "runtime_evidence.py",
                "runtime_phase_handoff.py",
                "process_supervisor.py",
            }
        }
        require(
            len(expected_sources) == 4
            and record["manager_source_sha256"] == expected_sources,
            "archived actual Manager source differs",
        )
        require(
            handoff == {**record, "binding_sha256": sha(raw_handoff)}
            and record["publisher"] == ready["actual_manager"] == peer["kernel"]
            and peer["receiver_kernel"] == expected_root
            and peer["pid"] == ready["actual_manager"]["pid"]
            and record["environment"] == ready["native_launch"],
            "archived original Manager handoff/peer differs",
        )
    else:
        context = json.loads((root / "baseline-owned-context.json").read_bytes())
        require(
            context["origin"] == "host-baseline"
            and context["publisher"] == ready["actual_host"]
            and context["environment"] == ready["native_launch"]
            and not context["Manager_handoff_or_ACK_claim"],
            "archived baseline context differs",
        )
    ready_raw = checked(ready["ready_original_journal"]["byte_exact_snapshot"])
    final_raw = checked(final["final_original_journal"]["byte_exact_snapshot"])
    require(
        final_raw.startswith(ready_raw)
        and ready["ready_original_journal"]["original_sha256"] == sha(ready_raw)
        and final["final_original_journal"]["original_sha256"] == sha(final_raw),
        "original callback snapshot bytes changed",
    )
    for k in ("original_path",):
        require(
            ready["ready_original_journal"][k] == final["final_original_journal"][k],
            "original journal changed path",
        )
    for k in ("device", "inode", "uid", "mode"):
        require(
            ready["ready_original_journal"]["original_identity"][k]
            == final["final_original_journal"]["original_identity"][k],
            "original journal inode/owner changed",
        )
    roster = source_owned_roster(
        final_raw,
        ready["native_launch"],
        host,
        lambda pid: required[pid],
        descendant_check=observed_ancestor,
    )
    require(
        roster == ready["actual_roster"] == final["final_live_roster"],
        "archived original two-MOD loader roster differs",
    )
    refs = {p.name: reference(p) for p in root.iterdir() if p.is_file()}
    return {
        "schema": "ecpa-h4-recomputed-pair-lifecycle-activation/v1",
        "scope": spec["scope"],
        "arm": arm,
        "wrapper": expected_root,
        "actual_host": host,
        "actual_manager": ready["actual_manager"],
        "roster": roster,
        "raw_artifacts": refs,
        "independent_epoch_archive": reference(resource_archive),
        "original_journal": final["final_original_journal"],
        "native_KV_completion_claim": False,
        "public_release_claim": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--config-sha256", required=True)
    p.add_argument(
        "--arm",
        choices=("vanilla-vllm-entry-points", "manual-integration", "ecpa"),
        required=True,
    )
    p.add_argument(
        "--phase",
        choices=("discovery", "validation", "planning", "rendering", "evidence_setup"),
    )
    args = p.parse_args()
    os.umask(0o077)
    if args.phase is not None:
        return prelaunch_phase(
            args.config.resolve(), args.config_sha256, args.arm, args.phase
        )
    result = execute(args.config.resolve(), args.arm, args.config_sha256)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
