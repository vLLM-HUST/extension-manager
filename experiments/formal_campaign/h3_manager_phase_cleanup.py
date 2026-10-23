"""Independent exact-start cleanup evidence; no service signaling or digest waiver."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import time
from pathlib import Path

from experiments.formal_campaign.h3_dynamic_authority import canonical, require
from experiments.formal_campaign.h3_owned_worker_carrier import checked_reference
from experiments.formal_campaign.h3_worker_relaunch import identity

SCHEMA = "ecpa-h3-manager-phase-independent-cleanup/v1"
KERNEL_FIELDS = {"pid", "start_ticks", "session", "boot_id"}


def _sha(path):
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def context_for(spec_path, receipt_path, spec, start):
    return {
        "start_id": start["start_id"],
        "campaign_sha256": _sha(spec_path),
        "receipt_sha256": _sha(receipt_path),
        "original_campaign": spec["original_campaign"],
        "policy": start["policy"],
        "recipe_template": start["recipe_template"],
        "external_references": spec["manager_cleanup"]["external_services"],
    }


def ordered_kernels(kernels):
    unique = {canonical(k): k for k in kernels}
    require(
        all(set(k) == KERNEL_FIELDS for k in unique.values()),
        "exact full kernel identities required",
    )
    return [unique[key] for key in sorted(unique)]


def required_epochs(epochs):
    require(
        set(epochs)
        == {"authority", "manager_initial", "host_initial", "client", "replacement"}
        and type(epochs["replacement"]) is list,
        "actual Manager phase role epochs required",
    )
    result = [
        epochs[k] for k in ("authority", "manager_initial", "host_initial", "client")
    ] + epochs["replacement"]
    require(
        all(type(k) is dict and set(k) == KERNEL_FIELDS for k in result),
        "Manager cleanup cannot guess or omit actual full epochs",
    )
    require(
        len({canonical(k) for k in result}) == len(result), "Manager phase epochs alias"
    )
    return result


def external_epochs(policy):
    result = []
    for service in policy["external_services"]:
        ref = service["identity_reference"]
        expected = json.loads(checked_reference(ref).read_bytes())
        actual = identity(expected["pid"])
        require(actual == expected, "externally owned service epoch differs")
        result.append(
            {"name": service["name"], "kernel": actual, "identity_reference": ref}
        )
    return result


def _listeners(tables, ports):
    found = []
    for name, encoded in tables.items():
        require(name in {"tcp", "tcp6"}, "unexpected TCP table")
        for line in base64.b64decode(encoded, validate=True).decode().splitlines()[1:]:
            fields = line.split()
            if fields[3] == "0A" and int(fields[1].rsplit(":", 1)[1], 16) in ports:
                found.append(
                    {
                        "table": name,
                        "raw": line,
                        "port": int(fields[1].rsplit(":", 1)[1], 16),
                        "inode": int(fields[9]),
                    }
                )
    require(set(tables) == {"tcp", "tcp6"}, "complete independent TCP tables required")
    return found


def _sample(kernel):
    try:
        raw = Path(f"/proc/{kernel['pid']}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError):
        raw = None
    return {"expected": kernel, "stat_raw": raw, "observed_ns": time.monotonic_ns()}


def _survives(sample, boot):
    raw = sample["stat_raw"]
    if raw is None:
        return False
    end = raw.rfind(")")
    fields = raw[end + 2 :].split()
    actual = {
        "pid": int(raw[: raw.index("(")].strip()),
        "start_ticks": int(fields[19]),
        "session": int(fields[3]),
        "boot_id": boot,
    }
    return actual == sample["expected"] and fields[0] != "Z"


def observe(
    policy, ports, *, context, stage, owned=(), run_epochs=None, external_before=None
):
    require(
        policy["allocated_devices"] == [0, 3]
        and policy["npu_command"] == ["/usr/local/sbin/npu-smi", "info"],
        "only original allocated NPU read command supported",
    )
    require(
        stage in {"before-product", "after-cleanup"},
        "explicit cleanup lifecycle stage required",
    )
    owned = ordered_kernels(owned)
    samples = [_sample(kernel) for kernel in owned]
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    tables = {
        name: base64.b64encode(Path("/proc/net/" + name).read_bytes()).decode()
        for name in ("tcp", "tcp6")
    }
    result = subprocess.run(
        policy["npu_command"], capture_output=True, timeout=20, check=False
    )
    external = external_epochs(policy)
    if external_before is not None:
        require(
            external == external_before, "external service changed during owned cleanup"
        )
    require(
        not any(e["kernel"] == k for e in external for k in owned),
        "externally owned service is in cleanup ownership set",
    )
    return {
        "schema": SCHEMA,
        "context": context,
        "stage": stage,
        "run_epochs": run_epochs,
        "observed_ns": time.monotonic_ns(),
        "boot_id": boot,
        "owned_kernels": owned,
        "process_samples": samples,
        "owned_survivors": [s["expected"] for s in samples if _survives(s, boot)],
        "external_services": external,
        "tcp_tables": tables,
        "listeners": _listeners(tables, ports),
        "ports": sorted(set(ports)),
        "devices": policy["allocated_devices"],
        "npu_argv": policy["npu_command"],
        "npu_exit": result.returncode,
        "npu_stdout_base64": base64.b64encode(result.stdout).decode(),
        "npu_stderr_base64": base64.b64encode(result.stderr).decode(),
        "npu_stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
    }


def verify(before, after, policy, *, context, run_epochs, owned_kernels, ports, clocks):
    """No default run binding; another clean run's witnesses cannot substitute."""
    expected_owned = ordered_kernels(owned_kernels)
    mandatory = required_epochs(run_epochs)
    require(
        all(k in expected_owned for k in mandatory),
        "complete actual role epochs absent from cleanup ownership",
    )
    require(
        before["boot_id"] == after["boot_id"] == mandatory[0]["boot_id"]
        and all(k["boot_id"] == after["boot_id"] for k in expected_owned),
        "cleanup witness kernel boot differs from actual run epochs",
    )
    expected_ports = sorted(set(ports))
    require(len(expected_ports) == 2, "exact registered public/backend ports required")
    require(
        before["schema"] == after["schema"] == SCHEMA
        and before["context"] == after["context"] == context
        and before["stage"] == "before-product"
        and after["stage"] == "after-cleanup",
        "cleanup witnesses belong to another start/campaign/receipt or lifecycle",
    )
    require(
        after["run_epochs"] == run_epochs and before["run_epochs"] is None,
        "cleanup witnesses belong to another actual run epoch",
    )
    require(
        after["owned_kernels"] == expected_owned
        and before["owned_kernels"] == []
        and before["ports"] == after["ports"] == expected_ports,
        "cleanup omitted/substituted full owned kernels or registered ports",
    )
    require(
        before["observed_ns"]
        < clocks["launch_ns"]
        <= clocks["fault_ns"]
        < clocks["dead_ns"]
        <= clocks["terminal_ns"]
        <= clocks["cleanup_started_ns"]
        <= after["observed_ns"]
        <= clocks["recorded_ns"],
        "cleanup witness clocks differ from original start/fault/independent terminal",
    )
    if clocks["terminal_kind"] == "complete-client-window":
        require(
            clocks["client_stop_ns"] is not None
            and clocks["launch_ns"]
            <= clocks["client_stop_ns"]
            <= clocks["terminal_ns"],
            "complete Manager cleanup lacks exact original client.stop join",
        )
    else:
        require(
            clocks["terminal_kind"] == "independent-runner-failed-start"
            and clocks["client_stop_ns"] is None,
            "partial cleanup cannot fabricate a client.stop or recovery clock",
        )
    for witness in (before, after):
        raw = base64.b64decode(witness["npu_stdout_base64"], validate=True)
        require(
            witness["npu_argv"] == policy["npu_command"]
            and witness["devices"] == policy["allocated_devices"]
            and hashlib.sha256(raw).hexdigest() == witness["npu_stdout_sha256"],
            "independent allocated NPU command/body differs",
        )
        require(
            witness["listeners"] == _listeners(witness["tcp_tables"], expected_ports),
            "listener summary differs from independent raw TCP tables",
        )
    require(
        context["external_references"] == policy["external_services"]
        and before["external_services"] == after["external_services"],
        "external epoch/reference inventory differs",
    )
    expected_external = [
        {"name": s["name"], "identity_reference": s["identity_reference"]}
        for s in policy["external_services"]
    ]
    require(
        [
            {"name": s["name"], "identity_reference": s["identity_reference"]}
            for s in before["external_services"]
        ]
        == expected_external,
        "cleanup external references differ from frozen inventory",
    )
    for service, recorded in zip(
        policy["external_services"], after["external_services"], strict=True
    ):
        original = json.loads(
            checked_reference(service["identity_reference"]).read_bytes()
        )
        require(
            type(original) is dict
            and set(original) == KERNEL_FIELDS
            and recorded["kernel"] == original,
            (
                "historical external epoch differs from SHA-checked "
                "original identity bytes"
            ),
        )
    require(
        not any(
            s["kernel"] == k for s in after["external_services"] for k in expected_owned
        ),
        "external epoch included in owned cleanup set",
    )
    samples = after["process_samples"]
    require(
        [s["expected"] for s in samples] == expected_owned
        and all(
            clocks["terminal_ns"] <= s["observed_ns"] <= after["observed_ns"]
            for s in samples
        ),
        "process-stat witness omitted/substituted exact owned epochs or clocks",
    )
    survivors = [s["expected"] for s in samples if _survives(s, after["boot_id"])]
    require(
        after["owned_survivors"] == survivors,
        "survivor summary differs from original process-stat samples",
    )
    raw = base64.b64decode(after["npu_stdout_base64"], validate=True)
    return {
        "processes_reclaimed": not survivors,
        "ports_reclaimed": not after["listeners"],
        "devices_reclaimed": after["npu_exit"] == 0
        and all(
            f"No running processes found in NPU {d}".encode() in raw for d in (0, 3)
        ),
        "external_services_preserved": True,
    }
