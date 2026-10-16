"""Source-owned H4 resource sampling over real descendants, including new sessions.

Only /proc and an explicitly registered device read command are observed. No
process is signalled. CPU/RSS definitions and the original 250 ms sample period
are unchanged; a different process group never excludes a real descendant.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
import time
from pathlib import Path


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def read_process(pid, *, proc=Path("/proc")):
    raw = (proc / str(pid) / "stat").read_text()
    fields = raw.rsplit(") ", 1)[1].split()
    rss = 0
    rss_line = None
    for line in (proc / str(pid) / "status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            rss = int(line.split()[1]) * 1024
            rss_line = line
    return {
        "stat_raw": raw,
        "rss_line": rss_line,
        "pid": pid,
        "ppid": int(fields[1]),
        "start_ticks": int(fields[19]),
        "session": int(fields[3]),
        "pgid": int(fields[2]),
        "state": fields[0],
        "own_ticks": int(fields[11]) + int(fields[12]),
        "reaped_child_ticks": int(fields[13]) + int(fields[14]),
        "rss_bytes": rss,
    }


def kernel(row, boot_id):
    return {k: row[k] for k in ("pid", "start_ticks", "session")} | {"boot_id": boot_id}


def collect_tree(expected, *, proc=Path("/proc")):
    """Require a second actual kernel/PPID observation for every ancestry edge."""
    boot = (proc / "sys/kernel/random/boot_id").read_text().strip()
    if boot != expected["boot_id"]:
        raise ValueError("resource observer kernel boot changed")
    rows = {}
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            row = read_process(int(entry.name), proc=proc)
        except (OSError, ValueError, IndexError):
            continue
        rows[row["pid"]] = row
    root = rows.get(expected["pid"])
    if root is None or kernel(root, boot) != expected or root["state"] == "Z":
        raise ValueError("actual resource root epoch is absent or reused")
    owned = {root["pid"]: root}
    while True:
        additions = {
            pid: row
            for pid, row in rows.items()
            if pid not in owned and row["ppid"] in owned
        }
        if not additions:
            break
        owned.update(additions)
    for pid, old in owned.items():
        current = read_process(pid, proc=proc)
        if (
            kernel(current, boot) != kernel(old, boot)
            or current["ppid"] != old["ppid"]
            or current["reaped_child_ticks"] != old["reaped_child_ticks"]
        ):
            # Reaping between the two observations could double-count the old
            # child's CPU and the parent's new cutime. Retry a coherent sample.
            raise ValueError(
                "resource ancestry or child accounting changed during sample"
            )
    return {
        "observed_monotonic_raw_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW),
        "root": expected,
        "members": [owned[pid] for pid in sorted(owned)],
        "cpu_ticks": sum(
            r["own_ticks"] + r["reaped_child_ticks"] for r in owned.values()
        ),
        "rss_bytes": sum(r["rss_bytes"] for r in owned.values() if r["state"] != "Z"),
    }


class OwnedTreeResourceSampler:
    def __init__(
        self,
        pid,
        npu_command,
        *,
        archive,
        interval_s=0.25,
        proc=Path("/proc"),
        expected_root=None,
    ):
        if interval_s != 0.25:
            raise ValueError("original H4 resource sampling period changed")
        self.proc = proc
        boot = (proc / "sys/kernel/random/boot_id").read_text().strip()
        self.root = kernel(read_process(pid, proc=proc), boot)
        if expected_root is not None and self.root != expected_root:
            raise ValueError("Popen resource root epoch differs")
        self.archive = Path(archive)
        if self.archive.exists():
            raise FileExistsError("resource archive must be fresh")
        self.archive.parent.mkdir(parents=True, exist_ok=True)
        self.command = list(npu_command) if npu_command else None
        self.source_ref = {
            "path": str(Path(__file__).resolve()),
            "sha256": digest(Path(__file__).read_bytes()),
        }
        self.interval_s = interval_s
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._sample, daemon=True)
        self.samples, self.errors = [], []
        self._known = {}
        self.finished = None
        try:
            self._append_sample()
        except (OSError, ValueError, IndexError, subprocess.SubprocessError) as exc:
            self.errors.append({"monotonic_ns": time.monotonic_ns(), "error": str(exc)})
            if not self.samples:
                raise
        self.cpu_start = self.samples[0]["cpu_ticks"]
        self.ticks_per_second = os.sysconf("SC_CLK_TCK")

    def _append_sample(self):
        last = None
        for _ in range(5):
            try:
                sample = collect_tree(self.root, proc=self.proc)
                break
            except (OSError, ValueError, IndexError) as exc:
                last = str(exc)
        else:
            raise ValueError(last)
        members = {r["pid"]: r for r in sample["members"]}
        for pid, expected in self._known.items():
            if pid in members:
                continue
            try:
                actual = read_process(pid, proc=self.proc)
            except (OSError, ValueError, IndexError):
                continue
            if kernel(actual, self.root["boot_id"]) == expected:
                raise ValueError("previously owned live process escaped ancestry")
        self._known.update(
            {pid: kernel(row, self.root["boot_id"]) for pid, row in members.items()}
        )
        if digest(Path(__file__).read_bytes()) != self.source_ref["sha256"]:
            raise ValueError("resource observer source changed during measurement")
        sample["device_memory_bytes"] = None
        sample["device_observation"] = None
        self.samples.append(sample)
        if self.command:
            result = subprocess.run(
                self.command, capture_output=True, text=True, check=False, timeout=5
            )
            sample["device_observation"] = {
                "argv": self.command,
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
            if result.returncode:
                raise ValueError("registered device memory read command failed")
            text = result.stdout.strip()
            if not text.isdecimal():
                raise ValueError(
                    "device memory read must return nonnegative integer bytes"
                )
            sample["device_memory_bytes"] = int(text)
            sample["device_observation"] = {
                "argv": self.command,
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

    def _sample(self):
        while not self.stop_event.wait(self.interval_s):
            try:
                self._append_sample()
            except (OSError, ValueError, IndexError, subprocess.SubprocessError) as exc:
                self.errors.append(
                    {"monotonic_ns": time.monotonic_ns(), "error": str(exc)}
                )

    def start(self):
        self.thread.start()

    def finish(self):
        if self.finished is not None:
            return self.finished
        self.stop_event.set()
        if self.thread.ident is not None:
            self.thread.join()
        try:
            self._append_sample()
        except (OSError, ValueError, IndexError, subprocess.SubprocessError) as exc:
            self.errors.append({"monotonic_ns": time.monotonic_ns(), "error": str(exc)})
        resources = {
            "cpu_ms": max(0, max(s["cpu_ticks"] for s in self.samples) - self.cpu_start)
            * 1000
            / self.ticks_per_second,
            "peak_host_rss_bytes": max(s["rss_bytes"] for s in self.samples),
            "peak_device_memory_bytes": max(
                (
                    s["device_memory_bytes"]
                    for s in self.samples
                    if s["device_memory_bytes"] is not None
                ),
                default=0,
            ),
        }
        value = {
            "schema": "ecpa-h4-owned-tree-resource-samples/v1",
            "root": self.root,
            "source": self.source_ref,
            "interval_s": self.interval_s,
            "clock_ticks_per_second": self.ticks_per_second,
            "device_command": self.command,
            "samples": self.samples,
            "errors": self.errors,
            "coverage": "complete" if not self.errors else "incomplete",
            "device_coverage": "observed"
            if self.command
            and all(s["device_memory_bytes"] is not None for s in self.samples)
            else "not-observed",
            "resources": resources,
        }
        self.archive.write_bytes(canonical(value) + b"\n")
        self.finished = resources
        return resources

    @property
    def last_known_epochs(self):
        return tuple(dict(value) for value in self._known.values())

    def require_coverage(self):
        if self.errors:
            raise ValueError("source-owned resource sample coverage incomplete")


def verify_archive(path, expected_root, resources):
    """Recompute original resource metrics from independently bound raw samples."""
    value = json.loads(Path(path).read_bytes())
    if (
        value["schema"] != "ecpa-h4-owned-tree-resource-samples/v1"
        or value["root"] != expected_root
        or value["interval_s"] != 0.25
        or value["coverage"] != "complete"
        or value["errors"]
    ):
        raise ValueError("resource archive epoch or coverage differs")
    if value["source"]["sha256"] != digest(Path(value["source"]["path"]).read_bytes()):
        raise ValueError("resource sampler source drifted")
    samples = value["samples"]
    if len(samples) < 2:
        raise ValueError("resource archive lacks initial and final observations")
    previous = 0
    for sample in samples:
        members = {r["pid"]: r for r in sample["members"]}
        root = members.get(expected_root["pid"])
        if (
            root is None
            or kernel(root, expected_root["boot_id"]) != expected_root
            or sample["root"] != expected_root
            or sample["observed_monotonic_raw_ns"] <= previous
        ):
            raise ValueError("resource sample root or clock changed")
        previous = sample["observed_monotonic_raw_ns"]
        observation = sample["device_observation"]
        if value["device_command"] is None:
            if observation is not None or sample["device_memory_bytes"] is not None:
                raise ValueError("device memory lacks registered source read")
        else:
            if (
                observation is None
                or observation["argv"] != value["device_command"]
                or observation["exit_code"] != 0
                or not observation["stdout"].strip().isdecimal()
                or int(observation["stdout"].strip()) != sample["device_memory_bytes"]
            ):
                raise ValueError("device metric differs from original source read")
            from experiments.formal_campaign.h4_npu_observation import (
                decode_observation,
                hbm_bytes,
            )

            smi_stdout, _ = decode_observation(json.loads(observation["stderr"]))
            if hbm_bytes(smi_stdout) != sample["device_memory_bytes"]:
                raise ValueError("device metric differs from raw actual NPU report")
        if len(members) != len(sample["members"]):
            raise ValueError("resource process duplicate within sample")
        for pid, row in members.items():
            fields = row["stat_raw"].rsplit(") ", 1)[1].split()
            decoded = {
                "pid": int(row["stat_raw"].split(" ", 1)[0]),
                "ppid": int(fields[1]),
                "state": fields[0],
                "pgid": int(fields[2]),
                "session": int(fields[3]),
                "start_ticks": int(fields[19]),
                "own_ticks": int(fields[11]) + int(fields[12]),
                "reaped_child_ticks": int(fields[13]) + int(fields[14]),
                "rss_bytes": int(row["rss_line"].split()[1]) * 1024
                if row["rss_line"] is not None
                else 0,
            }
            if any(row[k] != v for k, v in decoded.items()):
                raise ValueError("resource counters differ from original proc bytes")
            seen = set()
            while pid != expected_root["pid"]:
                if pid in seen or pid not in members:
                    raise ValueError("resource member lacks this root ancestry")
                seen.add(pid)
                pid = members[pid]["ppid"]
            if row["start_ticks"] < root["start_ticks"]:
                raise ValueError("resource member predates owned root")
        if sample["cpu_ticks"] != sum(
            r["own_ticks"] + r["reaped_child_ticks"] for r in members.values()
        ) or sample["rss_bytes"] != sum(
            r["rss_bytes"] for r in members.values() if r["state"] != "Z"
        ):
            raise ValueError("resource sample totals differ from member raw counters")
    measured = {
        "cpu_ms": max(0, max(s["cpu_ticks"] for s in samples) - samples[0]["cpu_ticks"])
        * 1000
        / value["clock_ticks_per_second"],
        "peak_host_rss_bytes": max(s["rss_bytes"] for s in samples),
        "peak_device_memory_bytes": max(
            (
                s["device_memory_bytes"]
                for s in samples
                if s["device_memory_bytes"] is not None
            ),
            default=0,
        ),
    }
    if measured != value["resources"] or measured != resources:
        raise ValueError("resource metrics differ from raw owned tree")
    return value
