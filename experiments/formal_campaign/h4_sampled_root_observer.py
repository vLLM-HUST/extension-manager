"""Independent root observer for one original registered sampled H4 start.

Source-only candidate. Launches the exact registered one-start command when
explicitly executed by root; no signals, retries, model inspection or cleanup.
A terminal marker alone never releases: every retained actual epoch must be gone
and original ports and NPU0/3 must be independently observed empty afterwards.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import subprocess
import time
from pathlib import Path


def require(value, reason):
    if not value:
        raise ValueError(reason)


def read(path):
    return json.loads(Path(path).read_bytes())


def kernel(pid):
    f = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return dict(
        pid=pid,
        ppid=int(f[1]),
        state=f[0],
        session=int(f[3]),
        start_ticks=int(f[19]),
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    )


def table():
    rows = {}
    for p in Path("/proc").iterdir():
        if p.name.isdecimal():
            try:
                row = kernel(int(p.name))
                if row["state"] != "Z":
                    rows[row["pid"]] = row
            except (OSError, ValueError, IndexError):
                pass
    return rows


def same_epoch(a, b):
    return all(
        type(a.get(k)) is type(b[k]) and a[k] == b[k]
        for k in ("pid", "start_ticks", "session", "boot_id")
    )


def save(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(json.dumps(value, sort_keys=True).encode() + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def runner_terminal(returncode, owner, popen_reference, observed_monotonic_ns):
    """Source-owned actual Popen.poll result; no guessed raw waitstatus."""
    require(type(returncode) is int, "actual runner returncode must be integer")
    return dict(
        schema="ecpa-h4-independent-runner-terminal/v1",
        kernel={k: owner[k] for k in ("pid", "start_ticks", "session", "boot_id")},
        returncode=returncode,
        kind="signal" if returncode < 0 else "exit",
        signal=-returncode if returncode < 0 else None,
        popen=popen_reference,
        observed_monotonic_ns=observed_monotonic_ns,
        wait_api="subprocess.Popen.poll",
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("campaign", "launch-spec", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--start-id", required=True)
    p.add_argument("--deployment-receipt", type=Path)
    p.add_argument("--unregistered-calibration", action="store_true")
    p.add_argument("--source-repositories", type=Path)
    p.add_argument("--python", type=Path, required=True)
    p.add_argument("--sdk", type=Path, required=True)
    p.add_argument(
        "--environment",
        type=Path,
        required=True,
        help="Exact frozen commands.environment JSON",
    )
    a = p.parse_args()
    require(os.geteuid() == 0, "root-only actual observation")
    os.umask(0o077)
    a.output.mkdir(mode=0o700, exist_ok=False)
    campaign = read(a.campaign)
    native_ref = campaign["sampled_native_inputs"]
    raw = Path(native_ref["path"]).read_bytes()
    require(
        hashlib.sha256(raw).hexdigest() == native_ref["sha256"].removeprefix("sha256:"),
        "registered native input changed",
    )
    native = json.loads(raw)
    starts = [s for s in native["starts"] if s["start_id"] == a.start_id]
    require(len(starts) == 1, "one original registered slot required")
    start = starts[0]
    run = Path(start["run_directory"])
    require(not run.exists(), "original start output already exists")
    phase = read(start["phase"]["path"])
    require(
        a.python == Path(phase["argv"][0]) and a.sdk == Path(phase["cwd"]),
        "actual interpreter/SDK differs",
    )
    env = read(a.environment)
    if a.unregistered_calibration:
        require(
            a.deployment_receipt is None and a.source_repositories is not None,
            "unregistered qualifier cannot consume a deployment receipt",
        )
        argv = [
            str(a.python),
            "-m",
            "experiments.formal_campaign.h4_sampled_calibration",
            "--produce",
            "--campaign",
            str(a.campaign),
            "--launch-spec",
            str(a.launch_spec),
            "--source-repositories",
            str(a.source_repositories),
            "--start-id",
            a.start_id,
            "--output",
            str(a.output / "calibration-artifacts"),
        ]
    else:
        require(
            a.deployment_receipt is not None, "registered start requires real receipt"
        )
        argv = [
            str(a.python),
            "-m",
            "experiments.formal_campaign.run_h4_sampled",
            "--campaign",
            str(a.campaign),
            "--launch-spec",
            str(a.launch_spec),
            "--deployment-receipt",
            str(a.deployment_receipt),
            "--start-id",
            a.start_id,
        ]
    result = dict(
        schema="ecpa-h4-sampled-independent-root-terminal/v1",
        run_directory=str(run),
        released=False,
        formal_result=False,
        qualification_or_hypothesis_claim=False,
        execution_domain="unregistered-calibration"
        if a.unregistered_calibration
        else "registered-original-start",
    )
    seen = {}
    sessions = set()
    try:
        with (
            (a.output / "runner.stdout").open("xb") as out,
            (a.output / "runner.stderr").open("xb") as err,
        ):
            process = subprocess.Popen(
                argv, cwd=a.sdk, env=env, stdout=out, stderr=err, start_new_session=True
            )
        owner = kernel(process.pid)
        seen[(owner["pid"], owner["start_ticks"])] = owner
        sessions.add(owner["session"])
        save(
            a.output / "actual-runner-Popen.json",
            dict(argv=argv, kernel=owner, observed_monotonic_ns=time.monotonic_ns()),
        )
        with (a.output / "live-observations.jsonl").open("xb") as log:
            while True:
                rows = table()
                live = {
                    p
                    for (p, t), e in seen.items()
                    if p in rows and same_epoch(rows[p], e)
                }
                while True:
                    more = {
                        pid
                        for pid, row in rows.items()
                        if row["ppid"] in live or row["session"] in sessions
                    } - live
                    if not more:
                        break
                    live.update(more)
                for pid in live:
                    e = rows[pid]
                    seen[(pid, e["start_ticks"])] = e
                    if e["pid"] == e["session"]:
                        sessions.add(e["session"])
                log.write(
                    json.dumps(
                        dict(
                            observed_monotonic_ns=time.monotonic_ns(),
                            members=[rows[p] for p in sorted(live)],
                        )
                    ).encode()
                    + b"\n"
                )
                log.flush()
                rc = process.poll()
                if rc is not None and not live:
                    break
                time.sleep(0.25)
        result["runner_exit_code"] = rc
        popen_path = a.output / "actual-runner-Popen.json"
        result["runner_terminal"] = runner_terminal(
            rc,
            owner,
            dict(
                path=str(popen_path),
                sha256=hashlib.sha256(popen_path.read_bytes()).hexdigest(),
            ),
            time.monotonic_ns(),
        )

        # Exit status is an observed outcome, never a substitute for cleanup.
        admission = read(run / "source-admission.json")
        timing = read(run / "phase0.product-popen-timing.json")
        require(
            admission["owner"] == timing["actual_kernel"],
            "actual product admission differs",
        )
        result["product_root"] = admission["owner"]
        epoch_path = run / "sampled-epoch-archive.json"
        epoch = read(epoch_path) if epoch_path.exists() else None
        expected_epochs = (
            admission["owner"],
            *(epoch["kernels"].values() if epoch is not None else ()),
        )
        for e in expected_epochs:
            require(
                any(same_epoch(e, x) for x in seen.values()),
                "actual role not independently observed; no retrospective promotion",
            )
        now = table()
        remaining = [
            e for e in seen.values() if e["pid"] in now and same_epoch(now[e["pid"]], e)
        ]
        result["all_observed_epochs"] = list(seen.values())
        result["remaining_observed_epochs"] = remaining
        require(not remaining, "actual observed epoch still live")
        ports = {}
        for port in native["allocated_tcp_ports"]:
            with socket.socket() as sock:
                sock.settimeout(0.25)
                ports[str(port)] = sock.connect_ex(("127.0.0.1", port)) == 0
        result["open_ports"] = ports
        require(not any(ports.values()), "actual original port remains open")
        command = ["/usr/local/sbin/npu-smi", "info"]
        smi = subprocess.run(command, capture_output=True, timeout=20)
        observation = dict(
            schema="ecpa-h4-original-npu-read/v1",
            argv=command,
            exit=smi.returncode,
            physical_devices=[0, 3],
            observed_wall_ns=time.time_ns(),
            observed_monotonic_raw_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW),
            stdout_base64=base64.b64encode(smi.stdout).decode(),
            stderr_base64=base64.b64encode(smi.stderr).decode(),
            stdout_sha256=hashlib.sha256(smi.stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(smi.stderr).hexdigest(),
        )
        path = a.output / "terminal-npu-original.json"
        save(path, observation)
        result["terminal_npu_observation"] = dict(
            path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest()
        )
        require(
            smi.returncode == 0
            and all(
                f"No running processes found in NPU {d}".encode() in smi.stdout
                for d in (0, 3)
            ),
            "actual NPU process table not explicitly empty",
        )
        require(
            not any(
                e["pid"] in table() and same_epoch(table()[e["pid"]], e)
                for e in seen.values()
            ),
            "retained epoch reappeared",
        )
        # Pin exact terminal files actually observed after this runner exited.
        # Omitted files stay omitted; no fabricated trace, stop, or completion.
        paths = [
            run / name
            for name in (
                "source-admission.json",
                "phase0.product-popen-timing.json",
                "actual-runtime-closure.json",
                "sampled-source-result.json",
                "sampled-epoch-archive.json",
                "request-results.jsonl",
                "all272-request-results.json",
                "owned-resources.json",
                "health-probes.jsonl",
                "health-probe-terminal.json",
            )
        ]
        result["terminal_artifacts"] = {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths
            if path.exists() and path.is_file() and not path.is_symlink()
        }
        result["released"] = True
        return 0
    except Exception as exc:
        result["error"] = repr(exc)
        return 2
    finally:
        result.setdefault("all_observed_epochs", list(seen.values()))
        save(a.output / "independent-root-terminal.json", result)


if __name__ == "__main__":
    raise SystemExit(main())
