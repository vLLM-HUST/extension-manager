"""Read actual assigned NPU HBM and preserve the command's original bytes."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

DEVICES = (0, 3)


def hbm_bytes(raw):
    text = raw.decode("utf-8", errors="strict")
    values = {}
    selected = None
    for line in text.splitlines():
        heading = re.match(r"^\|\s*(\d+)\s+910B2\s*\|", line)
        if heading:
            selected = int(heading.group(1))
            continue
        if selected not in DEVICES:
            continue
        if not re.match(r"^\|\s*\d+\s*\|\s*[0-9A-Fa-f]{4}:", line):
            continue
        usage = re.search(r"(\d+)\s*/\s*(\d+)\s*\|\s*$", line)
        if usage is None or selected in values:
            raise ValueError("actual NPU HBM row missing or repeated")
        used, total = map(int, usage.groups())
        if not 0 <= used <= total or total <= 0:
            raise ValueError("actual NPU HBM row invalid")
        values[selected] = used * 1024 * 1024
        selected = None
    if set(values) != set(DEVICES):
        raise ValueError("actual assigned NPU0/3 HBM inventory incomplete")
    return sum(values.values())


def decode_observation(value):
    raw = base64.b64decode(value["stdout_base64"], validate=True)
    err = base64.b64decode(value["stderr_base64"], validate=True)
    if (
        value["argv"] != ["/usr/local/sbin/npu-smi", "info"]
        or value["exit"] != 0
        or value["stdout_sha256"] != hashlib.sha256(raw).hexdigest()
        or value["stderr_sha256"] != hashlib.sha256(err).hexdigest()
        or value["physical_devices"] != list(DEVICES)
    ):
        raise ValueError("original NPU read command/body changed")
    return raw, err


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("operation", choices=("memory", "cleanup"))
    a = p.parse_args()
    argv = ["/usr/local/sbin/npu-smi", "info"]
    result = subprocess.run(argv, capture_output=True, check=False, timeout=20)
    value = {
        "schema": "ecpa-h4-original-npu-read/v1",
        "argv": argv,
        "exit": result.returncode,
        "physical_devices": list(DEVICES),
        "observed_wall_ns": time.time_ns(),
        "observed_monotonic_raw_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW),
        "stdout_base64": base64.b64encode(result.stdout).decode(),
        "stderr_base64": base64.b64encode(result.stderr).decode(),
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
    }
    if a.operation == "memory":
        print(json.dumps(value, sort_keys=True), file=sys.stderr)
        if result.returncode:
            return 1
        print(hbm_bytes(result.stdout))
        return 0
    run = Path(os.environ["ECPA_H4_RUN_DIRECTORY"])
    if not run.is_absolute() or run.resolve() != run or not run.is_dir():
        raise ValueError("actual H4 run directory required")
    for name, raw in [
        ("terminal-npu-smi.stdout", result.stdout),
        ("terminal-npu-smi.stderr", result.stderr),
        ("terminal-npu-smi.json", json.dumps(value, sort_keys=True).encode()),
    ]:
        fd = os.open(
            run / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
    empty = result.returncode == 0 and all(
        f"No running processes found in NPU {d}".encode() in result.stdout
        for d in DEVICES
    )
    print(json.dumps({"devices_reclaimed": empty, "original_command": value}))
    return 0 if empty else 1


if __name__ == "__main__":
    raise SystemExit(main())
