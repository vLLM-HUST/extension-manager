"""Strict immutable inputs shared by the new original conditional H4 domain."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

IDS = {"org.vllm-hust.pipeline-microbatch", "org.vllm-hust.bidkv"}
ARMS = ("vanilla-vllm-entry-points", "manual-integration", "ecpa")
CELLS = {
    "conditional-resource-pair.lifecycle-only",
    "conditional-resource-pair.sampled-invocation",
}
DOMAIN = "ecpa-h4-conditional-source-owned/v1"


def require(value, why):
    if not value:
        raise ValueError(why)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(ref):
    require(set(ref) == {"path", "sha256"}, "exact immutable reference required")
    path = Path(ref["path"])
    require(
        path.is_absolute() and path.resolve() == path and not path.is_symlink(),
        "canonical immutable artifact",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode), "immutable artifact is not a regular file"
        )
        raw = stream.read()
        after = os.fstat(stream.fileno())
        named = path.lstat()

    def state(v):
        return (
            v.st_dev,
            v.st_ino,
            v.st_mode,
            v.st_size,
            v.st_mtime_ns,
            v.st_ctime_ns,
        )

    require(
        state(before) == state(after) == state(named),
        "immutable artifact changed across actual read",
    )
    require(
        sha(raw) == ref["sha256"].removeprefix("sha256:"), "immutable input changed"
    )
    return raw


def load(ref):
    return json.loads(checked(ref))


def reference(path):
    path = Path(path)
    return dict(path=str(path.resolve()), sha256=sha(path.read_bytes()))


def write(path, value):
    path = Path(path)
    raw = value if isinstance(value, bytes) else canonical(value) + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return reference(path)


def private_directory(path):
    path = Path(path)
    require(
        path.is_absolute() and path.resolve() == path, "canonical private directory"
    )
    path.mkdir(mode=0o700, exist_ok=False)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        initial = os.fstat(fd)
        os.fchmod(fd, 0o700)
        final = os.fstat(fd)
        named = path.lstat()
        require(
            initial.st_uid == os.geteuid()
            and stat.S_ISDIR(final.st_mode)
            and stat.S_IMODE(final.st_mode) == 0o700
            and (initial.st_dev, initial.st_ino)
            == (final.st_dev, final.st_ino)
            == (named.st_dev, named.st_ino),
            "new owned directory identity/mode changed",
        )
    finally:
        os.close(fd)
    return path


def protocol_sources(sdk):
    sdk = Path(sdk)
    names = (
        "conditional_common.py",
        "conditional_plan.py",
        "conditional_preflight.py",
        "conditional_oracle.py",
        "conditional_selection_authority.py",
        "absolute_http.py",
        "qualify_conditional.py",
        "h4_conditional_provider_qualification.py",
        "conditional_qualification.py",
        "conditional_registration.py",
        "conditional_activation.py",
        "conditional_runtime.py",
        "conditional_root_observer.py",
        "conditional_intake.py",
        "conditional_record_bridge.py",
        "conditional_queue.py",
        "conditional_prepare.py",
        "conditional_binding.py",
        "conditional_request_trace.py",
        "conditional_input_audit.py",
        "conditional_entry.py",
        "h4_owned_resources.py",
        "h4_sampled_health.py",
        "h4_sampled_calibration.py",
        "h4_npu_observation.py",
        "h3_runtime_source_closure.py",
        "source_provenance.py",
        "h4_registration.py",
        "run_h4.py",
        "analyze.py",
        "h4_sampled_record_bridge.py",
        "h4_sampled_intake.py",
        "run_h4_sampled.py",
        "h3_worker_relaunch.py",
    )
    paths = [sdk / "experiments/formal_campaign" / name for name in names]
    paths += [
        sdk / "src/vllm_hust_ext" / name for name in ("cli.py", "runtime_evidence.py")
    ]
    paths += [
        sdk / "experiments/formal_campaign" / name
        for name in (
            "record.schema.json",
            "protocol.json",
            "conditional-actual-inputs.schema.json",
        )
    ]
    return {str(path.relative_to(sdk)): reference(path) for path in paths}


def mode(cell):
    require(cell in CELLS, "one original conditional cell required")
    return (
        "sampled-invocation"
        if cell.endswith(".sampled-invocation")
        else "lifecycle-only"
    )
