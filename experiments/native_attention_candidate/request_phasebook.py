"""Immutable finite requests and actual post-spawn enrollment, never admission."""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from urllib.parse import urlsplit

from experiments.exposure_gate import native_semantic_collector as native

BOOK = "ecpa-request-phasebook/v1"
ENROLLMENT = "ecpa-request-source-peer-enrollment/v1"
canonical, digest = native.canonical, native.sha


def require(value, reason):
    if not value:
        raise ValueError(reason)


def write_new(path, raw):
    path = Path(path)
    parent = path.parent.stat()
    require(path.is_absolute() and path.resolve() == path, "noncanonical artifact")
    require(
        parent.st_uid == os.geteuid() and not stat.S_IMODE(parent.st_mode) & 0o077,
        "artifact parent must be private and owned",
    )
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    return {"path": str(path), "sha256": digest(raw)}


def sources_current(sources):
    for item in sources:
        path = Path(item["path"])
        require(
            path.is_absolute() and path.resolve() == path and path.is_file(),
            "source path changed",
        )
        require(digest(path.read_bytes()) == item["sha256"], "source bytes changed")


def declare(recipe):
    """Freeze the complete recipe before launching a new owned Host service."""
    from .request_drain_consumer import validate_recipe

    validate_recipe(recipe)
    phases = recipe["phases"]
    require(1 <= len(phases) <= 64, "explicit bounded request list required")
    for key in (
        "phase_id",
        "client_request_id",
        "challenge_nonce",
        "external_request_id",
    ):
        require(
            len({phase[key] for phase in phases}) == len(phases),
            "phase/client/challenge identity reused",
        )
    bodies = [digest(canonical(phase["payload"])) for phase in phases]
    require(len(set(bodies)) == len(bodies), "request body identity reused")
    sources_current(recipe["sources"])
    return {
        "schema": BOOK,
        "declared_monotonic_ns": time.monotonic_ns(),
        "recipe_sha256": digest(canonical(recipe)),
        "recipe": json.loads(canonical(recipe)),
        "phases": [
            {
                "phase_id": phase["phase_id"],
                "phase_sha256": digest(canonical(phase)),
                "request_sha256": digest(canonical(phase["payload"])),
                "headers_sha256": digest(canonical(phase["headers"])),
                "tokenization_sha256": digest(canonical(phase["tokenization"])),
            }
            for phase in phases
        ],
        "request_order": "predeclared-serial-one-inflight",
        "total_request_budget_s": 240,
        "source": {
            "path": str(Path(__file__).resolve()),
            "sha256": digest(Path(__file__).read_bytes()),
        },
        "formal_result": False,
    }


def validate(book):
    require(
        book["schema"] == BOOK and book["formal_result"] is False,
        "phasebook classification differs",
    )
    require(
        book["total_request_budget_s"] == 240,
        "total budget must be240s; native HTTP/source budget remains180s",
    )
    require(
        book["request_order"] == "predeclared-serial-one-inflight",
        "concurrent batches are not yet qualified",
    )
    require(
        digest(canonical(book["recipe"])) == book["recipe_sha256"],
        "phasebook recipe changed",
    )
    require(
        book["source"]
        == {
            "path": str(Path(__file__).resolve()),
            "sha256": digest(Path(__file__).read_bytes()),
        },
        "phasebook adapter source changed",
    )
    from .request_drain_consumer import validate_recipe

    validate_recipe(book["recipe"])
    sources_current(book["recipe"]["sources"])
    phases = book["recipe"]["phases"]
    require(
        len(phases) == len(book["phases"]) and 1 <= len(phases) <= 64,
        "phasebook phase list changed",
    )
    for phase, row in zip(phases, book["phases"], strict=True):
        require(
            row
            == {
                "phase_id": phase["phase_id"],
                "phase_sha256": digest(canonical(phase)),
                "request_sha256": digest(canonical(phase["payload"])),
                "headers_sha256": digest(canonical(phase["headers"])),
                "tokenization_sha256": digest(canonical(phase["tokenization"])),
            },
            "phasebook request/tokenization changed",
        )


def _descendant(pid, ancestor):
    seen = set()
    while pid > 1 and pid not in seen:
        if pid == ancestor:
            return True
        seen.add(pid)
        before = native.identity(pid)
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        require(native.identity(pid) == before, "ancestry epoch changed")
        pid = int(fields[1])
    return False


def enroll_after_spawn(book, *, spec_path, host_process):
    """Record only real kernels after the owner has launched the Host process.

    Roles come from the frozen native source sender registration. They remain
    unqualified until genuine source callbacks and the independent consumer join
    those exact processes. This document issues no Manager/semantic readiness.
    """
    validate(book)
    require(host_process.poll() is None, "owned Host already exited")
    host = native.identity(host_process.pid)
    require(_descendant(host["pid"], os.getpid()), "Host is outside owner ancestry")
    tick_ns = 1_000_000_000 / os.sysconf("SC_CLK_TCK")
    require(
        host["start_ticks"] * tick_ns + tick_ns >= book["declared_monotonic_ns"],
        "phasebook was declared after Host launch",
    )
    raw = Path(spec_path).read_bytes()
    spec = json.loads(raw)
    phases = book["recipe"]["phases"]
    keys = (
        "phase_id",
        "client_request_id",
        "challenge_nonce",
        "external_request_id",
        "expected_ranks",
    )
    require(
        spec["phases"] == [{key: phase[key] for key in keys} for phase in phases],
        "native source enrollment differs from phasebook",
    )
    senders = spec["senders"]
    require(
        len(senders) == 3 and len({s["process"]["pid"] for s in senders}) == 3,
        "three distinct source peers required",
    )
    require(
        {(s["process"]["role"], s["process"]["ordinal"]) for s in senders}
        == {("api-server", 0), ("worker", 0), ("worker", 1)},
        "source API/TP2 membership differs",
    )
    value = {
        "schema": ENROLLMENT,
        "owner": native.identity(os.getpid()),
        "host": host,
        "phasebook_sha256": digest(canonical(book)),
        "spec": {"path": str(spec_path), "sha256": digest(raw)},
        "native_launch_id": spec["native_launch_id"],
        "native_plan_id": spec["native_plan_id"],
        "source_peers": senders,
        "enrolled_monotonic_ns": time.monotonic_ns(),
        "identity_status": "kernel-enrolled; native effect independently unverified",
        "formal_result": False,
    }
    enrollment_current(book, value)
    return value


def enrollment_current(book, enrollment, *, delegated_owner=None):
    validate(book)
    require(
        enrollment["schema"] == ENROLLMENT and enrollment["formal_result"] is False,
        "source enrollment classification differs",
    )
    require(
        enrollment["phasebook_sha256"] == digest(canonical(book)),
        "source enrollment belongs to another book",
    )
    expected_owner = (
        native.identity(os.getpid()) if delegated_owner is None else delegated_owner
    )
    require(
        enrollment["owner"] == expected_owner
        and native.identity(expected_owner["pid"]) == expected_owner,
        "request issuer owner epoch differs",
    )
    require(
        _descendant(os.getpid(), expected_owner["pid"]),
        "request producer outside owner ancestry",
    )
    require(
        enrollment["host"] == native.identity(enrollment["host"]["pid"]),
        "Host epoch changed",
    )
    require(
        digest(Path(enrollment["spec"]["path"]).read_bytes())
        == enrollment["spec"]["sha256"],
        "source enrollment spec changed",
    )
    for sender in enrollment["source_peers"]:
        process = sender["process"]
        actual = native.identity(process["pid"])
        require(
            process["assignment_source"] == "host"
            and all(process.get(key) == value for key, value in actual.items()),
            "source peer role/kernel changed",
        )
        require(
            _descendant(process["pid"], enrollment["host"]["pid"]),
            "source peer outside owned Host ancestry",
        )
        require(
            digest(Path(f"/proc/{process['pid']}/cmdline").read_bytes())
            == sender["cmdline_sha256"],
            "source peer command changed",
        )
        sources_current(sender["source_files"])


def match_request(book, phase_id, *, method, path, headers, body):
    validate(book)
    phase = next(
        (p for p in book["recipe"]["phases"] if p["phase_id"] == phase_id), None
    )
    require(phase is not None, "request phase is not predeclared")
    target = urlsplit(phase["url"])
    require(
        method == "POST"
        and path == target.path
        and body == canonical(phase["payload"])
        and headers == phase["headers"],
        "public request differs from exact predeclared body/header/nonce",
    )
    return phase
