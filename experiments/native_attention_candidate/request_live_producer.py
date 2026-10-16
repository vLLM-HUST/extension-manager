"""Independent source-pinned Unix producer for arrival-driven finite requests."""

import argparse
import json
import os
import socket
import stat
import struct
import time
import traceback
from pathlib import Path

from experiments.exposure_gate import native_semantic_collector as native

from . import request_phasebook as books
from .request_prefix_ticket import execute_phase, read_regular

REGISTRATION = "ecpa-request-live-producer-registration/v1"
COMMAND = "ecpa-request-live-producer-command/v1"
COMPLETION = "ecpa-request-live-producer-completion/v1"
FIXED_COMPLETION = "ecpa-request-live-producer-completion/v2"
LIFETIME_NS = 30_000_000_000
READY = "ecpa-request-live-producer-ready/v1"
MAX_FRAME = 65536


def receive(channel, *, retain_raw=False):
    raw = b""
    while not raw.endswith(b"\n"):
        block = channel.recv(MAX_FRAME + 1)
        books.require(
            block and len(raw) + len(block) <= MAX_FRAME,
            "producer command framing invalid",
        )
        raw += block
    value = json.loads(raw)
    return (value, raw) if retain_raw else value


def completion_domain(registration):
    domain = registration.get("completion_domain", COMPLETION)
    books.require(
        domain in {COMPLETION, FIXED_COMPLETION},
        "unsupported producer completion domain",
    )
    if domain == FIXED_COMPLETION:
        expiry = registration.get("original_route_expires_monotonic_ns")
        books.require(
            type(expiry) is int and expiry > time.monotonic_ns(),
            "original independently granted route expiry missing/expired",
        )
    else:
        books.require(
            "original_route_expires_monotonic_ns" not in registration,
            "legacy completion cannot claim fixed producer clock",
        )
    return domain


def fixed_completion_clock(issued_ns, deadline_ns, original_route_expiry_ns):
    """The producer captures issued once immediately after its first full verify."""
    books.require(
        all(
            type(n) is int and n > 0
            for n in (issued_ns, deadline_ns, original_route_expiry_ns)
        ),
        "producer original clock fields invalid",
    )
    expiry = min(issued_ns + LIFETIME_NS, deadline_ns, original_route_expiry_ns)
    books.require(
        issued_ns < expiry,
        "producer full verification completed after original deadline/lease",
    )
    return {
        "issued_monotonic_ns": issued_ns,
        "expires_monotonic_ns": expiry,
        "clock_origin": "producer-first-full-verification-completed",
        "lifetime_ns": LIFETIME_NS,
    }


def serve(path, expected_sha256):
    path = Path(path)
    raw = read_regular(path)
    books.require(books.digest(raw) == expected_sha256, "producer registration changed")
    registration = json.loads(raw)
    books.require(
        registration["schema"] == REGISTRATION
        and registration["formal_result"] is False,
        "producer registration scope differs",
    )
    domain = completion_domain(registration)
    book = registration["phasebook"]
    enrollment = registration["enrollment"]
    owner = enrollment["owner"]
    own = native.identity(os.getpid())
    peers = enrollment["source_peers"]
    collector = registration["descriptor"]["collector"]
    books.require(
        len(
            {
                owner["pid"],
                own["pid"],
                collector["pid"],
                *(p["process"]["pid"] for p in peers),
            }
        )
        == 6,
        "owner/API/W0/W1/producer/collector must be six distinct kernels",
    )
    books.enrollment_current(book, enrollment, delegated_owner=owner)
    books.sources_current(registration["sources"])
    address = Path(registration["socket_path"])
    books.require(
        not os.path.lexists(address)
        and stat.S_IMODE(address.parent.stat().st_mode) == 0o700,
        "fresh private producer socket required",
    )
    index = 0
    nonces = set()
    failed = None
    own_socket = None
    primary = None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(address))
            own_socket = (address.stat().st_dev, address.stat().st_ino)
            address.chmod(0o600)
            listener.listen(4)
            listener.settimeout(1)
            meta = address.stat()
            ready = {
                "schema": READY,
                "producer": own,
                "socket_identity": [meta.st_dev, meta.st_ino],
                "registration_sha256": books.digest(raw),
                "producer_source_sha256": books.digest(Path(__file__).read_bytes()),
                "formal_result": False,
            }
            books.write_new(Path(registration["ready_path"]), books.canonical(ready))
            stopped = False
            while not stopped:
                try:
                    channel, _ = listener.accept()
                except TimeoutError:
                    books.require(
                        native.identity(owner["pid"]) == owner,
                        "producer owner epoch gone",
                    )
                    continue
                with channel:
                    channel.settimeout(190)
                    nonce = None
                    try:
                        pid, uid, _ = struct.unpack(
                            "3i",
                            channel.getsockopt(
                                socket.SOL_SOCKET, socket.SO_PEERCRED, 12
                            ),
                        )
                        books.require(
                            uid == os.geteuid() and native.identity(pid) == owner,
                            "producer command peer is not exact owner",
                        )
                        command = receive(channel)
                        books.require(
                            command["schema"] == COMMAND,
                            "producer command schema differs",
                        )
                        nonce = command["nonce"]
                        books.require(
                            isinstance(nonce, str)
                            and len(nonce) == 64
                            and nonce not in nonces,
                            "producer command nonce missing/replayed",
                        )
                        nonces.add(nonce)
                        if command["operation"] == "stop":
                            stopped = True
                            response = {
                                "schema": COMPLETION,
                                "nonce": nonce,
                                "stopped": True,
                                "formal_result": False,
                            }
                        else:
                            books.require(
                                failed is None and command["operation"] == "execute",
                                "producer closed or unsupported operation",
                            )
                            books.require(
                                read_regular(path) == raw,
                                "producer registration bytes changed",
                            )
                            books.sources_current(registration["sources"])
                            books.enrollment_current(
                                book, enrollment, delegated_owner=owner
                            )
                            deadline = command["deadline_monotonic_ns"]
                            books.require(
                                type(deadline) is int
                                and deadline
                                == command["public_arrived_monotonic_ns"]
                                + book["total_request_budget_s"] * 1_000_000_000
                                and command["public_arrived_monotonic_ns"]
                                <= time.monotonic_ns()
                                < deadline,
                                "public request total deadline differs or expired",
                            )
                            phases = book["recipe"]["phases"]
                            books.require(
                                index < len(phases)
                                and command["phase_id"] == phases[index]["phase_id"]
                                and command["request_sha256"]
                                == books.digest(
                                    books.canonical(phases[index]["payload"])
                                ),
                                "producer request/order/body differs",
                            )
                            output = (
                                Path(registration["output_root"])
                                / f"request-{index:04d}"
                            )
                            completion = execute_phase(
                                book,
                                command["phase_id"],
                                output,
                                **registration["execution"],
                            )
                            first_verified_ns = time.monotonic_ns()
                            clock = (
                                fixed_completion_clock(
                                    first_verified_ns,
                                    deadline,
                                    registration["original_route_expires_monotonic_ns"],
                                )
                                if domain == FIXED_COMPLETION
                                else {}
                            )
                            books.sources_current(registration["sources"])
                            books.enrollment_current(
                                book, enrollment, delegated_owner=owner
                            )
                            books.require(
                                time.monotonic_ns()
                                < min(
                                    deadline,
                                    clock.get("expires_monotonic_ns", deadline),
                                ),
                                "producer validation exceeded total request deadline",
                            )
                            response = {
                                "schema": domain,
                                "nonce": nonce,
                                "producer": own,
                                **clock,
                                "registration_sha256": books.digest(raw),
                                "completion": completion,
                                "formal_result": False,
                            }
                            books.write_new(
                                output / "producer-command-completion.json",
                                books.canonical(response),
                            )
                            index += 1
                    except Exception as error:
                        first_failure = failed is None
                        failed = str(error)
                        if first_failure:
                            books.write_new(
                                Path(registration["output_root"])
                                / "producer-first-failure.json",
                                books.canonical(
                                    {
                                        "failure": failed,
                                        "failure_type": type(error).__name__,
                                        "traceback": traceback.format_exc(),
                                        "formal_result": False,
                                    }
                                ),
                            )
                        response = {
                            "schema": COMPLETION,
                            "nonce": nonce,
                            "failed": failed,
                            "formal_result": False,
                        }
                    channel.sendall(books.canonical(response) + b"\n")

    except BaseException as error:
        primary = error
        raise
    finally:
        if own_socket is not None:
            try:
                metadata = address.lstat()
                if (metadata.st_dev, metadata.st_ino) == own_socket:
                    address.unlink()
            except FileNotFoundError:
                pass
            except BaseException as cleanup:
                if primary is None:
                    raise
                primary.cleanup_error = repr(cleanup)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    serve(args.registration, args.expected_sha256)


if __name__ == "__main__":
    main()
