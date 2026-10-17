"""Actual-Popen concurrent H4 health witness; never native/public authority.

Every probe keeps original clocks and accepted TCP/kernel observations. The
unassigned early kernel is authorized only by later exact Host7+kernel4 joining.
No late bootstrap completion clock is substituted for first observed health200.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import socket
import threading
import time
import zlib
from pathlib import Path
from urllib.parse import urlparse

from .analyze import h4_body_binding, h4_decode_body

SCHEMA = "ecpa-h4-actual-popen-health-journal/v1"
TERMINAL = "ecpa-h4-actual-popen-health-terminal/v1"
MAX_JOURNAL = 64 * 1024 * 1024
MAX_CAPTURE = 2 * 1024 * 1024
MAX_BODY = 64 * 1024
POLL_SECONDS = 0.25  # original run_h4.wait_ready readiness policy
IO_SECONDS = 2.0
KEYS = ("pid", "start_ticks", "session", "boot_id")


class HealthEvidenceError(ValueError):
    """A corrupt/ambiguous physical witness is not a runtime success or timeout."""


class HealthOwnerExited(ConnectionError):
    """Only original owner ENOENT/same-kernel zombie; never pid replacement."""

    def __init__(self, observation):
        self.observation = observation
        super().__init__("original health product owner exited")


def observe_owner(owner):
    before_raw, before_mono = raw_ns(), time.monotonic_ns()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    require(boot == owner["boot_id"], "health owner boot changed")
    try:
        original = Path(f"/proc/{owner['pid']}/stat").read_text()
    except FileNotFoundError:
        original, kind = None, "original-owner-stat-ENOENT"
    else:
        fields = original.rsplit(")", 1)[1].split()
        actual = dict(pid=int(original.split(" ", 1)[0]), start_ticks=int(fields[19]),
                      session=int(fields[3]), boot_id=boot)
        require(canonical(actual) == canonical(owner), "health product pid reused/kernel changed")
        if fields[0] != "Z":
            return original
        kind = "original-owner-zombie"
    raise HealthOwnerExited(dict(kind=kind, owner=dict(owner), boot_id=boot,
        stat_raw=original, before_raw_ns=before_raw, before_monotonic_ns=before_mono,
        after_raw_ns=raw_ns(), after_monotonic_ns=time.monotonic_ns()))


class HealthAcceptedPeerExited(ConnectionError):
    """Exact previously accepted socket peer, no inferred role/readiness."""

    def __init__(self, observation):
        self.observation = observation
        super().__init__("original accepted health peer exited")


def observe_accepted_peer(expected):
    try:
        observe_owner(expected)
    except HealthOwnerExited as error:
        value = dict(error.observation)
        value["accepted_peer"] = value.pop("owner")
        value["kind"] = value["kind"].replace("original-owner", "accepted-peer")
        raise HealthAcceptedPeerExited(value) from error


def require(value, message):
    if not value:
        raise HealthEvidenceError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def raw_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)


def kernel(stat_raw, boot):
    f = stat_raw.rsplit(")", 1)[1].split()
    require(f[0] != "Z", "health peer/product became zombie")
    return dict(pid=int(stat_raw.split(" ", 1)[0]), start_ticks=int(f[19]), session=int(f[3]), boot_id=boot)


def pack(value):
    raw = canonical(value)
    require(len(raw) <= MAX_CAPTURE, "health kernel capture exceeds source bound")
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                zlib_base64=base64.b64encode(zlib.compress(raw)).decode())


def unpack(value):
    require(type(value) is dict and set(value) == {"bytes", "sha256", "zlib_base64"}
            and type(value["bytes"]) is int and 0 < value["bytes"] <= MAX_CAPTURE,
            "invalid health raw capture descriptor")
    compressed = base64.b64decode(value["zlib_base64"], validate=True)
    require(len(compressed) <= MAX_CAPTURE, "oversized health compressed capture")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(compressed, MAX_CAPTURE + 1)
    require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
            and len(raw) == value["bytes"] <= MAX_CAPTURE
            and hashlib.sha256(raw).hexdigest() == value["sha256"], "health raw capture changed")
    result = json.loads(raw)
    require(canonical(result) == raw, "noncanonical health raw capture")
    return result


def tcp_address(endpoint):
    return socket.inet_aton(endpoint[0])[::-1].hex().upper() + f":{endpoint[1]:04X}"


def tree_rows(value, owner):
    """Reconstruct ancestry from original /proc stat bytes, never stored flags."""
    require(type(value) is dict and set(value) == {"boot_id", "processes", "tcp_raw", "observed_begin_raw_ns", "observed_begin_monotonic_ns", "observed_raw_ns", "observed_monotonic_ns"}
            and type(value["boot_id"]) is str and value["boot_id"] == owner["boot_id"]
            and type(value["processes"]) is list and type(value["tcp_raw"]) is str
            and all(type(value[k]) is int for k in ("observed_begin_raw_ns", "observed_begin_monotonic_ns", "observed_raw_ns", "observed_monotonic_ns"))
            and value["observed_begin_raw_ns"] <= value["observed_raw_ns"]
            and value["observed_begin_monotonic_ns"] <= value["observed_monotonic_ns"],
            "health raw capture schema/boot/clocks differ")
    rows, parents = {}, {}
    for item in value["processes"]:
        require(type(item) is dict and set(item) == {"stat_raw", "fd_links"}
                and type(item["stat_raw"]) is str and type(item["fd_links"]) is list,
                "malformed raw health process/FD capture")
        for link in item["fd_links"]:
            require(type(link) is dict and set(link) == {"fd", "target"}
                    and type(link["fd"]) is int and link["fd"] >= 0
                    and type(link["target"]) is str, "malformed raw health FD link")
        ident = kernel(item["stat_raw"], value["boot_id"])
        pid = ident["pid"]
        require(pid not in rows, "duplicate health process kernel")
        rows[pid] = ident
        parents[pid] = int(item["stat_raw"].rsplit(")", 1)[1].split()[1])
    require(canonical(rows.get(owner["pid"])) == canonical(owner), "actual product kernel changed in health capture")
    reachable = {owner["pid"]}
    while True:
        more = {pid for pid in rows if parents[pid] in reachable} - reachable
        if not more:
            break
        reachable.update(more)
    require(reachable == set(rows), "health accepted owner escaped actual product ancestry")
    return rows


def capture_tree(owner):
    begin_raw, begin_mono = raw_ns(), time.monotonic_ns()
    observe_owner(owner)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    stats, parents = {}, {}
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            raw = (path / "stat").read_text()
            ident = kernel(raw, boot)
        except (OSError, ValueError, IndexError):
            continue
        stats[ident["pid"]] = raw
        parents[ident["pid"]] = int(raw.rsplit(")", 1)[1].split()[1])
    reachable = {owner["pid"]}
    while True:
        more = {pid for pid in stats if parents[pid] in reachable} - reachable
        if not more:
            break
        reachable.update(more)
    observe_owner(owner)
    require(owner["pid"] in stats and canonical(kernel(stats[owner["pid"]], boot)) == canonical(owner),
            "actual product epoch changed before health probe")
    processes = []
    for pid in sorted(reachable):
        if pid not in stats:
            continue
        links = []
        try:
            descriptors = list(Path(f"/proc/{pid}/fd").iterdir())
        except OSError:
            descriptors = []
        for fd in descriptors:
            try:
                links.append(dict(fd=int(fd.name), target=os.readlink(fd)))
            except OSError:
                continue
        processes.append(dict(stat_raw=stats[pid], fd_links=sorted(links, key=lambda row: row["fd"])))
    return dict(boot_id=boot, processes=processes, tcp_raw=Path("/proc/net/tcp").read_text(),
                observed_begin_raw_ns=begin_raw, observed_begin_monotonic_ns=begin_mono,
                observed_raw_ns=raw_ns(), observed_monotonic_ns=time.monotonic_ns())


def accepted_owner(capture, owner, local, peer):
    rows = tree_rows(capture, owner)
    matches = {line.split()[9] for line in capture["tcp_raw"].splitlines()[1:]
               if line.split()[1:4] == [tcp_address(peer), tcp_address(local), "01"]}
    require(len(matches) <= 1, "ambiguous actual health accepted TCP tuple")
    matches.discard("0")
    if not matches:
        return None
    inode = next(iter(matches))
    candidates = set()
    for item in capture["processes"]:
        pid = kernel(item["stat_raw"], capture["boot_id"])["pid"]
        require(len({link["fd"] for link in item["fd_links"]}) == len(item["fd_links"]), "duplicate health FD capture")
        if any(link["target"] == f"socket:[{inode}]" for link in item["fd_links"]):
            candidates.add(pid)
    require(len(candidates) <= 1, "health accepted FD has ambiguous process owners")
    return dict(inode=inode, kernel=rows[next(iter(candidates))]) if candidates else None


class HealthObserver:
    """One observer outside the actual product subtree, with owned socket cancel."""

    def __init__(self, output, url, startup_timeout_seconds, owner, timing_path):
        self.output, self.url, self.owner = Path(output), url, dict(owner)
        self.timing_path = Path(timing_path)
        timing_raw = self.timing_path.read_bytes()
        timing = json.loads(timing_raw)
        require(canonical(timing["actual_kernel"]) == canonical(owner), "health observer Popen differs")
        endpoint = urlparse(url)
        require(endpoint.scheme == "http" and endpoint.hostname == "127.0.0.1"
                and endpoint.port is not None and not endpoint.username and not endpoint.password
                and not endpoint.fragment, "health requires exact registered IPv4 loopback HTTP endpoint")
        self.endpoint = endpoint
        self.deadline_ns = timing["before_monotonic_ns"] + int(startup_timeout_seconds * 1e9)
        self.stop_event, self.watchdog_stop = threading.Event(), threading.Event()
        self.socket_lock, self.actual_socket = threading.Lock(), None
        self.sequence, self.previous, self.reason, self.failure = 0, "0" * 64, None, None
        self.first_success_sequence = None
        self.cancellations = []
        self.finished = False
        self.log = os.open(self.output / "health-probes.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.record(dict(kind="start", source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            product_owner=self.owner, url=url, deadline_ns=self.deadline_ns,
            popen_timing=dict(path=str(self.timing_path), sha256=hashlib.sha256(timing_raw).hexdigest()),
            poll_seconds=POLL_SECONDS, io_seconds=IO_SECONDS,
            observed_raw_ns=raw_ns(), observed_monotonic_ns=time.monotonic_ns()))
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.watchdog = threading.Thread(target=self.expire, daemon=True)

    def record(self, event):
        event = dict(event, schema=SCHEMA, sequence=self.sequence, previous_sha256=self.previous)
        event["event_sha256"] = hashlib.sha256(canonical(event)).hexdigest()
        raw = canonical(event) + b"\n"
        require(os.fstat(self.log).st_size + len(raw) <= MAX_JOURNAL, "health journal source bound exceeded")
        remaining = memoryview(raw)
        while remaining:
            count = os.write(self.log, remaining)
            require(count > 0, "health original journal write failed")
            remaining = remaining[count:]
        os.fsync(self.log)
        self.sequence += 1
        self.previous = event["event_sha256"]

    def start(self):
        self.watchdog.start()
        self.thread.start()

    def cancel_socket(self, reason):
        # Keep the actual socket object even when HTTPConnection.sock is None.
        with self.socket_lock:
            observation = dict(reason=reason, raw_ns=raw_ns(), monotonic_ns=time.monotonic_ns(),
                               actual_socket_present=self.actual_socket is not None, shutdown_error=None,
                               shutdown_before_raw_ns=None, shutdown_before_monotonic_ns=None,
                               shutdown_after_raw_ns=None, shutdown_after_monotonic_ns=None)
            if reason in {"absolute-startup-deadline", "caller-finally-cancel"}:
                self.stop_event.set()
            if self.actual_socket is not None:
                observation["shutdown_before_raw_ns"], observation["shutdown_before_monotonic_ns"] = raw_ns(), time.monotonic_ns()
                try:
                    self.actual_socket.shutdown(socket.SHUT_RDWR)
                except OSError as error:
                    observation["shutdown_error"] = dict(type=type(error).__name__, errno=error.errno, message=str(error))
                finally:
                    observation["shutdown_after_raw_ns"], observation["shutdown_after_monotonic_ns"] = raw_ns(), time.monotonic_ns()
            self.cancellations.append(observation)

    def expire(self):
        if not self.watchdog_stop.wait(max(0, (self.deadline_ns - time.monotonic_ns()) / 1e9)):
            self.cancel_socket("absolute-startup-deadline")

    def probe(self):
        row = dict(kind="probe", sent_raw_ns=raw_ns(), sent_monotonic_ns=time.monotonic_ns(),
                   before=None, before_attempts=[], after=None, local=None, peer=None, accepted=None,
                   response=None, error=None, response_complete=False)
        connection = http.client.HTTPConnection(self.endpoint.hostname, self.endpoint.port)
        response = None
        owned = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with self.socket_lock:
            self.actual_socket = owned
        try:
            remaining = min(IO_SECONDS, (self.deadline_ns - time.monotonic_ns()) / 1e9)
            if remaining <= 0 or self.stop_event.is_set():
                raise TimeoutError("original health startup deadline/cancellation before connect")
            owned.settimeout(remaining)
            owned.connect((self.endpoint.hostname, self.endpoint.port))
            connection.sock = owned
            row["local"], row["peer"] = list(owned.getsockname()), list(owned.getpeername())
            accept_deadline = min(self.deadline_ns, time.monotonic_ns() + int(IO_SECONDS * 1e9))
            while time.monotonic_ns() < accept_deadline and not self.stop_event.is_set():
                before = capture_tree(self.owner)
                row["before"] = pack(before)
                row["before_attempts"].append(row["before"])
                accepted = accepted_owner(before, self.owner, row["local"], row["peer"])
                if accepted is not None:
                    row["accepted"] = accepted
                    break
                self.stop_event.wait(.005)
            if row["accepted"] is None:
                # No HTTP bytes were sent: preserve this unresolved connection,
                # never call it an authenticated response or fabricate health.
                raise ConnectionError("health accepted FD not yet independently observable")
            connection.putrequest("GET", (self.endpoint.path or "/") + ("?" + self.endpoint.query if self.endpoint.query else ""))
            row["backend_sent_raw_ns"], row["backend_sent_monotonic_ns"] = raw_ns(), time.monotonic_ns()
            connection.endheaders()
            response = connection.getresponse()
            body = response.read(MAX_BODY + 1)
            require(len(body) <= MAX_BODY, "health response exceeds original source bound")
            if response.length is not None and response.length != 0:
                raise http.client.IncompleteRead(body, response.length)
            # An explicit read limit must not turn a truncated length-framed
            # body or a still-open close-framed response into complete health.
            require(response.read(1) == b"", "health response exceeds original source bound")
            # Completion and local shutdown are serialized by the same lock.
            # SHUT_RDWR-induced EOF of a close-framed response is not completion.
            with self.socket_lock:
                row["received_raw_ns"], row["received_monotonic_ns"] = raw_ns(), time.monotonic_ns()
                local_cancel = next((dict(item) for item in self.cancellations
                    if item["actual_socket_present"] and item["monotonic_ns"] <= row["received_monotonic_ns"]), None)
            if local_cancel is not None:
                row["interrupted_response"] = dict(status_code=response.status,
                    headers=list(response.getheaders()), **h4_body_binding(body), body_complete=False)
                row["local_cancel"] = local_cancel
                raise ConnectionAbortedError("local health cancellation preceded response completion")
            row["response"] = dict(status_code=response.status, headers=list(response.getheaders()), **h4_body_binding(body))
            row["response_complete"] = True
            observe_accepted_peer(row["accepted"]["kernel"])
            after = capture_tree(self.owner)
            row["after"] = pack(after)
            after_rows = tree_rows(after, self.owner)
            if canonical(after_rows.get(row["accepted"]["kernel"]["pid"])) != canonical(row["accepted"]["kernel"]):
                # Only a new, exact physical ENOENT/same-kernel-Z observation
                # makes this a runtime interruption. Missing/tampered raw or a
                # replacement/live escaped kernel still raises integrity error.
                observe_accepted_peer(row["accepted"]["kernel"])
                raise HealthEvidenceError("live accepted health peer missing/replaced in original after capture")
        except Exception as error:
            row["error"] = dict(type=type(error).__module__ + "." + type(error).__qualname__, message=str(error))
            if response is not None and isinstance(error, http.client.IncompleteRead):
                row["interrupted_response"] = dict(status_code=response.status,
                    headers=list(response.getheaders()), **h4_body_binding(error.partial), body_complete=False)
            if isinstance(error, HealthAcceptedPeerExited):
                row["accepted_peer_terminal"] = error.observation
            elif isinstance(error, HealthOwnerExited):
                row["owner_terminal"] = error.observation
            elif isinstance(error, HealthEvidenceError):
                row["evidence_error"] = True
        finally:
            row["finished_raw_ns"], row["finished_monotonic_ns"] = raw_ns(), time.monotonic_ns()
            with self.socket_lock:
                self.actual_socket = None
            close_errors = []
            for resource in (response, connection, owned):
                if resource is not None:
                    try:
                        resource.close()
                    except OSError as error:
                        close_errors.append(type(error).__name__ + ": " + str(error))
            if close_errors:
                row["close_errors"] = close_errors
                row["evidence_error"] = True
                row["error"] = row["error"] or dict(type="owned-socket-close", message="; ".join(close_errors))
        return row

    def run(self):
        try:
            while not self.stop_event.is_set() and time.monotonic_ns() < self.deadline_ns:
                row = self.probe()
                sequence = self.sequence
                self.record(row)
                if row.get("evidence_error"):
                    raise HealthEvidenceError("actual health physical witness failed")
                if row.get("owner_terminal") is not None:
                    self.reason = "owner-exited"
                    break
                if row.get("accepted_peer_terminal") is not None:
                    self.reason = "accepted-peer-exited"
                    break
                if (row["response_complete"] and row["error"] is None
                    and row["response"]["status_code"] == 200
                    and row["received_monotonic_ns"] <= self.deadline_ns):
                    self.first_success_sequence, self.reason = sequence, "success"
                    break
                self.stop_event.wait(min(POLL_SECONDS, max(0, (self.deadline_ns - time.monotonic_ns()) / 1e9)))
            if self.reason is None:
                self.reason = "deadline" if time.monotonic_ns() >= self.deadline_ns else "cancelled"
        except Exception as error:
            self.reason, self.failure = "error", type(error).__name__ + ": " + str(error)
        finally:
            self.watchdog_stop.set()

    def finish(self, *, cancel=False):
        if not self.finished:
            if cancel:
                self.cancel_socket("caller-finally-cancel")
            try:
                self.thread.join(timeout=max(0, (self.deadline_ns - time.monotonic_ns()) / 1e9) + 3 if not cancel else 5)
            finally:
                # Try both joins/cancellation paths even if a worker join fails.
                self.watchdog_stop.set()
                self.cancel_socket("join-finally-cleanup")
                self.watchdog.join(timeout=3)
            require(not self.thread.is_alive(), "owned health observer did not join")
            require(not self.watchdog.is_alive(), "owned health deadline observer did not join")
            os.close(self.log)
            raw = (self.output / "health-probes.jsonl").read_bytes()
            terminal = dict(schema=TERMINAL, reason=self.reason, failure=self.failure,
                first_success_sequence=self.first_success_sequence,
                local_cancellations=self.cancellations,
                original_journal=dict(path=str(self.output / "health-probes.jsonl"), sha256=hashlib.sha256(raw).hexdigest()),
                next_sequence=self.sequence, last_event_sha256=self.previous,
                observed_raw_ns=raw_ns(), observed_monotonic_ns=time.monotonic_ns())
            fd = os.open(self.output / "health-probe-terminal.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(canonical(terminal)); stream.flush(); os.fsync(stream.fileno())
            self.finished = True
        return self.output / "health-probe-terminal.json"


def validate_local_cancel(item):
    require(type(item) is dict and set(item) == {"reason", "raw_ns", "monotonic_ns", "actual_socket_present", "shutdown_error", "shutdown_before_raw_ns", "shutdown_before_monotonic_ns", "shutdown_after_raw_ns", "shutdown_after_monotonic_ns"}
            and item["reason"] in {"absolute-startup-deadline", "caller-finally-cancel", "join-finally-cleanup"}
            and type(item["actual_socket_present"]) is bool
            and type(item["raw_ns"]) is int and type(item["monotonic_ns"]) is int,
            "health original local cancellation malformed")
    fields = ("shutdown_before_raw_ns", "shutdown_before_monotonic_ns", "shutdown_after_raw_ns", "shutdown_after_monotonic_ns")
    if item["actual_socket_present"]:
        require(all(type(item[key]) is int for key in fields)
                and item["raw_ns"] <= item["shutdown_before_raw_ns"] <= item["shutdown_after_raw_ns"]
                and item["monotonic_ns"] <= item["shutdown_before_monotonic_ns"] <= item["shutdown_after_monotonic_ns"],
                "actual local socket shutdown clocks differ")
    else:
        require(all(item[key] is None for key in fields) and item["shutdown_error"] is None,
                "local cancellation invented a socket shutdown")
    if item["shutdown_error"] is not None:
        require(type(item["shutdown_error"]) is dict and set(item["shutdown_error"]) == {"type", "errno", "message"}
                and type(item["shutdown_error"]["type"]) is str
                and type(item["shutdown_error"]["errno"]) is int
                and type(item["shutdown_error"]["message"]) is str, "local socket shutdown error malformed")


def verify_health(output, url, startup_timeout_seconds, timing, *, epoch=None, require_terminal=False):
    """Portable full replay; epoch=None retains unknown API readiness, not success."""
    output = Path(output)
    journal = output / "health-probes.jsonl"
    terminal_path = output / "health-probe-terminal.json"
    if not journal.exists():
        require(not terminal_path.exists() and not require_terminal, "required original health witness absent")
        return None
    require(journal.resolve() == journal and not journal.is_symlink(), "unsafe original health journal")
    raw = journal.read_bytes()
    require(0 < len(raw) <= MAX_JOURNAL and raw.endswith(b"\n"), "original health journal truncated/oversized")
    events, previous = [], "0" * 64
    for sequence, line in enumerate(raw.splitlines()):
        event = json.loads(line)
        require(canonical(event) == line and event["schema"] == SCHEMA
                and type(event["sequence"]) is int and event["sequence"] == sequence
                and event["previous_sha256"] == previous, "health original chain/sequence differs")
        material = {k: v for k, v in event.items() if k != "event_sha256"}
        require(hashlib.sha256(canonical(material)).hexdigest() == event["event_sha256"], "health original event hash differs")
        previous = event["event_sha256"]
        events.append(event)
    header = events[0]
    common = {"schema", "sequence", "previous_sha256", "event_sha256"}
    require(set(header) == common | {"kind", "source_sha256", "product_owner", "url", "deadline_ns", "popen_timing", "poll_seconds", "io_seconds", "observed_raw_ns", "observed_monotonic_ns"},
            "unexpected original health header field")
    owner = timing["actual_kernel"]
    deadline = timing["before_monotonic_ns"] + int(startup_timeout_seconds * 1e9)
    timing_raw = (output / "phase0.product-popen-timing.json").read_bytes()
    require(header["kind"] == "start" and header["url"] == url
            and canonical(header["product_owner"]) == canonical(owner)
            and header["source_sha256"] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            and header["deadline_ns"] == deadline and type(header["deadline_ns"]) is int
            and type(header["poll_seconds"]) is float and header["poll_seconds"] == POLL_SECONDS
            and type(header["io_seconds"]) is float and header["io_seconds"] == IO_SECONDS
            and header["popen_timing"] == dict(path=str(output / "phase0.product-popen-timing.json"), sha256=hashlib.sha256(timing_raw).hexdigest())
            and type(header["observed_monotonic_ns"]) is int
            and type(header["observed_raw_ns"]) is int
            and timing["before_monotonic_ns"] <= header["observed_monotonic_ns"]
            and timing["after_ns"] <= header["observed_raw_ns"], "health original source/Popen/policy binding differs")
    endpoint = urlparse(url)
    require(endpoint.scheme == "http" and endpoint.hostname == "127.0.0.1" and endpoint.port is not None,
            "registered health endpoint differs")
    first_candidate, first_authenticated = None, None
    owner_exits, peer_exits, response_completions, local_cancel_rows = [], [], [], []
    last_raw, last_mono = header["observed_raw_ns"], header["observed_monotonic_ns"]
    require(len(events) <= int(startup_timeout_seconds / POLL_SECONDS) + 3, "health probe population exceeds original polling bound")
    for row in events[1:]:
        required = common | {"kind", "sent_raw_ns", "sent_monotonic_ns", "before", "before_attempts", "after", "local", "peer", "accepted", "response", "error", "response_complete", "finished_raw_ns", "finished_monotonic_ns"}
        optional = {"backend_sent_raw_ns", "backend_sent_monotonic_ns", "received_raw_ns", "received_monotonic_ns", "interrupted_response", "evidence_error", "close_errors", "owner_terminal", "accepted_peer_terminal", "local_cancel"}
        require(required <= set(row) <= required | optional, "unexpected original health probe field")
        require(row["kind"] == "probe" and type(row["response_complete"]) is bool
                and all(type(row[k]) is int for k in ("sent_raw_ns", "sent_monotonic_ns", "finished_raw_ns", "finished_monotonic_ns"))
                and last_raw <= row["sent_raw_ns"] <= row["finished_raw_ns"]
                and last_mono <= row["sent_monotonic_ns"] <= row["finished_monotonic_ns"]
                and row["sent_monotonic_ns"] < deadline, "health original probe clocks differ")
        require(first_candidate is None, "health source continued after its first complete on-time200")
        require(not owner_exits and not peer_exits, "health source continued after exact original owner/accepted-peer exit")
        last_raw, last_mono = row["finished_raw_ns"], row["finished_monotonic_ns"]
        if row["error"] is not None:
            require(type(row["error"]) is dict and set(row["error"]) == {"type", "message"}
                    and type(row["error"]["type"]) is str and type(row["error"]["message"]) is str,
                    "invalid original health error")
        require(not row.get("evidence_error"), "source health physical witness failed; no qualification")
        accepted, before = None, None
        require(type(row["before_attempts"]) is list, "missing original health acceptance capture history")
        require(canonical(row["before"]) == canonical(row["before_attempts"][-1] if row["before_attempts"] else None),
                "health selected capture differs from original capture history")
        previous_capture_raw, previous_capture_mono = row["sent_raw_ns"], row["sent_monotonic_ns"]
        for index, descriptor in enumerate(row["before_attempts"]):
            capture = unpack(descriptor)
            require(previous_capture_raw <= capture["observed_begin_raw_ns"] <= capture["observed_raw_ns"] <= row["finished_raw_ns"]
                    and previous_capture_mono <= capture["observed_begin_monotonic_ns"] <= capture["observed_monotonic_ns"] <= row["finished_monotonic_ns"],
                    "health original capture attempt clock differs")
            captured_owner = accepted_owner(capture, owner, row["local"], row["peer"])
            require(index == len(row["before_attempts"]) - 1 or captured_owner is None,
                    "health source skipped an already observed accepted peer")
            previous_capture_raw, previous_capture_mono = capture["observed_raw_ns"], capture["observed_monotonic_ns"]
        if row["before"] is not None:
            local, peer = row["local"], row["peer"]
            require(type(local) is list and type(peer) is list and len(local) == len(peer) == 2
                    and local[0] == peer[0] == "127.0.0.1" and type(local[1]) is int
                    and type(peer[1]) is int and peer[1] == endpoint.port, "health TCP tuple differs")
            before = unpack(row["before"])
            require(row["sent_raw_ns"] <= before["observed_begin_raw_ns"] <= before["observed_raw_ns"] <= row["finished_raw_ns"]
                    and row["sent_monotonic_ns"] <= before["observed_begin_monotonic_ns"] <= before["observed_monotonic_ns"] <= row["finished_monotonic_ns"],
                    "health accepted capture clocks differ")
            accepted = accepted_owner(before, owner, local, peer)
            require(canonical(accepted) == canonical(row["accepted"]), "health accepted FD/kernel changed")
        else:
            require(row["accepted"] is None and row["response"] is None and row["after"] is None,
                    "health response without original accepted-socket evidence")
        if row.get("interrupted_response") is not None:
            partial = row["interrupted_response"]
            require(partial["body_complete"] is False and len(h4_decode_body(partial)) <= MAX_BODY + 1,
                    "interrupted health body mislabeled or changed")
        if row.get("local_cancel") is not None:
            item = row["local_cancel"]
            validate_local_cancel(item)
            require(type(item) is dict and set(item) == {"reason", "raw_ns", "monotonic_ns", "actual_socket_present", "shutdown_error", "shutdown_before_raw_ns", "shutdown_before_monotonic_ns", "shutdown_after_raw_ns", "shutdown_after_monotonic_ns"}
                    and item["reason"] in {"absolute-startup-deadline", "caller-finally-cancel", "join-finally-cleanup"}
                    and item["actual_socket_present"] is True
                    and type(item["raw_ns"]) is int and type(item["monotonic_ns"]) is int
                    and type(row.get("received_raw_ns")) is int and type(row.get("received_monotonic_ns")) is int
                    and row["sent_raw_ns"] <= item["raw_ns"] <= row["received_raw_ns"] <= row["finished_raw_ns"]
                    and row["sent_monotonic_ns"] <= item["monotonic_ns"] <= row["received_monotonic_ns"] <= row["finished_monotonic_ns"]
                    and (item["shutdown_error"] is None or (type(item["shutdown_error"]) is dict
                        and set(item["shutdown_error"]) == {"type", "errno", "message"}
                        and type(item["shutdown_error"]["type"]) is str
                        and type(item["shutdown_error"]["errno"]) is int
                        and type(item["shutdown_error"]["message"]) is str)),
                    "invalid original local cancellation EOF clocks")
            local_cancel_rows.append(item)
            require(row.get("interrupted_response") is not None and row["response"] is None
                    and row["error"] is not None, "cancelled EOF minted complete health")
        peer_exit = row.get("accepted_peer_terminal")
        if peer_exit is not None:
            require(row.get("owner_terminal") is None and type(peer_exit) is dict
                    and set(peer_exit) == {"kind", "accepted_peer", "boot_id", "stat_raw", "before_raw_ns", "before_monotonic_ns", "after_raw_ns", "after_monotonic_ns"}
                    and accepted is not None
                    and canonical(peer_exit["accepted_peer"]) == canonical(accepted["kernel"])
                    and peer_exit["boot_id"] == owner["boot_id"]
                    and row["error"] is not None
                    and row["error"]["type"] == __name__ + ".HealthAcceptedPeerExited"
                    and row["response"] is not None and row["response_complete"] is True
                    and len(h4_decode_body(row["response"])) <= MAX_BODY
                    and type(row["response"]["status_code"]) is int
                    and all(type(row[k]) is int for k in ("backend_sent_raw_ns", "backend_sent_monotonic_ns", "received_raw_ns", "received_monotonic_ns"))
                    and all(type(peer_exit[k]) is int for k in ("before_raw_ns", "before_monotonic_ns", "after_raw_ns", "after_monotonic_ns"))
                    and before["observed_raw_ns"] <= row["backend_sent_raw_ns"] <= row["received_raw_ns"] <= peer_exit["before_raw_ns"] <= peer_exit["after_raw_ns"] <= row["finished_raw_ns"]
                    and before["observed_monotonic_ns"] <= row["backend_sent_monotonic_ns"] <= row["received_monotonic_ns"] <= peer_exit["before_monotonic_ns"] <= peer_exit["after_monotonic_ns"] <= row["finished_monotonic_ns"],
                    "accepted peer exit lacks exact original accepted kernel/body/clocks")
            if peer_exit["kind"] == "accepted-peer-zombie":
                original = peer_exit["stat_raw"]
                require(type(original) is str, "accepted peer zombie lacks original stat")
                fields = original.rsplit(")", 1)[1].split()
                actual = dict(pid=int(original.split(" ", 1)[0]), start_ticks=int(fields[19]), session=int(fields[3]), boot_id=peer_exit["boot_id"])
                require(fields[0] == "Z" and canonical(actual) == canonical(accepted["kernel"]), "accepted peer zombie kernel changed")
            else:
                require(peer_exit["kind"] == "accepted-peer-stat-ENOENT" and peer_exit["stat_raw"] is None,
                        "unknown accepted peer interruption cause")
            if row["after"] is not None:
                after = unpack(row["after"])
                after_rows = tree_rows(after, owner)
                require(row["received_raw_ns"] <= after["observed_begin_raw_ns"] <= after["observed_raw_ns"] <= peer_exit["before_raw_ns"]
                        and row["received_monotonic_ns"] <= after["observed_begin_monotonic_ns"] <= after["observed_monotonic_ns"] <= peer_exit["before_monotonic_ns"],
                        "accepted peer exit hides invalid original after clocks")
                require(accepted["kernel"]["pid"] not in after_rows,
                        "accepted peer exit cannot excuse conflicting/replaced original after kernel")
                after_inodes = {line.split()[9] for line in after["tcp_raw"].splitlines()[1:]
                    if line.split()[1:4] == [tcp_address(row["peer"]), tcp_address(row["local"]), "01"]}
                require(not after_inodes or after_inodes == {accepted["inode"]},
                        "accepted peer exit hides conflicting original after TCP inode")
            if epoch is not None:
                api, api_kernel = epoch["roster"]["api-server/0"], epoch["kernels"]["api-server/0"]
                require(api["assignment_source"] == "host" and api["role"] == "api-server"
                        and type(api["ordinal"]) is int and api["ordinal"] == 0
                        and api["pid"] == api_kernel["pid"]
                        and api["start_identity"] == f"pid:{api_kernel['pid']}:start_ticks:{api_kernel['start_ticks']}"
                        and canonical(accepted["kernel"]) == canonical(api_kernel),
                        "interrupted accepted peer differs from actual Host7/kernel4 API epoch")
            response_completions.append(row["received_monotonic_ns"])
            peer_exits.append(peer_exit)
            # A source-observed exact peer exit retains a negative/unknown
            # observation only. Independent root/cause binding is still needed.
            continue
        owner_exit = row.get("owner_terminal")
        if owner_exit is not None:
            require(type(owner_exit) is dict and set(owner_exit) == {"kind", "owner", "boot_id", "stat_raw", "before_raw_ns", "before_monotonic_ns", "after_raw_ns", "after_monotonic_ns"}
                    and canonical(owner_exit["owner"]) == canonical(owner) and owner_exit["boot_id"] == owner["boot_id"]
                    and all(type(owner_exit[k]) is int for k in ("before_raw_ns", "before_monotonic_ns", "after_raw_ns", "after_monotonic_ns"))
                    and row["sent_raw_ns"] <= owner_exit["before_raw_ns"] <= owner_exit["after_raw_ns"] <= row["finished_raw_ns"]
                    and row["sent_monotonic_ns"] <= owner_exit["before_monotonic_ns"] <= owner_exit["after_monotonic_ns"] <= row["finished_monotonic_ns"],
                    "original owner interruption identity/clocks changed")
            if owner_exit["kind"] == "original-owner-zombie":
                original = owner_exit["stat_raw"]
                require(type(original) is str, "zombie interruption lacks original stat")
                fields = original.rsplit(")", 1)[1].split()
                actual = dict(pid=int(original.split(" ", 1)[0]), start_ticks=int(fields[19]), session=int(fields[3]), boot_id=owner_exit["boot_id"])
                require(fields[0] == "Z" and canonical(actual) == canonical(owner), "owner zombie kernel changed")
            else:
                require(owner_exit["kind"] == "original-owner-stat-ENOENT" and owner_exit["stat_raw"] is None,
                        "unknown owner interruption cause")
            require(row["error"] is not None
                    and row["error"]["type"] == __name__ + ".HealthOwnerExited",
                    "owner exit lacks exact typed source transport outcome")
            owner_exits.append(owner_exit)
            if row["response"] is not None:
                require(accepted is not None and row["response_complete"] is True and row["after"] is None
                        and len(h4_decode_body(row["response"])) <= MAX_BODY
                        and type(row["response"]["status_code"]) is int,
                        "owner exit hides corrupt complete response")
                require(all(type(row[k]) is int for k in ("backend_sent_raw_ns", "backend_sent_monotonic_ns", "received_raw_ns", "received_monotonic_ns"))
                        and before["observed_raw_ns"] <= row["backend_sent_raw_ns"] <= row["received_raw_ns"] <= owner_exit["before_raw_ns"]
                        and before["observed_monotonic_ns"] <= row["backend_sent_monotonic_ns"] <= row["received_monotonic_ns"] <= owner_exit["before_monotonic_ns"],
                        "owner exit hides corrupt existing response clocks")
                response_completions.append(row["received_monotonic_ns"])
            # Every available before capture/body was checked; absent after
            # witness never becomes successful native/readiness authority.
            continue
        if row["response"] is None:
            require(row["error"] is not None and row["response_complete"] is False,
                    "missing health response lacks actual transport outcome")
            continue
        require(accepted is not None and row["response_complete"] is True and row["after"] is not None,
                "complete health response lacks complete physical peer witness")
        after = unpack(row["after"])
        after_rows = tree_rows(after, owner)
        require(canonical(after_rows.get(accepted["kernel"]["pid"])) == canonical(accepted["kernel"]),
                "health accepted process kernel changed after actual HTTP read")
        # Connection: close may remove the accepted FD/TCP entry immediately;
        # retain raw after bytes and forbid a conflicting still-established tuple.
        after_inodes = {line.split()[9] for line in after["tcp_raw"].splitlines()[1:]
                        if line.split()[1:4] == [tcp_address(row["peer"]), tcp_address(row["local"]), "01"]}
        require(not after_inodes or after_inodes == {accepted["inode"]}, "health TCP tuple changed after read")
        require(all(type(row[k]) is int for k in ("backend_sent_raw_ns", "backend_sent_monotonic_ns", "received_raw_ns", "received_monotonic_ns"))
                and before["observed_raw_ns"] <= row["backend_sent_raw_ns"] <= row["received_raw_ns"] <= after["observed_begin_raw_ns"] <= after["observed_raw_ns"] <= row["finished_raw_ns"]
                and before["observed_monotonic_ns"] <= row["backend_sent_monotonic_ns"] <= row["received_monotonic_ns"] <= after["observed_begin_monotonic_ns"] <= after["observed_monotonic_ns"] <= row["finished_monotonic_ns"],
                "health original send/receive/peer after clocks differ")
        response_completions.append(row["received_monotonic_ns"])
        body = h4_decode_body(row["response"])
        require(len(body) <= MAX_BODY and type(row["response"]["status_code"]) is int,
                "original health response bytes/status differ")
        if epoch is not None:
            api, api_kernel = epoch["roster"]["api-server/0"], epoch["kernels"]["api-server/0"]
            require(api["assignment_source"] == "host" and api["role"] == "api-server"
                    and type(api["ordinal"]) is int and api["ordinal"] == 0
                    and api["pid"] == api_kernel["pid"]
                    and api["start_identity"] == f"pid:{api_kernel['pid']}:start_ticks:{api_kernel['start_ticks']}"
                    and canonical(accepted["kernel"]) == canonical(api_kernel),
                    "original health accepted peer is not exact actual Host7+kernel4 API epoch")
        if row["error"] is None and row["response"]["status_code"] == 200 and row["received_monotonic_ns"] <= deadline:
            first_candidate = row["sequence"]
            if epoch is not None:
                first_authenticated = dict(status_code=200, observed_ns=row["received_raw_ns"],
                    observed_monotonic_ns=row["received_monotonic_ns"], sequence=row["sequence"],
                    accepted_api_socket_inode=accepted["inode"], probe_sent_raw_ns=row["sent_raw_ns"],
                    backend_sent_raw_ns=row["backend_sent_raw_ns"],
                    peer_capture_begin_raw_ns=before["observed_begin_raw_ns"], peer_capture_end_raw_ns=before["observed_raw_ns"],
                    acceptance_capture_count=len(row["before_attempts"]),
                    actual_api_host7=epoch["roster"]["api-server/0"],
                    actual_api_kernel4=accepted["kernel"])
    terminal = None
    if terminal_path.exists():
        require(terminal_path.resolve() == terminal_path and not terminal_path.is_symlink(), "unsafe health terminal path")
        terminal = json.loads(terminal_path.read_bytes())
        require(type(terminal) is dict and set(terminal) == {"schema", "reason", "failure", "first_success_sequence", "local_cancellations", "original_journal", "next_sequence", "last_event_sha256", "observed_raw_ns", "observed_monotonic_ns"}
                and type(terminal["next_sequence"]) is int
                and (terminal["first_success_sequence"] is None or type(terminal["first_success_sequence"]) is int)
                and (terminal["failure"] is None or type(terminal["failure"]) is str)
                and terminal["schema"] == TERMINAL and terminal["next_sequence"] == len(events)
                and terminal["last_event_sha256"] == previous
                and terminal["original_journal"] == dict(path=str(journal), sha256=hashlib.sha256(raw).hexdigest())
                and type(terminal["observed_raw_ns"]) is int and terminal["observed_raw_ns"] >= last_raw
                and type(terminal["observed_monotonic_ns"]) is int and terminal["observed_monotonic_ns"] >= last_mono
                and terminal["first_success_sequence"] == first_candidate, "health terminal differs from full original probes")
        require(type(terminal["local_cancellations"]) is list, "health local cancellation history missing")
        previous_cancel_mono = header["observed_monotonic_ns"]
        for item in terminal["local_cancellations"]:
            validate_local_cancel(item)
            require(type(item) is dict and set(item) == {"reason", "raw_ns", "monotonic_ns", "actual_socket_present", "shutdown_error", "shutdown_before_raw_ns", "shutdown_before_monotonic_ns", "shutdown_after_raw_ns", "shutdown_after_monotonic_ns"}
                    and item["reason"] in {"absolute-startup-deadline", "caller-finally-cancel", "join-finally-cleanup"}
                    and type(item["actual_socket_present"]) is bool
                    and type(item["raw_ns"]) is int and type(item["monotonic_ns"]) is int
                    and header["observed_raw_ns"] <= item["raw_ns"] <= terminal["observed_raw_ns"]
                    and previous_cancel_mono <= item["monotonic_ns"] <= terminal["observed_monotonic_ns"],
                    "health local cancellation raw clocks changed")
            require(not item["actual_socket_present"] or
                    (item["shutdown_after_raw_ns"] <= terminal["observed_raw_ns"]
                     and item["shutdown_after_monotonic_ns"] <= terminal["observed_monotonic_ns"]),
                    "socket shutdown extends beyond original terminal")
            previous_cancel_mono = item["monotonic_ns"]
            if item["shutdown_error"] is not None:
                require(type(item["shutdown_error"]) is dict and set(item["shutdown_error"]) == {"type", "errno", "message"}
                        and type(item["shutdown_error"]["type"]) is str
                        and type(item["shutdown_error"]["errno"]) is int
                        and type(item["shutdown_error"]["message"]) is str, "health shutdown error malformed")
            require(not item["actual_socket_present"] or all(completed < item["monotonic_ns"] for completed in response_completions),
                    "local shutdown EOF cannot prove response completion")
        require(all(any(canonical(item) == canonical(recorded) for recorded in terminal["local_cancellations"])
                    for item in local_cancel_rows), "probe cancellation absent from original terminal")
        require((terminal["reason"] == "accepted-peer-exited") is bool(peer_exits), "accepted peer exit terminal differs from raw observation")
        require((terminal["reason"] == "owner-exited") is bool(owner_exits), "owner exit terminal differs from raw original observation")
        require((terminal["reason"] == "success") is (first_candidate is not None)
                and terminal["reason"] in {"success", "deadline", "cancelled", "error", "owner-exited", "accepted-peer-exited"}, "health completion status differs")
        if terminal["reason"] == "deadline":
            require(terminal["observed_monotonic_ns"] >= deadline, "health timeout before original startup deadline")
        if terminal["failure"] is not None:
            raise HealthEvidenceError("health source observer failed: " + terminal["failure"])
    else:
        require(not require_terminal, "complete slot lacks joined original health terminal")
    return dict(schema="ecpa-h4-first-authenticated-observed-health/v1", first_health=first_authenticated,
        original_journal=dict(path=str(journal), sha256=hashlib.sha256(raw).hexdigest()),
        original_terminal=dict(path=str(terminal_path), sha256=hashlib.sha256(terminal_path.read_bytes()).hexdigest()) if terminal is not None else None,
        product_owner=owner, product_popen_before_raw_ns=timing["before_ns"], deadline_ns=deadline,
        observer_started_raw_ns=header["observed_raw_ns"], poll_interval_seconds=POLL_SECONDS,
        per_operation_io_timeout_seconds=IO_SECONDS,
        observed_time_scope="Popen-to-first-authenticated-observed-health200 upper bound; no instantaneous-ready claim",
        owner_exit_observations=owner_exits,
        accepted_peer_exit_observations=peer_exits,
        local_cancellations=terminal["local_cancellations"] if terminal is not None else None,
        requires_authenticated_runtime_failure=bool(owner_exits or peer_exits),
        probe_count=len(events) - 1, API_epoch_status="unknown-owner-exited" if owner_exits else ("unknown-accepted-peer-exited" if peer_exits else ("verified" if epoch is not None else "unknown-no-enrollment")),
        completion_status=terminal["reason"] if terminal is not None else "incomplete-original-prefix")
