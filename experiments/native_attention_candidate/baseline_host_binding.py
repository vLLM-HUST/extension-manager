"""Authenticated baseline Host callbacks; activation observations are not effects.

The owner creates HostObserver, starts the actual Host with environment(), then
attaches its Popen kernel identity. finalize() joins raw callbacks to the later
Host-assigned API/TP2 peers. No Manager handoff, Plan execution or admission is
created. Host and in-process plugins retain their existing non-adversarial trust
boundary; SO_PEERCRED authenticates a process, not arbitrary Python call stacks.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import stat
import struct
import threading
import time
from pathlib import Path

from vllm_hust_ext import activation_profile as profiles
from vllm_hust_ext.runtime_phase_handoff import process_identity

SCHEMA = "ecpa-baseline-host-observer/v1"
SINK = __name__ + ":record_event"
SOCKET_ENV = "ECPA_BASELINE_HOST_OBSERVER_SOCKET"
TRIAL_ENV = "ECPA_BASELINE_HOST_OBSERVER_TRIAL"
OWNER_ENV = "ECPA_BASELINE_HOST_OBSERVER_OWNER"
LIMIT = 256 * 1024
ARMS = {"entry-points-unmanaged", "explicit-manual-hooks"}


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def _receive(connection):
    raw = b""
    while not raw.endswith(b"\n"):
        data = connection.recv(min(4096, LIMIT + 1 - len(raw)))
        require(
            data and len(raw) + len(data) <= LIMIT,
            "observer frame incomplete/oversized",
        )
        raw += data
    require(raw.count(b"\n") == 1, "observer frame has trailing data")
    return json.loads(raw)


def _send(connection, value):
    raw = canonical(value) + b"\n"
    require(len(raw) <= LIMIT, "observer frame oversized")
    connection.sendall(raw)


def _peer(connection):
    pid, uid, _ = struct.unpack(
        "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    require(uid == os.geteuid(), "observer peer uid differs")
    return process_identity(pid)


def _socket(path):
    p = Path(path)
    require(
        p.is_absolute() and p.parent.resolve() == p.parent and not p.is_symlink(),
        "observer socket path differs",
    )
    parent, meta = p.parent.stat(), p.lstat()
    require(
        parent.st_uid == meta.st_uid == os.geteuid()
        and not stat.S_IMODE(parent.st_mode) & 0o077
        and stat.S_ISSOCK(meta.st_mode)
        and stat.S_IMODE(meta.st_mode) == 0o600,
        "observer socket ownership/mode differs",
    )
    return {"device": meta.st_dev, "inode": meta.st_ino}


def _environment(pid):
    return dict(
        part.split(b"=", 1)
        for part in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
        if b"=" in part
    )


def _ancestors(pid):
    identities = []
    while pid > 1 and len(identities) < 128:
        identity = process_identity(pid)
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        parent = int(fields[1])
        require(process_identity(pid) == identity, "observer ancestry epoch changed")
        identities.append(identity)
        pid = parent
    return identities


def record_event(payload):
    """Actual Host sink: one new owner challenge and strict ACK per callback."""
    path = Path(os.environ[SOCKET_ENV])
    trial = os.environ[TRIAL_ENV]
    owner = json.loads(os.environ[OWNER_ENV])
    profile = profiles.profile_from_environment()
    require(profile is not None, "baseline observer profile missing")
    profile.bind_environment()
    before = _socket(path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(15)
        connection.connect(str(path))
        require(
            _peer(connection) == owner and process_identity(owner["pid"]) == owner,
            "observer owner epoch differs",
        )
        challenge = _receive(connection)
        require(
            set(challenge) == {"schema", "trial", "nonce", "socket"}
            and challenge["schema"] == SCHEMA
            and challenge["trial"] == trial
            and challenge["socket"] == before
            and isinstance(challenge["nonce"], str)
            and len(challenge["nonce"]) == 64,
            "observer challenge differs",
        )
        require(_socket(path) == before, "observer socket replaced")
        envelope = {
            "schema": SCHEMA,
            "trial": trial,
            "nonce": challenge["nonce"],
            "profile_sha256": profile.sha256,
            "sender": process_identity(os.getpid()),
            "payload": payload,
            "observer_source": {
                "path": str(Path(__file__).resolve()),
                "sha256": digest(Path(__file__).read_bytes()),
            },
        }
        _send(connection, envelope)
        ack = _receive(connection)
        require(
            ack
            == {
                "schema": SCHEMA,
                "trial": trial,
                "nonce": challenge["nonce"],
                "record_sha256": digest(canonical(envelope)),
            },
            "observer acknowledgement differs",
        )
        require(
            _peer(connection) == owner and _socket(path) == before,
            "observer owner/socket changed",
        )


class HostObserver:
    """Owner-side authenticated callback capture, with no durable coordinator."""

    def __init__(self, socket_path, journal_path, *, profile, arm, host_sources):
        require(arm in ARMS, "unsupported baseline arm")
        require(
            isinstance(profile, profiles.ActivationProfile),
            "explicit activation profile required",
        )
        profile.validate_installed()
        self.profile, self.arm = profile, arm
        self.owner = process_identity(os.getpid())
        self.trial = "baseline-trial:" + secrets.token_hex(32)
        self.host_sources = dict(host_sources)
        self.observer_source = {
            "path": str(Path(__file__).resolve()),
            "sha256": digest(Path(__file__).read_bytes()),
        }
        # Pin both the actual stock loader and its callback dispatcher.
        from importlib import metadata

        dist = metadata.distribution("vllm")
        expected = {
            str(Path(str(dist.locate_file(p))).resolve())
            for p in (
                "vllm/plugins/__init__.py",
                "vllm/plugins/evidence.py",
                "vllm/entrypoints/cli/main.py",
                "vllm/v1/executor/multiproc_executor.py",
                "vllm/v1/engine/core.py",
            )
        }
        require(set(self.host_sources) == expected, "baseline Host source roles differ")
        self._sources_current()
        self.path = Path(socket_path)
        parent = self.path.parent
        require(
            self.path.is_absolute()
            and parent.resolve() == parent
            and not self.path.exists()
            and not self.path.is_symlink(),
            "observer socket not fresh/canonical",
        )
        require(
            parent.stat().st_uid == os.geteuid()
            and not stat.S_IMODE(parent.stat().st_mode) & 0o077,
            "observer parent not private",
        )
        self.journal_path = Path(journal_path)
        require(self.journal_path.parent == parent, "observer journal parent differs")
        self.journal = os.open(
            self.journal_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        self.path.chmod(0o600)
        self.listener.listen(32)
        self.listener.settimeout(0.1)
        self.socket_identity = _socket(self.path)
        self.host = None
        self.attached = threading.Event()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.records = []
        self.failures = []
        self.previous = "0" * 64
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _sources_current(self):
        self.profile.validate_installed()
        for name, expected in (
            self.host_sources
            | {self.observer_source["path"]: self.observer_source["sha256"]}
        ).items():
            p = Path(name)
            require(
                p.is_absolute()
                and p.resolve() == p
                and not p.is_symlink()
                and digest(p.read_bytes()) == expected,
                "baseline Host source bytes differ",
            )

    def environment(self):
        """Merge into the real child environment before exec; never Manager IDs."""
        return {
            SOCKET_ENV: str(self.path),
            TRIAL_ENV: self.trial,
            OWNER_ENV: canonical(self.owner).decode(),
            profiles.PATH_ENV: str(self.profile.path),
            profiles.SHA_ENV: self.profile.sha256,
            profiles.ENABLE_ENV: "1",
            profiles.CONFIG_ENV: profiles.canonical(
                self.profile.configuration
            ).decode(),
            "VLLM_ECPA_EVIDENCE_SINK": SINK,
            "VLLM_ECPA_EVIDENCE_STRICT": "1",
            "ECPA_ACTIVATION_CONTRACT": self.arm,
            "VLLMHUST_EXT_ENABLED_BUNDLES": "",
        }

    def attach_host(self, host):
        require(
            self.host is None and process_identity(host["pid"]) == host,
            "baseline Host attachment differs",
        )
        require(
            self.owner in _ancestors(host["pid"])[1:],
            "baseline Host is not owned descendant",
        )
        self.host = dict(host)
        self.attached.set()

    def _sender_current(self, sender):
        require(
            process_identity(sender["pid"]) == sender, "baseline sender epoch changed"
        )
        chain = _ancestors(sender["pid"])
        require(
            self.host in chain and self.owner in chain,
            "baseline sender outside owned Host subtree",
        )
        actual = _environment(sender["pid"])
        expected = self.environment()
        expected.pop("VLLMHUST_EXT_ENABLED_BUNDLES")
        require(
            actual.get(b"VLLMHUST_EXT_ENABLED_BUNDLES") in (None, b""),
            "baseline inherited Manager bundles",
        )
        for key, value in expected.items():
            require(
                actual.get(key.encode()) == value.encode(),
                "baseline sender environment differs",
            )
        self._sources_current()
        return chain

    def _accept(self, connection):
        require(self.attached.wait(10), "baseline Host not attached")
        sender = _peer(connection)
        ancestors = self._sender_current(sender)
        nonce = secrets.token_hex(32)
        _send(
            connection,
            {
                "schema": SCHEMA,
                "trial": self.trial,
                "nonce": nonce,
                "socket": self.socket_identity,
            },
        )
        envelope = _receive(connection)
        require(
            set(envelope)
            == {
                "schema",
                "trial",
                "nonce",
                "profile_sha256",
                "sender",
                "payload",
                "observer_source",
            }
            and envelope["schema"] == SCHEMA
            and envelope["trial"] == self.trial
            and envelope["nonce"] == nonce
            and envelope["profile_sha256"] == self.profile.sha256
            and envelope["sender"] == sender
            and envelope["observer_source"] == self.observer_source,
            "baseline callback challenge/identity differs",
        )
        payload = envelope["payload"]
        require(
            isinstance(payload, dict)
            and payload.get("schema") == "vllm-hust-plugin-evidence/0.1",
            "baseline Host callback schema differs",
        )
        process = payload["process"]
        require(
            process["pid"] == sender["pid"]
            and process["start_identity"]
            == f"pid:{sender['pid']}:start_ticks:{sender['start_ticks']}"
            and type(process["process_epoch"]) is int
            and process["process_epoch"]
            == int(
                hashlib.sha256(process["start_identity"].encode()).hexdigest()[:12], 16
            ),
            "baseline callback process differs",
        )
        require(
            _peer(connection) == sender and self._sender_current(sender) == ancestors,
            "baseline sender changed during callback",
        )
        require(_socket(self.path) == self.socket_identity, "observer socket replaced")
        row = {
            "schema": SCHEMA,
            "sequence": len(self.records),
            "previous_sha256": self.previous,
            "received_monotonic_ns": time.monotonic_ns(),
            "envelope": envelope,
            "kernel": sender,
            "ancestors": ancestors,
            "cmdline_sha256": digest(
                Path(f"/proc/{sender['pid']}/cmdline").read_bytes()
            ),
        }
        row["sha256"] = digest(canonical(row))
        raw = canonical(row) + b"\n"
        with self.lock:
            view = memoryview(raw)
            while view:
                count = os.write(self.journal, view)
                require(count > 0, "baseline journal write failed")
                view = view[count:]
            os.fsync(self.journal)
            self.records.append(row)
            self.previous = row["sha256"]
        _send(
            connection,
            {
                "schema": SCHEMA,
                "trial": self.trial,
                "nonce": nonce,
                "record_sha256": digest(canonical(envelope)),
            },
        )

    def _serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self.stop.is_set():
                    return
                raise
            with connection:
                connection.settimeout(10)
                try:
                    self._accept(connection)
                except Exception as exc:
                    with self.lock:
                        self.failures.append(str(exc))

    def finalize(self, peers):
        """Join later Host-assigned peers; callbacks alone never prove effects."""
        self._sources_current()
        require(
            self.host is not None and process_identity(self.host["pid"]) == self.host,
            "baseline Host epoch gone",
        )
        require(
            {(p["process"]["role"], p["process"]["ordinal"]) for p in peers}
            == {("api-server", 0), ("worker", 0), ("worker", 1)}
            and len(peers) == 3,
            "baseline API/TP2 membership differs",
        )
        require(
            len({p["process"]["pid"] for p in peers}) == 3,
            "baseline API/TP2 requires three distinct live process identities",
        )
        with self.lock:
            require(
                not self.failures, "baseline ingress rejected: " + repr(self.failures)
            )
            records = json.loads(canonical(self.records))
            journal_raw = self.journal_path.read_bytes()
            require(
                journal_raw == b"".join(canonical(row) + b"\n" for row in records),
                "baseline captured journal differs",
            )
        joined = []
        for peer in peers:
            p = peer["process"]
            require(
                p["assignment_source"] == "host",
                "baseline final role is not Host-assigned",
            )
            kernel = process_identity(p["pid"])
            require(
                all(p.get(k) == v for k, v in kernel.items()),
                "baseline final peer kernel differs",
            )
            self._sender_current(kernel)
            events = [row for row in records if row["kernel"] == kernel]
            require(
                any(
                    row["envelope"]["payload"]["process"]
                    == {k: p[k] for k in row["envelope"]["payload"]["process"]}
                    and row["envelope"]["payload"]["process"]["assignment_source"]
                    == "host"
                    for row in events
                ),
                "early environment role lacks later authenticated Host assignment",
            )
            target = [
                row
                for row in events
                if row["envelope"]["payload"].get("entry_point")
                == {
                    "group": profiles.GROUP,
                    "name": profiles.NAME,
                    "value": profiles.VALUE,
                }
            ]
            resolved = [
                row
                for row in target
                if row["envelope"]["payload"]["event"] == "resolved"
                and row["envelope"]["payload"].get("detail")
                == (
                    None
                    if self.arm == "entry-points-unmanaged"
                    else "baseline-explicit-callable"
                )
            ]
            invoked = [
                row
                for row in target
                if row["envelope"]["payload"]["event"] == "invoked"
            ]
            require(
                resolved
                and invoked
                and resolved[0]["sequence"] < invoked[-1]["sequence"]
                and not any(
                    row["envelope"]["payload"]["event"] == "failed" for row in target
                ),
                "baseline target activation chain absent/failed/wrong arm",
            )
            joined.append(
                {
                    "process": p,
                    "kernel": kernel,
                    "activation_resolved_sequence": resolved[0]["sequence"],
                    "activation_invoked_sequence": invoked[-1]["sequence"],
                }
            )
        return {
            "schema": SCHEMA,
            "origin": "baseline-host-observer",
            "arm": self.arm,
            "observer_trial_id": self.trial,
            "owner": self.owner,
            "host": self.host,
            "peers": joined,
            "activation_profile_sha256": self.profile.sha256,
            "host_sources": self.host_sources,
            "observer_source": self.observer_source,
            "socket": self.socket_identity,
            "journal": {
                "path": str(self.journal_path),
                "sha256": digest(journal_raw),
                "prefix_bytes": len(journal_raw),
                "records": len(records),
                "last_sha256": records[-1]["sha256"],
            },
            "activation_only": True,
            "effect_qualification": None,
            "formal_result": False,
        }

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(12)
        require(not self.thread.is_alive(), "baseline observer thread did not stop")
        os.close(self.journal)
