"""Prospective real-fault delivery window; never formal or execution qualification.

The authority must be the source-pinned actual-forward loopback authority. The
finite cached-response controllers intentionally cannot supply this interface.
This adapter owns only its client process and an explicitly owned fault target;
it does not create or recover a model server, enroll future worker identities,
issue semantic permits, or weaken any existing formal gate.
"""

from __future__ import annotations

import base64
import json
import os
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

from experiments.exposure_gate.loopback_traffic import read_traffic_journal
from experiments.formal_campaign import h3_client_trace as trace
from experiments.formal_campaign.analyze import h3_response_correctness


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def kernel(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    require(fields[0] != "Z", "kernel is no longer live")
    return {
        "pid": pid,
        "start_ticks": int(fields[19]),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "session": int(fields[3]),
    }


def current(identity):
    try:
        return kernel(identity["pid"]) == identity
    except (OSError, ValueError):
        return False


def owned_descendant(pid):
    seen = set()
    while pid > 1 and pid not in seen:
        if pid == os.getpid():
            return True
        seen.add(pid)
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        pid = int(fields[1])
    return False


def save_new(path, value):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(trace.canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


class ProspectiveClientWindow:
    """Compose the existing finite client/verifier around an actual owned fault.

    ``spec`` and source references are frozen before ``start``. Backend process
    registrations must already contain their actual kernels; guessing a future
    replacement PID is forbidden. Dynamic membership enrollment is a separate
    prerequisite. All delivery/execution accounting retains its original scope.
    """

    def __init__(self, spec, output, *, authority_source, client_source):
        trace.validate_spec(spec)
        self.spec = json.loads(trace.canonical(spec))
        self.output = Path(output)
        require(not self.output.exists(), "window output must be fresh")
        self.authority_source = dict(authority_source)
        self.client_source = dict(client_source)
        require(
            Path(client_source["path"]).resolve() == Path(trace.__file__).resolve(),
            "different client implementation",
        )
        from experiments.exposure_gate import loopback_traffic

        require(
            Path(authority_source["path"]).resolve()
            == Path(loopback_traffic.__file__).resolve(),
            "cached or unsupported authority source",
        )
        self._sources_current()
        authority = self.spec.get("authority_process_identity")
        require(isinstance(authority, dict), "actual authority identity required")
        self.authority = kernel(authority["pid"])
        require(
            all(
                self.authority[k] == authority[k]
                for k in ("pid", "start_ticks", "boot_id")
            ),
            "authority epoch differs",
        )
        require(self.authority["pid"] != os.getpid(), "authority must be independent")
        arguments = (
            Path(f"/proc/{self.authority['pid']}/cmdline").read_bytes().split(b"\0")
        )
        source_argument = str(Path(authority_source["path"]).resolve()).encode()
        module_launch = any(
            arguments[index : index + 2]
            == [b"-m", b"experiments.exposure_gate.loopback_traffic"]
            for index in range(len(arguments) - 1)
        )
        require(
            source_argument in arguments or module_launch,
            "authority process did not launch the pinned forwarding source",
        )
        registrations = self.spec.get("backend_registration")
        require(
            isinstance(registrations, dict) and registrations,
            "actual backend registrations required",
        )
        self.process = None
        self.log = None
        self.client_pidfd = None
        self.client = None
        self.fault = None
        self.recovery = None
        self.finished = False

    def _sources_current(self):
        for reference in (self.authority_source, self.client_source):
            require(
                trace.sha(Path(reference["path"]).read_bytes()) == reference["sha256"],
                "window source drifted",
            )

    def start(self, *, ready_timeout_s=15):
        require(self.process is None, "window cannot restart")
        require(current(self.authority), "authority epoch gone before client launch")
        self._sources_current()
        self.output.mkdir(mode=0o700)
        self.output.chmod(0o700)
        save_new(self.output / "spec.json", self.spec)
        save_new(
            self.output / "source-ownership.json",
            {
                "authority": self.authority,
                "authority_source": self.authority_source,
                "client_source": self.client_source,
                "runner_source_sha256": trace.sha(Path(__file__).read_bytes()),
                "formal_result": False,
            },
        )
        # Run the exact source file, not a sitecustomize or caller-provided command.
        try:
            self.log = (self.output / "client.log").open("xb")
            self.process = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(trace.__file__).resolve()),
                    "--spec",
                    str(self.output / "spec.json"),
                    "--trace",
                    str(self.output / "client.jsonl"),
                    "--ready",
                    str(self.output / "client-ready.json"),
                ],
                stdout=self.log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            self.client_pidfd = os.pidfd_open(self.process.pid)
            self.client = kernel(self.process.pid)
            deadline = time.monotonic() + ready_timeout_s
            while time.monotonic() < deadline:
                require(self.process.poll() is None, "client exited before ready")
                ready = self.output / "client-ready.json"
                if ready.exists():
                    try:
                        value = json.loads(ready.read_bytes())
                    except json.JSONDecodeError:
                        time.sleep(0.01)
                        continue
                    require(
                        value["client"]
                        == {
                            k: self.client[k] for k in ("pid", "start_ticks", "boot_id")
                        },
                        "client ready epoch differs",
                    )
                    events = trace.read_client_trace(self.output / "client.jsonl")
                    require(
                        events[0]["detail"]["spec_sha256"]
                        == trace.sha(trace.canonical(self.spec)),
                        "client spec binding differs",
                    )
                    save_new(self.output / "client-kernel.json", self.client)
                    return dict(self.client)
                time.sleep(0.01)
            raise TimeoutError("client ready timed out")
        except BaseException as error:
            self._close_preserving(error)
            raise

    def observe_owned_fault(
        self, *, target, launcher, fault_signal=signal.SIGTERM, exit_timeout_s=30
    ):
        require(
            self.process is not None and self.process.poll() is None,
            "client must be live across fault",
        )
        require(self.fault is None, "fault already observed")
        self._sources_current()
        require(
            current(launcher) and current(target), "fault target/launcher epoch differs"
        )
        require(
            target["session"] == launcher["pid"] == launcher["session"],
            "fault target outside launcher session",
        )
        require(
            launcher["pid"] != os.getpid()
            and owned_descendant(launcher["pid"])
            and owned_descendant(target["pid"]),
            "fault process is not owned by this runner",
        )
        require(
            target["pid"] not in (self.client["pid"], self.authority["pid"]),
            "client/authority cannot be this backend fault target",
        )
        affected_ports = []
        for port, binding in self.spec["backend_registration"].items():
            identity = binding.get("process_identity", {})
            try:
                actual = kernel(identity["pid"])
            except (KeyError, OSError, ValueError):
                continue
            require(
                all(
                    actual[k] == identity[k] for k in ("pid", "start_ticks", "boot_id")
                ),
                "registered backend changed before fault",
            )
            if actual["session"] == target["session"]:
                affected_ports.append(port)
        require(affected_ports, "fault target is outside registered backend sessions")
        events = trace.read_client_trace(self.output / "client.jsonl")
        require(
            any(event["kind"] == "request.start" for event in events),
            "client has not dispatched a prefault request",
        )
        require(
            fault_signal in (signal.SIGTERM, signal.SIGKILL), "unsupported fault signal"
        )
        descriptor = os.pidfd_open(target["pid"])
        try:
            require(
                current(target) and current(launcher),
                "fault epoch changed before signal",
            )
            sent_ns = time.monotonic_ns()
            signal.pidfd_send_signal(descriptor, fault_signal)
        finally:
            os.close(descriptor)
        deadline = time.monotonic() + exit_timeout_s
        while current(target) and time.monotonic() < deadline:
            time.sleep(0.01)
        require(not current(target), "actual fault target did not exit")
        self.fault = {
            "signal_sent_ns": sent_ns,
            "target_gone_ns": time.monotonic_ns(),
            "target": target,
            "launcher": launcher,
            "signal": int(fault_signal),
            "affected_backend_ports": affected_ports,
        }
        save_new(self.output / "actual-fault.json", self.fault)
        return dict(self.fault)

    def derive_recovery(self, authority_path):
        """Select a real forwarding completion, never accept a supplied time."""
        require(self.fault is not None, "actual fault must precede recovery")
        self._sources_current()
        require(current(self.authority), "authority epoch changed")
        events = read_traffic_journal(Path(authority_path))
        first = events[0]
        require(
            first["kind"] == "authority.start", "actual-forward authority start absent"
        )
        require(
            all(
                event.get("proxy_" + k) == self.authority[k]
                for event in events
                for k in ("pid", "start_ticks", "boot_id")
            ),
            "authority trace epoch differs",
        )
        require(
            first["detail"].get("backend_registration_sha256")
            == trace.sha(trace.canonical(self.spec["backend_registration"])),
            "backend enrollment differs",
        )
        prefix = self.spec["start_id"] + "/request-"
        for event in events:
            detail = event["detail"]
            if (
                event["kind"] != "request.complete"
                or event["monotonic_ns"] <= self.fault["target_gone_ns"]
                or detail.get("status") != 200
                or not detail.get("request_id", "").startswith(prefix)
            ):
                continue
            admissions = [
                e
                for e in events
                if e["kind"] == "request.admit"
                and e["detail"].get("request_id") == detail["request_id"]
                and e["detail"].get("admission_id") == detail.get("admission_id")
            ]
            require(
                len(admissions) == 1
                and admissions[0]["detail"].get("request_sha256")
                == trace.sha(trace.canonical(self.spec["payload"]))
                and admissions[0]["monotonic_ns"] < event["monotonic_ns"]
                and admissions[0]["sequence"] < event["sequence"],
                "recovery lacks unique chronological fresh request admission",
            )
            if admissions[0]["monotonic_ns"] <= self.fault["target_gone_ns"]:
                # A legitimate in-flight request can finish after the fault. It
                # cannot establish recovery; continue to a fresh postfault one.
                continue
            binding = self.spec["backend_registration"].get(
                str(detail.get("backend_port"))
            )
            observed = detail.get("backend_identity")
            require(
                isinstance(binding, dict) and isinstance(observed, dict),
                "completion lacks real backend enrollment",
            )
            require(
                {k: v for k, v in observed.items() if k != "listener_inode"} == binding,
                "completion backend epoch differs",
            )
            require(
                str(observed.get("listener_inode", "")).isdigit()
                and binding["generation"] == event["route"]["generation"],
                "backend listener/generation differs",
            )
            expected_kernel = binding["process_identity"]
            backend = kernel(expected_kernel["pid"])
            require(
                all(
                    backend[k] == expected_kernel[k]
                    for k in ("pid", "start_ticks", "boot_id")
                ),
                "recovery backend epoch is not current",
            )
            require(
                backend["session"] != self.fault["target"]["session"],
                "dead backend session cannot count as recovered generation",
            )
            response = base64.b64decode(detail["body_base64"], validate=True)
            require(
                trace.sha(response) == detail["body_sha256"],
                "recovery response bytes differ",
            )
            parsed = json.loads(response)
            require(
                h3_response_correctness(
                    parsed, self.spec["payload"], self.spec["response_expectation"]
                ),
                "forwarded recovery fails frozen functional oracle",
            )
            response_id = parsed.get("id")
            require(
                isinstance(response_id, str) and bool(response_id),
                "recovery response identity missing",
            )
            previous_ids = []
            for previous in events:
                if previous["sequence"] >= event["sequence"]:
                    break
                if (
                    previous["kind"] == "request.complete"
                    and previous["detail"].get("status") == 200
                ):
                    prior = json.loads(
                        base64.b64decode(
                            previous["detail"]["body_base64"], validate=True
                        )
                    )
                    previous_ids.append(prior.get("id"))
            require(
                response_id not in previous_ids,
                "cached/reused response identity cannot establish recovery",
            )
            self.recovery = {
                "monotonic_ns": event["monotonic_ns"],
                "authority_event_sequence": event["sequence"],
                "request_id": detail["request_id"],
                "admission_id": detail["admission_id"],
                "backend": binding,
                "authority_event_sha256": trace.sha(trace.canonical(event)),
                "scope": (
                    "actual-forward-delivery-only; native execution "
                    "remains independently unverified"
                ),
            }
            save_new(self.output / "forwarding-recovery.json", self.recovery)
            return dict(self.recovery)
        raise ValueError("no source-owned postfault fresh forwarded response")

    def finish(self, authority_path, *, timeout_s=60):
        try:
            require(
                self.process is not None and not self.finished,
                "window not active or already finalized",
            )
            require(
                self.fault is not None and self.recovery is not None,
                "actual fault and forwarding-derived recovery required",
            )
            self.process.wait(timeout=timeout_s)
            require(
                self.process.returncode == 0, "client failed; retain original raw log"
            )
            self._sources_current()
            result = trace.verify_window(
                self.spec,
                self.output / "client.jsonl",
                Path(authority_path),
                expected_client={
                    k: self.client[k] for k in ("pid", "start_ticks", "boot_id")
                },
                fault_ns=self.fault["signal_sent_ns"],
                recovery_ns=self.recovery["monotonic_ns"],
            )
            require(
                result.get("backend_execution_duplicates") is None,
                "delivery accounting cannot claim execution duplicates",
            )
            result.update(
                classification="PROSPECTIVE_ACTUAL_FAULT_DELIVERY_WINDOW_NONFORMAL",
                formal_result=False,
                fresh_backend_execution_qualification=None,
                additional_formal_starts=0,
            )
            save_new(self.output / "result.json", result)
            self.finished = True
            return result
        except BaseException as error:
            self._close_preserving(error)
            raise
        finally:
            # The successful path also reclaims descriptors and closes its log.
            if self.finished:
                self.close()

    def _close_preserving(self, original):
        try:
            self.close()
        except BaseException as cleanup:
            # Keep the operation's original type/message/traceback authoritative.
            original.cleanup_error = repr(cleanup)
            if hasattr(original, "add_note"):
                original.add_note("client cleanup also failed: " + repr(cleanup))

    def _signal_client(self, value):
        if self.process is None or self.process.poll() is not None:
            return
        if self.client is not None and not current(self.client):
            return
        if self.client_pidfd is not None:
            with suppress(ProcessLookupError):
                signal.pidfd_send_signal(self.client_pidfd, value)
        else:
            # Before the first kernel lookup, this is our unreaped Popen child.
            # Popen.send_signal rechecks returncode; an unreaped child PID cannot
            # be reused. Never fall back to signaling any caller-supplied PID.
            self.process.send_signal(value)

    def close(self):
        """Idempotently reclaim only the Popen client and its descriptors."""
        try:
            if self.process is not None:
                self._signal_client(signal.SIGTERM)
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._signal_client(signal.SIGKILL)
                    self.process.wait(timeout=5)
        finally:
            try:
                if self.client_pidfd is not None:
                    os.close(self.client_pidfd)
                    self.client_pidfd = None
            finally:
                if self.log is not None:
                    self.log.close()
