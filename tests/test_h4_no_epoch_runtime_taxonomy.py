"""Unrun CPU regression source; source-admitted start/root cleanup still mandatory."""

from __future__ import annotations

import copy
import hashlib
import json
import signal
import subprocess
import sys
import time

import pytest

from experiments.formal_campaign import h4_sampled_intake as intake
from experiments.formal_campaign import h4_sampled_root_observer as observer
from experiments.formal_campaign.run_h4_sampled import runtime_interruption


def admission():
    return dict(before_monotonic_ns=1, after_ns=1)


def timeout_outcome():
    event = runtime_interruption(TimeoutError("actual original budget expired"))
    return dict(
        schema="ecpa-h4-sampled-live-source-observation/v1",
        failure="TimeoutError: actual original budget expired",
        failure_category="runtime-interruption",
        runtime_interruption=event,
        failure_observed_monotonic_ns=time.monotonic_ns(),
        failure_observed_raw_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW),
    )


@pytest.mark.parametrize("code", [0, 1, 2, -signal.SIGTERM])
def test_present_verification_error_never_overridden_by_exit(code):
    outcome = dict(
        schema="ecpa-h4-sampled-live-source-observation/v1",
        failure_category="unqualified-verification-error",
        failure="ValueError: schema",
    )
    with pytest.raises(ValueError, match="unqualified"):
        intake.no_epoch_runtime_cause(
            outcome, dict(released=True, runner_exit_code=code), {}, [], admission()
        )


@pytest.mark.parametrize("code", [0, 1, 2])
def test_missing_outcome_generic_exit_is_not_runtime_cause(code):
    with pytest.raises(ValueError, match="missing cause"):
        intake.no_epoch_runtime_cause(
            None, dict(released=True, runner_exit_code=code), {}, [], admission()
        )


def test_real_timeout_classification_is_typed_and_no_message_guessing():
    outcome = timeout_outcome()
    cause = intake.no_epoch_runtime_cause(
        outcome, dict(released=True, runner_exit_code=0), {}, [], admission()
    )
    assert cause["kind"] == "source-observed-runtime-interruption"
    assert cause["source"]["exception_type"] == "builtins.TimeoutError"
    assert runtime_interruption(ValueError("TimeoutError: pretend timeout")) is None


@pytest.mark.parametrize("mutate", ["family", "class", "clock", "untyped"])
def test_corrupt_or_untyped_source_cause_still_rejects(mutate):
    outcome = timeout_outcome()
    if mutate == "family":
        outcome["runtime_interruption"]["family"] = "ABI-error"
    elif mutate == "class":
        outcome["runtime_interruption"]["exception_type"] = "builtins.ValueError"
    elif mutate == "clock":
        outcome["runtime_interruption"]["observed_monotonic_ns"] = True
    else:
        del outcome["runtime_interruption"]
    with pytest.raises(ValueError):
        intake.no_epoch_runtime_cause(
            outcome, dict(released=True, runner_exit_code=0), {}, [], admission()
        )


def actual_signal_witness(tmp_path):
    # An actual throwaway CPU child self-terminates only when this future test is
    # explicitly authorized/executed. No product PID or external process signal.
    argv = [
        sys.executable,
        "-c",
        ("import os,signal,sys; print('ready',flush=True); "
         "sys.stdin.readline(); os.kill(os.getpid(),signal.SIGTERM)"),
    ]
    child = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout.readline().strip() == "ready"
        owner = observer.kernel(child.pid)
        launch = dict(
            argv=argv, kernel=owner, observed_monotonic_ns=time.monotonic_ns()
        )
        path = tmp_path / "actual-runner-Popen.json"
        path.write_text(json.dumps(launch))
        child.stdin.write("terminate\n")
        child.stdin.flush()
        code = child.wait(timeout=5)
        assert code == -signal.SIGTERM
        ref = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        terminal = observer.runner_terminal(code, owner, ref, time.monotonic_ns())
        root = dict(
            released=True,
            runner_exit_code=code,
            runner_terminal=terminal,
            all_observed_epochs=[owner],
        )
        return root, dict(path=str(tmp_path / "independent-root-terminal.json")), argv
    finally:
        if child.poll() is None:
            child.stdin.close()
            child.wait(timeout=5)


def test_actual_negative_popen_signal_is_bound_to_original_kernel_and_launch(tmp_path):
    root, ref, argv = actual_signal_witness(tmp_path)
    cause = intake.no_epoch_runtime_cause(None, root, ref, argv, admission())
    assert cause["kind"] == "independently-observed-runner-signal"
    assert cause["terminal"]["signal"] == signal.SIGTERM
    bad = copy.deepcopy(root)
    bad["runner_terminal"]["kernel"]["start_ticks"] += 1
    with pytest.raises(ValueError, match="kernel"):
        intake.no_epoch_runtime_cause(None, bad, ref, argv, admission())
    with pytest.raises(ValueError, match="kernel"):
        intake.no_epoch_runtime_cause(
            None, root, ref, argv + ["wrong-original-start"], admission()
        )


def test_timeout_or_signal_never_overrides_failed_independent_cleanup():
    with pytest.raises(ValueError, match="cleanup"):
        intake.no_epoch_runtime_cause(
            timeout_outcome(),
            dict(released=False, runner_exit_code=-15),
            {},
            [],
            admission(),
        )
