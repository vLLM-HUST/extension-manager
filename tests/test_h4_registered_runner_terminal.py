"""Unrun source tests: every registered positive/negative checks root wait facts."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import time

import pytest

from experiments.formal_campaign import h4_sampled_intake as intake
from experiments.formal_campaign import h4_sampled_root_observer as observer


@pytest.fixture
def normal_exit(tmp_path):
    argv = [
        sys.executable,
        "-c",
        "import sys; print('ready',flush=True); sys.stdin.readline(); sys.exit(0)",
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
        path = tmp_path / "actual-runner-Popen.json"
        path.write_text(
            json.dumps(
                dict(argv=argv, kernel=owner, observed_monotonic_ns=time.monotonic_ns())
            )
        )
        child.stdin.write("finish\n")
        child.stdin.flush()
        assert child.wait(timeout=5) == 0
        terminal = observer.runner_terminal(
            child.returncode,
            owner,
            dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest()),
            time.monotonic_ns(),
        )
        root = dict(
            runner_terminal=terminal, runner_exit_code=0, all_observed_epochs=[owner]
        )
        yield root, dict(path=str(tmp_path / "independent-root-terminal.json")), argv
    finally:
        if child.poll() is None:
            child.stdin.close()
            child.wait(timeout=5)


def test_actual_normal_exit_is_valid_terminal_but_not_signal_cause(normal_exit):
    root, ref, argv = normal_exit
    assert intake.independent_runner_signal(root, ref, argv) is None


@pytest.mark.parametrize("mutation", ["kernel", "argv", "returncode", "hash", "clock"])
def test_normal_exit_terminal_corruption_cannot_hide_on_positive_path(
    normal_exit, mutation
):
    original, ref, argv = normal_exit
    root = copy.deepcopy(original)
    expected = list(argv)
    if mutation == "kernel":
        root["runner_terminal"]["kernel"]["start_ticks"] += 1
    elif mutation == "argv":
        expected += ["wrong-original-slot"]
    elif mutation == "returncode":
        root["runner_terminal"]["returncode"] = 1
    elif mutation == "hash":
        root["runner_terminal"]["popen"]["sha256"] = "0" * 64
    else:
        root["runner_terminal"]["observed_monotonic_ns"] = 1
    with pytest.raises(ValueError):
        intake.independent_runner_signal(root, ref, expected)
