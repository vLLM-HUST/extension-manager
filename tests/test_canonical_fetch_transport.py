"""Real local Git objects plus injected transport errors; no network admission."""

import base64
import json
import subprocess
from pathlib import Path

import pytest
from test_source_provenance import source as source

from experiments.formal_campaign import source_provenance as p


def records(capsys):
    return [
        json.loads(line)
        for line in capsys.readouterr().err.splitlines()
        if line.startswith("{")
    ]


def inject(monkeypatch, failures):
    original = subprocess.run
    calls = []

    def run(command, *args, **kwargs):
        if len(command) > 3 and command[0] == "git" and command[3] == "fetch":
            assert kwargs["timeout"] == p.GIT_FETCH_TIMEOUT_SECONDS >= 240
            calls.append(tuple(command))
            # No successful/failed attempt's Git objects can seed a new attempt.
            root = Path(command[2])
            if command[-1] != "refs/heads/main":
                assert not any(x.is_file() for x in (root / "objects").rglob("*"))
            failure = failures(len(calls), command)
            if failure is not None:
                raise failure
        return original(command, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", run)
    return calls


def error(command, number):
    return subprocess.CalledProcessError(
        128,
        command,
        output=f"partial-{number}".encode(),
        stderr=b"actual fetch transport failure\xff-" + str(number).encode(),
    )


def test_failed_exact_fetch_uses_three_new_empty_canonical_attempts(
    source, monkeypatch, capsys
):
    _, _, commit, definition, location = source
    calls = inject(monkeypatch, lambda n, cmd: error(cmd, n) if n <= 2 else None)
    observed = p.observe_component("accelerator", commit, definition, location)
    assert observed["requested_commit"] == observed["remote_commit"] == commit
    assert observed["merged_to_main"] is None
    assert len(calls) == 3 and len({c[2] for c in calls}) == 3
    assert all(c[-1] == commit for c in calls)
    assert all(not Path(c[2]).exists() for c in calls)
    events = records(capsys)
    fetches = [x for x in events if x["event"] == "fetch-command-result"]
    assert [x["returncode"] for x in fetches] == [128, 128, 0]
    assert base64.b64decode(fetches[0]["stderr_base64"]) == error([], 1).stderr
    assert base64.b64decode(fetches[1]["stdout_base64"]) == b"partial-2"
    assert all(x["source_admission"] is False for x in events)
    assert not {"attempt", "started_ns", "finished_ns", "quarantine"} & set(observed)


def test_failed_main_fetch_restarts_exact_commit_in_empty_store(
    source, monkeypatch, capsys
):
    _, _, commit, definition, location = source
    calls = inject(monkeypatch, lambda n, cmd: error(cmd, n) if n == 2 else None)
    observed = p.observe_component(
        "accelerator", commit, dict(definition, requirement="merged-main"), location
    )
    assert [c[-1] for c in calls] == [commit, "refs/heads/main"] * 2
    assert calls[0][2] == calls[1][2] != calls[2][2] == calls[3][2]
    assert observed["merged_to_main"] is True and observed["main_commit"] == commit
    begins = [x for x in records(capsys) if x["event"] == "component-attempt-begin"]
    assert [x["attempt"] for x in begins] == [1, 2]
    assert all(
        x["remote"] == "https://github.com/example/accelerator.git" for x in begins
    )


def test_exhaustion_retains_all_raw_outputs_and_final_exception(
    source, monkeypatch, capsys
):
    _, _, commit, definition, location = source
    calls = inject(monkeypatch, lambda n, cmd: error(cmd, n))
    with pytest.raises(p.GitFetchTransportError) as caught:
        p.observe_component("accelerator", commit, definition, location)
    assert isinstance(caught.value, subprocess.CalledProcessError)
    assert len(calls) == p.GIT_FETCH_ATTEMPTS == 3
    assert caught.value.stderr == error([], 3).stderr
    assert "partial-3" in str(caught.value) and "actual fetch transport failure" in str(
        caught.value
    )
    fetches = [x for x in records(capsys) if x["event"] == "fetch-command-result"]
    assert [base64.b64decode(x["stderr_base64"]) for x in fetches] == [
        error([], n).stderr for n in (1, 2, 3)
    ]
    assert all(not Path(c[2]).exists() for c in calls)


def test_timeout_preserves_partial_bytes_then_new_store(source, monkeypatch, capsys):
    _, _, commit, definition, location = source
    calls = inject(
        monkeypatch,
        lambda n, cmd: (
            subprocess.TimeoutExpired(
                cmd,
                p.GIT_FETCH_TIMEOUT_SECONDS,
                output=b"timeout-partial",
                stderr=b"timeout-stderr",
            )
            if n == 1
            else None
        ),
    )
    assert (
        p.observe_component("accelerator", commit, definition, location)[
            "remote_commit"
        ]
        == commit
    )
    assert len(calls) == 2 and calls[0][2] != calls[1][2]
    fetches = [x for x in records(capsys) if x["event"] == "fetch-command-result"]
    assert fetches[0]["timed_out"] and fetches[0]["returncode"] is None
    assert base64.b64decode(fetches[0]["stdout_base64"]) == b"timeout-partial"
    assert base64.b64decode(fetches[0]["stderr_base64"]) == b"timeout-stderr"


def test_wrong_exact_sha_is_not_retried(source, monkeypatch, capsys):
    _, _, commit, definition, location = source
    calls = inject(monkeypatch, lambda *args: None)
    original = p._git

    def wrong(root, *args):
        if args == ("rev-parse", "FETCH_HEAD"):
            return b"f" * 40 + b"\n"
        return original(root, *args)

    monkeypatch.setattr(p, "_git", wrong)
    with pytest.raises(ValueError, match="requested exact source"):
        p.observe_component("accelerator", commit, definition, location)
    assert len(calls) == 1
    assert (
        len([x for x in records(capsys) if x["event"] == "component-attempt-begin"])
        == 1
    )


def test_nonfetch_error_has_no_retry_or_fetch_diagnostic(tmp_path, monkeypatch, capsys):
    calls = []

    def fail(command, **kwargs):
        calls.append(command)
        assert "timeout" not in kwargs
        raise subprocess.CalledProcessError(128, command, stderr=b"local failure")

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError) as caught:
        p._git(tmp_path, "status", "--porcelain")
    assert type(caught.value) is subprocess.CalledProcessError
    assert len(calls) == 1 and records(capsys) == []
