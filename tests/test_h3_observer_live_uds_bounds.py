"""Source-only UDS byte-bound regressions, unrun; no future kernel is guessed."""

import os
from pathlib import Path

import pytest

from experiments.formal_campaign.h3_observer_live_registration import (
    MAX_ACTUAL_PID,
    PID_COMPONENT_BYTES,
    UDS_PATH_BYTES,
    actual_control_path,
    check_uds_path,
    precheck_uds_paths,
)
from vllm_hust_ext.exposure_gate import GateError


def ascii_directory(bytes_count):
    return Path("/" + "a" * (bytes_count - 1))


def test_future_control_path_107_bytes_passes_108_rejects_before_launch():
    suffix = len(os.fsencode("/" + "P" * PID_COMPONENT_BYTES + "/control.sock"))
    directory = ascii_directory(UDS_PATH_BYTES - suffix)
    precheck_uds_paths(directory, Path("/short-successor"))
    with pytest.raises(GateError, match="sun_path byte bound"):
        precheck_uds_paths(Path(str(directory) + "a"), Path("/short-successor"))


def test_successor_native_path_107_bytes_passes_108_rejects_before_launch():
    suffix = len(os.fsencode("/native.sock"))
    successor = ascii_directory(UDS_PATH_BYTES - suffix)
    precheck_uds_paths(Path("/short-control"), successor)
    with pytest.raises(GateError, match="sun_path byte bound"):
        precheck_uds_paths(Path("/short-control"), Path(str(successor) + "a"))


def test_path_bound_counts_filesystem_bytes_instead_of_characters():
    path = Path("/" + "界" * 36 + "/native.sock")
    assert len(str(path)) < 108 and len(os.fsencode(str(path))) > UDS_PATH_BYTES
    with pytest.raises(GateError, match="sun_path byte bound"):
        check_uds_path(path)


def test_future_pid_width_check_is_size_only_without_filesystem_or_process_probe(
    monkeypatch,
):
    def forbidden(*args, **kwargs):
        raise AssertionError("sizing cannot inspect/reserve a future identity/path")

    monkeypatch.setattr(Path, "stat", forbidden)
    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    precheck_uds_paths(Path("/control"), Path("/successor"))


def test_actual_positive_pid_path_is_rechecked_at_worst_supported_width():
    suffix = len(os.fsencode("/" + "P" * PID_COMPONENT_BYTES + "/control.sock"))
    directory = ascii_directory(UDS_PATH_BYTES - suffix)
    actual = actual_control_path(directory, MAX_ACTUAL_PID)
    assert actual == directory / str(MAX_ACTUAL_PID) / "control.sock"
    assert len(os.fsencode(str(actual))) == UDS_PATH_BYTES
    with pytest.raises(GateError, match="sun_path byte bound"):
        actual_control_path(Path(str(directory) + "a"), MAX_ACTUAL_PID)


@pytest.mark.parametrize("pid", [0, -1, True, "123", MAX_ACTUAL_PID + 1])
def test_actual_pid_cannot_escape_preregistered_signed_pid_t_width(pid):
    with pytest.raises(GateError, match="actual Linux producer PID"):
        actual_control_path(Path("/control"), pid)


@pytest.mark.parametrize(
    "path", ["relative/native.sock", "/control/embedded\x00nul.sock"]
)
def test_pathname_uds_cannot_use_relative_or_nul_name(path):
    with pytest.raises(GateError, match="sun_path byte bound"):
        check_uds_path(path)
