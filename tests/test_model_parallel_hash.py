"""CPU-only model hash equivalence; no model/installed-runtime inspection."""

import threading
from pathlib import Path

import pytest

from experiments.native_attention_candidate import live_route_reader as routes


def inputs(tmp_path):
    rows = []
    for index in range(14):
        path = tmp_path / f"model-{index}.bin"
        path.write_bytes(bytes([index]) * (4096 + index))
        rows.append({"path": str(path), "sha256": routes._hash(path)})
    return rows


def test_complete_inventory_exact_equivalence_and_fresh_again(tmp_path, monkeypatch):
    rows = inputs(tmp_path)
    sequential_states, parallel_states = {}, {}
    expected = routes._inventory(rows, sequential_states)
    original = routes._hash
    observed, lock = [], threading.Lock()

    def counted(path, states=None):
        with lock:
            observed.append((str(path), threading.get_ident(), id(states)))
        return original(path, states)

    monkeypatch.setattr(routes, "_hash", counted)
    actual = routes._model_inventory(rows, parallel_states)
    assert routes.registry.canonical(actual) == routes.registry.canonical(expected)
    assert routes.registry.canonical(parallel_states) == routes.registry.canonical(
        sequential_states
    )
    routes._check_file_states(parallel_states)
    assert len(observed) == 14
    assert 1 <= len({thread for _, thread, _ in observed}) <= 4
    assert all(thread != threading.get_ident() for _, thread, _ in observed)
    second_states = {}
    assert routes._model_inventory(rows, second_states) == expected
    assert len(observed) == 28
    assert second_states == sequential_states


def test_duplicate_rejected_before_hash(tmp_path, monkeypatch):
    rows = inputs(tmp_path)
    monkeypatch.setattr(
        routes, "_hash", lambda *args: pytest.fail("duplicate scheduled")
    )
    with pytest.raises(ValueError, match="repeats a path"):
        routes._model_inventory(rows + [rows[0]], {})


def test_missing_file_rejected(tmp_path):
    rows = inputs(tmp_path)
    Path(rows[3]["path"]).unlink()
    with pytest.raises(OSError):
        routes._model_inventory(rows, {})


def test_wrong_bytes_rejected(tmp_path):
    rows = inputs(tmp_path)
    Path(rows[4]["path"]).write_bytes(b"different")
    with pytest.raises(ValueError, match="input bytes differ"):
        routes._model_inventory(rows, {})


def test_during_read_mutation_rejected(tmp_path, monkeypatch):
    rows = inputs(tmp_path)
    target = rows[0]["path"]
    original = routes._stream_sha

    def mutate(stream):
        digest = original(stream)
        if stream.name == target:
            with open(target, "ab") as output:
                output.write(b"changed during read")
        return digest

    monkeypatch.setattr(routes, "_stream_sha", mutate)
    with pytest.raises(ValueError, match="input changed during hashing"):
        routes._model_inventory(rows, {})


def test_preexisting_state_conflict_rejected(tmp_path):
    rows = inputs(tmp_path)
    states = {}
    routes._hash(rows[0]["path"], states)
    states[rows[0]["path"]] = dict(states[rows[0]["path"]], st_size=0)
    with pytest.raises(ValueError, match="input file state conflicts"):
        routes._model_inventory(rows, states)


def test_post_hash_mutation_rejected_by_original_final_check(tmp_path):
    rows = inputs(tmp_path)
    states = {}
    routes._model_inventory(rows, states)
    Path(rows[1]["path"]).write_bytes(b"post hash mutation")
    with pytest.raises(ValueError, match="audited input file changed"):
        routes._check_file_states(states)
