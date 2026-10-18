"""Tiny genuine file hashes only; never model/device qualification."""

import hashlib
import os

import pytest

from experiments.native_attention_candidate import live_route_reader as routes


def tiny(tmp_path):
    path = tmp_path / "model-bytes.bin"
    path.write_bytes(b"actual small CPU fixture")
    rows = [dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())]
    return path, rows


def count_real_hashes(monkeypatch):
    original = routes._model_inventory
    calls = []

    def counted(rows, states):
        calls.append(rows)
        return original(rows, states)

    monkeypatch.setattr(routes, "_model_inventory", counted)
    return calls


def test_same_call_same_binding_hashes_once_and_returns_detached_data(
    tmp_path, monkeypatch
):
    path, rows = tiny(tmp_path)
    calls = count_real_hashes(monkeypatch)
    with routes._fresh_model_audit_call() as token:
        first = routes._model_inventory_in_call(rows, {}, token, {"config": "one"})
        first[str(path)] = "caller-edited"
        second = routes._model_inventory_in_call(rows, {}, token, {"config": "one"})
        assert second[str(path)] == rows[0]["sha256"]
        assert len(calls) == 1
        with pytest.raises(AttributeError):
            token.capacity = 999


def test_new_call_and_distinct_binding_reobserve_real_bytes(tmp_path, monkeypatch):
    _, rows = tiny(tmp_path)
    calls = count_real_hashes(monkeypatch)
    for _ in range(2):
        with routes._fresh_model_audit_call() as token:
            for key in ("one", "two"):
                routes._model_inventory_in_call(rows, {}, token, {"config": key})
    assert len(calls) == 4


def test_default_audit_path_never_reuses_previous_model_hash(tmp_path, monkeypatch):
    _, rows = tiny(tmp_path)
    calls = count_real_hashes(monkeypatch)
    for _ in range(2):
        routes._model_inventory_in_call(rows, {}, None, {})
    assert len(calls) == 2


@pytest.mark.parametrize("token", [{}, object(), routes._ModelAuditCall()])
def test_caller_dict_or_unissued_exact_type_rejected(tmp_path, token):
    _, rows = tiny(tmp_path)
    with pytest.raises(ValueError, match="unissued or closed"):
        routes._model_inventory_in_call(rows, {}, token, {})


def test_closed_call_cannot_authorize_later_read(tmp_path):
    _, rows = tiny(tmp_path)
    with routes._fresh_model_audit_call() as token:
        routes._model_inventory_in_call(rows, {}, token, {})
    with pytest.raises(ValueError, match="unissued or closed"):
        routes._model_inventory_in_call(rows, {}, token, {})


def test_same_size_write_even_restored_mtime_fails_and_revokes(tmp_path):
    path, rows = tiny(tmp_path)
    with pytest.raises(ValueError), routes._fresh_model_audit_call() as token:
        routes._model_inventory_in_call(rows, {}, token, {})
        old = path.stat()
        path.write_bytes(b"x" * old.st_size)
        os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns))
        routes._model_inventory_in_call(rows, {}, token, {})
    with pytest.raises(ValueError, match="unissued or closed"):
        routes._model_inventory_in_call(rows, {}, token, {})


def test_mutation_after_last_use_still_fails_final_scope_check(tmp_path):
    path, rows = tiny(tmp_path)
    with pytest.raises(ValueError), routes._fresh_model_audit_call() as token:
        routes._model_inventory_in_call(rows, {}, token, {})
        path.write_bytes(b"changed after last phase")
    assert token not in routes._MODEL_AUDIT_CALLS


@pytest.mark.parametrize("operation", ["use", "close"])
def test_scope_owner_thread_is_required(tmp_path, operation):
    from threading import Thread

    _, rows = tiny(tmp_path)
    context = routes._fresh_model_audit_call()
    token = context.__enter__()
    routes._model_inventory_in_call(rows, {}, token, {})
    errors = []

    def other_thread():
        try:
            if operation == "use":
                routes._model_inventory_in_call(rows, {}, token, {})
            else:
                context.__exit__(None, None, None)
        except ValueError as exc:
            errors.append(str(exc))

    thread = Thread(target=other_thread)
    thread.start()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert len(errors) == 1
    if operation == "close":
        # An invalid concurrent close cannot leave a live capability for the
        # remaining original audit: both its helper and final active check fail.
        with pytest.raises(ValueError, match="unissued or closed"):
            routes._active_model_audit_call(token)
        with pytest.raises(ValueError, match="unissued or closed"):
            context.__exit__(None, None, None)
    else:
        routes._active_model_audit_call(token)
        context.__exit__(None, None, None)


def test_replaced_ancestor_with_same_model_inode_is_rejected(tmp_path):
    root = tmp_path / "ancestor"
    model_dir = root / "model"
    model_dir.mkdir(parents=True)
    path, rows = tiny(model_dir)
    original = path.stat()
    with (
        pytest.raises(ValueError, match="ancestor identity"),
        routes._fresh_model_audit_call() as token,
    ):
        routes._model_inventory_in_call(rows, {}, token, {})
        root.rename(tmp_path / "retained-old-ancestor")
        root.mkdir()
        (tmp_path / "retained-old-ancestor/model").rename(model_dir)
        assert path.stat().st_ino == original.st_ino
        assert path.stat().st_ctime_ns == original.st_ctime_ns
        routes._model_inventory_in_call(rows, {}, token, {})
    assert token not in routes._MODEL_AUDIT_CALLS


def test_unlisted_model_directory_file_is_not_a_claimed_inventory_gate(tmp_path):
    path, rows = tiny(tmp_path)
    with routes._fresh_model_audit_call() as token:
        expected = routes._model_inventory_in_call(rows, {}, token, {})
        (path.parent / "outside-declared-inventory.bin").write_bytes(b"not declared")
        assert routes._model_inventory_in_call(rows, {}, token, {}) == expected


def test_fork_child_cannot_block_on_inherited_parent_registry_lock(tmp_path):
    import select
    import signal
    from threading import Event, Thread

    _, rows = tiny(tmp_path)
    held, release = Event(), Event()

    def hold_parent_lock():
        with routes._MODEL_AUDIT_CALLS_LOCK:
            held.set()
            release.wait(5)

    with routes._fresh_model_audit_call() as token:
        routes._model_inventory_in_call(rows, {}, token, {})
        thread = Thread(target=hold_parent_lock)
        thread.start()
        assert held.wait(2)
        reader, writer = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(reader)
            try:
                routes._active_model_audit_call(token)
            except ValueError:
                os.write(writer, b"rejected")
                os._exit(0)
            os._exit(1)
        os.close(writer)
        try:
            readable, _, _ = select.select([reader], [], [], 3)
            if not readable:
                os.kill(pid, signal.SIGKILL)  # this exact test-owned child only
            assert readable, "child blocked on inherited parent lock"
            assert os.read(reader, 64) == b"rejected"
        finally:
            os.close(reader)
            release.set()
            thread.join(timeout=2)
            _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0


def test_nonowner_generator_close_owner_exit_must_fail(tmp_path):
    from threading import Thread

    path = tmp_path / "actual-small-model.bin"
    path.write_bytes(b"original bytes")
    rows = [
        {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    ]
    context = routes._fresh_model_audit_call()
    token = context.__enter__()
    routes._model_inventory_in_call(rows, {}, token, {})
    errors = []

    def nonowner_close():
        try:
            context.__exit__(None, None, None)
        except ValueError as error:
            errors.append(str(error))

    thread = Thread(target=nonowner_close)
    thread.start()
    thread.join(timeout=2)
    assert not thread.is_alive() and len(errors) == 1
    path.write_bytes(b"changed AFTER invalid close")
    # Revoking a capability in another thread must also prevent its owner from
    # treating generator exhaustion as a successful verified context exit.
    with pytest.raises(ValueError):
        context.__exit__(None, None, None)
