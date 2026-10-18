"""Tiny real files/ZIPs and explicit Git-metadata fixtures; never qualification."""

import hashlib
import os
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from experiments.formal_campaign import h3_source_read_call as source


def ref(path):
    return dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())


class SourceReadCallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ecpa-source-read-tiny-")
        self.root = Path(self.temp.name)
        self.wheel = self.root / "tiny.whl"
        with zipfile.ZipFile(self.wheel, "w") as archive:
            archive.writestr("tiny/__init__.py", b"VALUE = 1\n")
            archive.writestr("tiny/native_blob", b"\x7fELFtiny")
        self.reference = ref(self.wheel)
        self.repo = self.root / "source"
        self.repo.mkdir()
        (self.repo / "sample.py").write_bytes(b"VALUE = 1\n")
        self.objects = self.repo / ".git/objects"
        self.objects.mkdir(parents=True)
        (self.objects / "tiny-object").write_bytes(b"owned tiny object fixture")
        self.git_identity = ["head", "tree"]
        self.git_status = ""
        self.original_calls = 0

    def tearDown(self):
        self.temp.cleanup()

    def git(self, root, *args):
        self.assertEqual(root, self.repo)
        if args[0] == "--no-optional-locks":
            args = args[1:]
        if args[0] == "rev-parse":
            if args[1] == "--git-common-dir":
                return b".git\n.git\n"
            return ("\n".join(self.git_identity) + "\n").encode()
        if args[0] == "config":
            return b"fixture-config\0"
        if args[0] == "status":
            return self.git_status.encode()
        if args[0] == "ls-files":
            return b"sample.py\x00"
        raise AssertionError(args)

    def observe(self):
        self.original_calls += 1
        raw = source.current().read(self.reference)
        with zipfile.ZipFile(self.wheel) as archive:
            body = archive.read("tiny/__init__.py")
        return dict(
            Python={"tiny/__init__.py": hashlib.sha256(body).hexdigest()},
            native_ELF={"tiny/native_blob": hashlib.sha256(raw).hexdigest()},
        )

    def role(self, scope, key="same-complete-original-input"):
        return scope.source_role(key, self.repo, "revision", self.git, self.observe)

    def test_36_same_invocation_static_roles_proved_once_with_fresh_fences(self):
        with source.fresh_source_read_call() as scope:
            expected = self.role(scope)
            for _ in range(35):
                scope.check_refs()
                self.assertEqual(self.role(scope), expected)
                scope.check()
        self.assertEqual(self.original_calls, 1)

    def test_second_invocation_repeats_original_full_proof(self):
        for _ in range(2):
            with source.fresh_source_read_call() as scope:
                self.role(scope)
        self.assertEqual(self.original_calls, 2)

    def test_changed_full_role_key_reexecutes_original_proof(self):
        with source.fresh_source_read_call() as scope:
            self.role(scope)
            self.role(scope, key="different-config-or-source")
        self.assertEqual(self.original_calls, 2)

    def test_actual_member_bytes_changed_even_restored_mtime_reject(self):
        with (
            self.assertRaisesRegex(ValueError, "source call reference"),
            source.fresh_source_read_call() as scope,
        ):
            self.role(scope)
            before = self.wheel.stat()
            with self.wheel.open("ab") as stream:
                stream.write(b"tampered")
            os.utime(self.wheel, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.role(scope)

    def test_same_bytes_wheel_inode_replacement_reject(self):
        with (
            self.assertRaisesRegex(ValueError, "source call reference"),
            source.fresh_source_read_call() as scope,
        ):
            self.role(scope)
            other = self.wheel.with_suffix(".replacement")
            other.write_bytes(self.wheel.read_bytes())
            os.replace(other, self.wheel)
            scope.check()

    def test_object_content_or_new_namespace_reject(self):
        for mutation in ("content", "new-file"):
            with (
                self.subTest(mutation=mutation),
                self.assertRaisesRegex(ValueError, "source Git/checkout"),
                source.fresh_source_read_call() as scope,
            ):
                self.role(scope)
                if mutation == "content":
                    (self.objects / "tiny-object").write_bytes(b"corrupt-object")
                else:
                    (self.objects / "another-object").write_bytes(b"extra")
                self.role(scope)

    def test_checkout_leaf_and_Git_head_status_changes_reject(self):
        for kind in ("leaf", "head", "status"):
            with (
                self.subTest(kind=kind),
                self.assertRaisesRegex(ValueError, "source Git/checkout"),
                source.fresh_source_read_call() as scope,
            ):
                self.role(scope)
                if kind == "leaf":
                    (self.repo / "sample.py").write_bytes(b"CHANGED = 1\n")
                elif kind == "head":
                    self.git_identity[0] += "-changed"
                else:
                    self.git_status = " M sample.py"
                self.role(scope)

    def test_finalizer_freshness_rejects_without_next_reuse(self):
        with (
            self.assertRaisesRegex(ValueError, "source call reference"),
            source.fresh_source_read_call() as scope,
        ):
            scope.read(self.reference)
            self.wheel.write_bytes(b"changed-after-last-phase")
        self.assertIsNone(source.current())

    def test_closed_scope_and_cross_process_and_foreign_thread_reject(self):
        with source.fresh_source_read_call() as scope:
            scope.read(self.reference)
            errors = []

            def foreign():
                try:
                    scope.read(self.reference)
                except ValueError as error:
                    errors.append(str(error))

            worker = threading.Thread(target=foreign)
            worker.start()
            worker.join()
            self.assertTrue(errors)
            with (
                patch.object(source.os, "getpid", return_value=scope.pid + 1),
                self.assertRaisesRegex(ValueError, "crossed process"),
            ):
                scope.read(self.reference)
        with self.assertRaisesRegex(ValueError, "closed"):
            scope.read(self.reference)

    def test_original_raw_and_ELF_result_memo_are_immutable_and_rechecked(self):
        calls = []
        with source.fresh_source_read_call() as scope:
            first = scope.read(self.reference)
            self.assertIs(first, scope.read(self.reference))

            def elves(raw):
                calls.append(raw)
                return {"tiny/native_blob": "digest"}

            result = scope.elves(first, elves)
            result.clear()
            self.assertEqual(scope.elves(first, elves), {"tiny/native_blob": "digest"})
        self.assertEqual(len(calls), 1)

    def test_worker_borrow_is_joined_and_cannot_escape_scope(self):
        with source.fresh_source_read_call() as scope:
            result = []
            worker = threading.Thread(
                target=lambda: result.append(
                    source.run_source_role(scope, lambda: scope.read(self.reference))
                )
            )
            worker.start()
            worker.join()
            self.assertTrue(result)
            self.assertEqual(scope.workers, set())
        self.assertFalse(scope.active)

    def test_blobless_object_fetch_during_first_proof_is_not_cached(self):
        with source.fresh_source_read_call() as scope:

            def original_with_new_object():
                (self.objects / "new-object").write_bytes(
                    b"first real fetch-shaped change"
                )
                return self.observe()

            scope.source_role(
                "key", self.repo, "revision", self.git, original_with_new_object
            )
            self.assertEqual(scope.roles, {})
            self.role(scope, "key")
            self.assertEqual(len(scope.roles), 1)
        self.assertEqual(self.original_calls, 2)

    def test_Git_replace_ref_mutation_rejects(self):
        with (
            self.assertRaisesRegex(ValueError, "source Git/checkout"),
            source.fresh_source_read_call() as scope,
        ):
            self.role(scope)
            replacement = self.repo / ".git/refs/replace/original-object"
            replacement.parent.mkdir(parents=True)
            replacement.write_bytes(b"different-object\n")
            self.role(scope)

    def test_Git_replace_symlink_target_mutation_rejects(self):
        target = self.root / "outside-replace-ref"
        target.write_bytes(b"original-object\n")
        link = self.repo / ".git/refs/replace/object"
        link.parent.mkdir(parents=True)
        link.symlink_to(target)
        with (
            self.assertRaisesRegex(ValueError, "source Git/checkout"),
            source.fresh_source_read_call() as scope,
        ):
            self.role(scope)
            target.write_bytes(b"another-object\n")
            self.role(scope)

    def test_Git_config_values_are_hashed_not_retained_in_fence(self):
        import json

        original = self.git

        def configured(root, *args):
            if args[0] == "config":
                return b"file:fixture\0credential.password\nunit-secret-sentinel\0"
            return original(root, *args)

        with source.fresh_source_read_call() as scope:
            scope.source_role(
                "config-key", self.repo, "revision", configured, self.observe
            )
            snapshot = next(iter(scope.roles.values()))[-1]
            self.assertNotIn("unit-secret-sentinel", json.dumps(snapshot))

    def test_actual_PR250_threadpools_reuse_original_Git_proof_and_reject_tamper(self):
        from experiments.formal_campaign import h3_runtime_source_closure as closure

        repo = Path(closure.__file__).resolve().parents[2]
        revision = closure.git(repo, "rev-parse", "HEAD").decode().strip()
        raw = (repo / "src/vllm_hust_ext/__init__.py").read_bytes()
        with zipfile.ZipFile(self.wheel, "w") as archive:
            archive.writestr("vllm_hust_ext/__init__.py", raw)
        item = {"wheel": dict(ref(self.wheel), revision=revision)}
        role = "plugin:tiny-actual-source"
        expected = {role: revision}
        items, repositories = {role: item}, {role: dict(path=str(repo))}
        calls, owner = [], threading.get_ident()
        original = closure._source_members

        def observe(*args):
            calls.append(threading.get_ident())
            return original(*args)

        with (
            self.assertRaisesRegex(ValueError, "source call reference"),
            patch.object(closure, "_source_members", observe),
            source.fresh_source_read_call() as scope,
        ):
            first = closure._source_roles(expected, items, repositories, {})
            second = closure._source_roles(expected, items, repositories, {})
            self.assertEqual(first, second)
            self.assertEqual(
                first[role]["Python"]["vllm_hust_ext/__init__.py"],
                hashlib.sha256(raw).hexdigest(),
            )
            self.assertEqual(len(calls), 1)
            self.assertNotEqual(calls[0], owner)
            self.assertEqual(len(scope.roles), 1)
            self.assertFalse(scope.workers)
            with self.wheel.open("ab") as stream:
                stream.write(b"changed-between-real-threadpools")
            closure._source_roles(expected, items, repositories, {})
        self.assertEqual(len(calls), 1)

    def test_worker_success_is_not_cached_without_owner_accept(self):
        from concurrent.futures import ThreadPoolExecutor

        with source.fresh_source_read_call() as scope:
            with ThreadPoolExecutor(max_workers=4) as executor:
                observation = executor.submit(
                    source.run_source_role, scope, lambda: self.role(scope)
                ).result()
            self.assertEqual(scope.roles, {})
            values = scope.accept_roles([observation])
            self.assertEqual(values[0]["Python"].keys(), {"tiny/__init__.py"})
            self.assertEqual(len(scope.roles), 1)

    def test_partial_worker_failure_never_publishes_role_cache(self):
        from concurrent.futures import ThreadPoolExecutor

        with source.fresh_source_read_call() as scope:

            def failed():
                raise RuntimeError("original source role failed")

            with (
                self.assertRaisesRegex(RuntimeError, "original source role failed"),
                ThreadPoolExecutor(max_workers=4) as executor,
            ):
                futures = [
                    executor.submit(source.run_source_role, scope, action)
                    for action in (lambda: self.role(scope), failed)
                ]
                [future.result() for future in futures]
            self.assertFalse(scope.workers)
            self.assertEqual(scope.roles, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
