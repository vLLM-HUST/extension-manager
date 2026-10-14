"""Actual CPU Git fetch/clean-source checks; URL identity is a declared fixture."""

import copy
import subprocess
from pathlib import Path

import pytest

from experiments.formal_campaign import source_provenance as p


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args]).decode().strip()


@pytest.fixture
def source(tmp_path, monkeypatch):
    repo = tmp_path / "source"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.name", "CPU Source Fixture")
    git(repo, "config", "user.email", "cpu-fixture@localhost")
    (repo / "effect.py").write_text("actual_source = 1\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "clone", "--bare", "-q", str(repo), str(remote)], check=True)
    git(repo, "remote", "add", "origin", str(remote))
    # CPU fixture only: real subprocess fetches/commit/tree/clean checks;
    # independent URL identity is not a claim about public repository admission.
    original = p._git

    def fixture_git(root, *args):
        if args == ("remote", "get-url", "origin"):
            return b"https://github.com/example/accelerator.git\n"
        if args[:4] == (
            "fetch",
            "--quiet",
            "--no-tags",
            "https://github.com/example/accelerator.git",
        ):
            args = (*args[:3], str(remote), *args[4:])
        return original(root, *args)

    monkeypatch.setattr(p, "_git", fixture_git)
    definition = {
        "repository": "example/accelerator",
        "requirement": "published-commit",
    }
    location = {"path": str(repo), "remote": "origin"}
    return repo, remote, base, definition, location


def test_actual_fetch_and_explicit_merge_policy(source):
    repo, _, base, definition, location = source
    observed = p.observe_component("accelerator", base, definition, location)
    assert observed["remote_commit"] == base
    assert observed["merged_to_main"] is None
    assert observed["tree"] == git(repo, "rev-parse", "HEAD^{tree}")
    observed = p.observe_component(
        "accelerator", base, dict(definition, requirement="merged-main"), location
    )
    assert observed["merged_to_main"] is True


def test_local_only_dirty_and_wrong_head_are_not_source_admission(source):
    repo, _, base, definition, location = source
    (repo / "untracked").write_text("dirty")
    with pytest.raises(ValueError, match="dirty"):
        p.observe_component("accelerator", base, definition, location)
    (repo / "untracked").unlink()
    (repo / "effect.py").write_text("actual_source = 2\n")
    git(repo, "commit", "-qam", "unpublished")
    local = git(repo, "rev-parse", "HEAD")
    with pytest.raises(subprocess.CalledProcessError):
        p.observe_component("accelerator", local, definition, location)
    with pytest.raises(ValueError, match="not requested"):
        p.observe_component("accelerator", base, definition, location)
    git(repo, "push", "-q", "origin", "HEAD:refs/heads/candidate")
    # Published-but-unmerged is valid only when explicitly selected in policy.
    assert (
        p.observe_component("accelerator", local, definition, location)["main_commit"]
        is None
    )
    with pytest.raises(ValueError, match="not merged"):
        p.observe_component(
            "accelerator", local, dict(definition, requirement="merged-main"), location
        )


def fixed_and_policy():
    fixed = dict(
        manager_commit="1" * 40,
        host_commit="2" * 40,
        accelerator_commit="3" * 40,
        plugin_commits={"kv": "4" * 40},
    )
    policy = {
        "schema": p.POLICY,
        "components": {
            "manager": {"repository": p.MANAGER, "requirement": "merged-main"},
            "host": {"repository": p.HOST, "requirement": "merged-main"},
            "accelerator": {
                "repository": "example/accelerator",
                "requirement": "published-commit",
            },
            "plugin:kv": {
                "repository": "example/kv",
                "requirement": "published-commit",
            },
        },
    }
    return fixed, policy


def test_no_missing_components_or_implicit_policy_weakening():
    fixed, policy = fixed_and_policy()
    assert len(p.validate_policy(policy, fixed)) == 4
    for role in ("manager", "host", "accelerator", "plugin:kv"):
        missing = copy.deepcopy(policy)
        del missing["components"][role]
        with pytest.raises(ValueError):
            p.validate_policy(missing, fixed)
    for role in ("manager", "host"):
        changed = copy.deepcopy(policy)
        changed["components"][role]["requirement"] = "published-commit"
        with pytest.raises(ValueError, match="cannot be weakened"):
            p.validate_policy(changed, fixed)
    with pytest.raises(ValueError, match="locations"):
        p.observe_sources(fixed, policy, {})


def test_remote_namespace_cannot_be_local_or_foreign_host():
    assert p.repository_name("git@github.com:example/kv.git") == "example/kv"
    for remote in (
        "/tmp/example/kv.git",
        "https://foreign.test/example/kv.git",
        "file:///example/kv.git",
    ):
        with pytest.raises(ValueError):
            p.repository_name(remote)


def test_receipt_policy_cannot_downgrade_or_change_exact_tuple():
    fixed, policy = fixed_and_policy()
    obs = dict(
        schema=p.OBSERVATION,
        policy_sha256=p.digest(p.canonical(policy)),
        subjects=p.subjects(fixed),
        components={},
        identity_verified=True,
    )
    for role, commit in p.subjects(fixed).items():
        definition = policy["components"][role]
        merged = definition["requirement"] == "merged-main"
        obs["components"][role] = dict(
            role=role,
            repository=definition["repository"],
            remote="https://github.com/" + definition["repository"] + ".git",
            requested_commit=commit,
            remote_commit=commit,
            tree="5" * 40,
            clean_checkout=True,
            requirement=definition["requirement"],
            main_commit=commit if merged else None,
            merged_to_main=True if merged else None,
        )
    campaign = dict(fixed_identity=fixed, source_provenance_policy=policy)
    here = Path(p.__file__).parent
    for family, old, new in (("h3", 2, 3), ("h4", 1, 2)):
        original = dict(fixed, schema=f"ecpa-{family}-deployment-receipt/v{old}")
        binding = {
            name: p.digest((here / name).read_bytes())
            for name in (
                "source_provenance.py",
                f"{family}_registration.py",
                f"{family}-deployment-receipt-v{new}.schema.json",
            )
        }
        receipt = p.upgrade_receipt(original, campaign, obs, binding)
        assert p.receipt_schema(receipt, campaign, family).endswith(
            f"v{new}.schema.json"
        )
        with pytest.raises(ValueError, match="legacy"):
            p.receipt_schema(original, campaign, family)
        assert p.receipt_schema(original, dict(fixed_identity=fixed), family).endswith(
            "receipt.schema.json"
        )
        bad = copy.deepcopy(receipt)
        bad["source_provenance_observation"]["components"]["accelerator"][
            "remote_commit"
        ] = "6" * 40
        with pytest.raises(ValueError, match="identity"):
            p.receipt_schema(bad, campaign, family)
        bad = copy.deepcopy(receipt)
        bad["source_provenance_protocol_binding"]["source_provenance.py"] = (
            "sha256:" + "0" * 64
        )
        with pytest.raises(ValueError, match="source differs"):
            p.receipt_schema(bad, campaign, family)
