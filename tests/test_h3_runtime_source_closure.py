"""Small CPU source/wheel fixtures; never a Host/model qualification."""

import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from experiments.formal_campaign import h3_runtime_source_closure as closure


def run_git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args]).decode().strip()


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    repo = tmp_path / "source"
    repo.mkdir()
    run_git(repo, "init", "-q")
    distributions = {
        "manager": ("vllm-hust-ext", "vllm_hust_ext"),
        "host": ("vllm", "vllm"),
        "accelerator": ("vllm-ascend", "vllm_ascend"),
        "plugin:fixture": ("owned-fixture", "owned_fixture"),
    }
    site = tmp_path / "site"
    site.mkdir()
    for _, module in distributions.values():
        (repo / module).mkdir()
        (repo / module / "__init__.py").write_text("VALUE = 'source-owned'\n")
    run_git(repo, "add", ".")
    run_git(
        repo,
        "-c",
        "user.name=CPU Fixture",
        "-c",
        "user.email=fixture@example.org",
        "commit",
        "-qm",
        "source fixture only",
    )
    revision = run_git(repo, "rev-parse", "HEAD")
    wheels = {}
    for role, (distribution, module) in distributions.items():
        wheel = tmp_path / (module + "-1-py3-none-any.whl")
        members = {
            module + "/__init__.py": (repo / module / "__init__.py").read_bytes(),
            module + "-1.dist-info/METADATA": (
                f"Metadata-Version: 2.1\nName: {distribution}\nVersion: 1\n"
            ).encode(),
        }
        with zipfile.ZipFile(wheel, "w") as archive:
            for path, raw in members.items():
                archive.writestr(path, raw)
                installed = site / path
                installed.parent.mkdir(parents=True, exist_ok=True)
                installed.write_bytes(raw)
        wheels[role] = {
            "distribution": distribution,
            "module": module,
            "wheel": {
                "path": str(wheel),
                "sha256": closure.sha(wheel.read_bytes()),
                "version": "1",
                "revision": revision,
            },
        }
    # This changes only this tiny fixture child's metadata/import search. The
    # production verifier still requires the exact parent critical environment.
    monkeypatch.setenv("PYTHONPATH", str(site))
    phase = {
        "argv": [sys.executable],
        "cwd": str(tmp_path),
        "environment": dict(os.environ),
    }
    fixed = {
        "manager_commit": revision,
        "host_commit": revision,
        "accelerator_commit": revision,
        "plugin_commits": {"fixture": revision},
    }
    repositories = {
        role: {"path": str(repo), "remote": "unused-CPU-fixture"}
        for role in distributions
    }
    return phase, fixed, repositories, wheels, site, repo


def verify(runtime):
    phase, fixed, repositories, wheels, _, _ = runtime
    return closure.verify_runtime_source_closure(phase, fixed, repositories, wheels)


def test_actual_child_installed_wheel_and_immutable_git_source_match(runtime):
    result = verify(runtime)
    assert result["schema"] == closure.SCHEMA
    assert set(result["actual_runtime"]["distributions"]) == set(runtime[3])
    assert result["actual_runtime"]["python"] == sys.executable


@pytest.mark.parametrize("mutation", ["installed", "source-wheel", "shadow", "extra"])
def test_real_child_payload_source_shadow_and_inventory_mutations_reject(
    runtime, mutation
):
    phase, _, _, wheels, site, _ = runtime
    if mutation == "installed":
        (site / "vllm/__init__.py").write_text("DIFFERENT = True\n")
    elif mutation == "source-wheel":
        wheel = Path(wheels["host"]["wheel"]["path"])
        with zipfile.ZipFile(wheel) as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        members["vllm/__init__.py"] = b"WRONG_SOURCE = True\n"
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, raw in members.items():
                archive.writestr(name, raw)
        wheels["host"]["wheel"]["sha256"] = closure.sha(wheel.read_bytes())
    elif mutation == "shadow":
        shadow = Path(phase["cwd"]) / "shadow"
        (shadow / "vllm").mkdir(parents=True)
        (shadow / "vllm/__init__.py").write_text("WRONG_IMPORT = True\n")
        # Mirror the parent's proposed environment to exercise the child origin
        # check itself, rather than stopping at the earlier environment fence.
        os.environ["PYTHONPATH"] = str(shadow) + os.pathsep + str(site)
        phase["environment"] = dict(os.environ)
    else:
        (site / "vllm/unrecorded.py").write_text("EXTRA = True\n")
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        verify(runtime)


@pytest.mark.parametrize("mutation", ["python", "environment", "revision", "missing"])
def test_cross_runtime_and_incomplete_source_tuple_reject(runtime, mutation):
    phase, _, _, wheels, _, _ = runtime
    if mutation == "python":
        phase["argv"][0] = str(Path(sys.executable).resolve())
        if phase["argv"][0] == sys.executable:
            phase["argv"][0] += "-another-environment"
    elif mutation == "environment":
        phase["environment"]["PYTHONPATH"] = "/unadmitted/import/root"
    elif mutation == "revision":
        wheels["host"]["wheel"]["revision"] = "0" * 40
    else:
        del wheels["accelerator"]
    with pytest.raises(ValueError):
        verify(runtime)


def test_native_payload_cannot_claim_source_without_real_compile_provenance(tmp_path):
    wheel = tmp_path / "native.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("vllm_ascend/native.so", b"\x7fELFfixture-not-a-build")
    item = {"wheel": {"path": str(wheel), "sha256": closure.sha(wheel.read_bytes())}}
    with pytest.raises(ValueError, match="source/compile proof"):
        closure._build_proof(item, tmp_path, "a" * 40, closure._elfs(wheel))
