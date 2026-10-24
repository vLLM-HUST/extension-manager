"""Negative packaging cases must not become installation-asset exceptions."""

import io
import tarfile
import zipfile

import pytest

from scripts.check_distribution import CONSOLE, check


def artifacts(tmp_path, *, extra=None, missing=False, changed=False, symlink=False):
    root = tmp_path / "source"
    package = root / "src/vllm_hust_ext"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b"# runtime\n")
    (root / "README.md").write_bytes(b"# install\n")
    (root / "pyproject.toml").write_bytes(b"# packaging\n")
    dist = tmp_path / "dist"
    dist.mkdir()
    members = {
        "vllm_hust_ext/__init__.py": b"# runtime\n",
        "vllm_hust_ext-0.3.0.dist-info/METADATA": b"Version: 0.3.0\n",
        "vllm_hust_ext-0.3.0.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
        "vllm_hust_ext-0.3.0.dist-info/RECORD": b"",
        "vllm_hust_ext-0.3.0.dist-info/entry_points.txt": (
            "[console_scripts]\n"
            + "".join(f"{n} = vllm_hust_ext:main\n" for n in CONSOLE)
        ).encode(),
    }
    if missing:
        del members["vllm_hust_ext/__init__.py"]
    with zipfile.ZipFile(dist / "manager.whl", "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    source = {
        "src/vllm_hust_ext/__init__.py": b"changed" if changed else b"# runtime\n",
        "README.md": b"# install\n",
        "pyproject.toml": b"# packaging\n",
        "PKG-INFO": b"metadata",
    }
    if extra:
        source[extra] = b"payload"
    with tarfile.open(dist / "manager.tar.gz", "w:gz") as archive:
        for name, content in source.items():
            member = tarfile.TarInfo("manager-0.3.0/" + name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        if symlink:
            member = tarfile.TarInfo("manager-0.3.0/link")
            member.type = tarfile.SYMTYPE
            member.linkname = "/outside"
            archive.addfile(member)
    return dist, root


def test_bounded_installation_payload(tmp_path):
    check(*artifacts(tmp_path))


@pytest.mark.parametrize(
    "extra",
    [
        "experiments/probe.json",
        "paper/table.json",
        "docs/evidence/run.md",
        "arbitrary.json",
        "src/vllm_hust_ext/raw.csv",
        "../escape.py",
    ],
)
def test_reject_data_and_unexpected_members(tmp_path, extra):
    with pytest.raises(ValueError):
        check(*artifacts(tmp_path, extra=extra))


@pytest.mark.parametrize("change", ["missing", "changed", "symlink"])
def test_reject_incomplete_or_changed_runtime(tmp_path, change):
    with pytest.raises(ValueError):
        check(*artifacts(tmp_path, **{change: True}))


def test_ci_and_release_gate_check_both_distributions():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    for name in ("ci.yml", "release-gate.yml"):
        workflow = (root / ".github/workflows" / name).read_text()
        assert (
            workflow.index("python -m build")
            < workflow.index("python scripts/check_distribution.py dist")
            < workflow.index("Verify clean wheel installation")
        )
