from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "experiments/false_effective/installed_environment.py"


def load_fingerprint():
    spec = importlib.util.spec_from_file_location("installed_environment", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.fingerprint


def venv(tmp_path: Path) -> tuple[Path, Path]:
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin/python").write_bytes(b"python-binary")
    (tmp_path / "pyvenv.cfg").write_text("include-system-site-packages = false\n")
    site = tmp_path / "lib/python3.12/site-packages"
    site.mkdir(parents=True)
    (site / "package.py").write_bytes(b"value = 1\n")
    return tmp_path, site


def test_installed_bytes_are_stable_and_content_bound(tmp_path: Path) -> None:
    fingerprint = load_fingerprint()
    root, site = venv(tmp_path)
    first = fingerprint(root)
    assert first == fingerprint(root)
    assert first["file_count"] == 3
    (site / "__pycache__").mkdir()
    (site / "__pycache__/package.pyc").write_bytes(b"generated")
    assert first == fingerprint(root)
    (site / "package.py").write_bytes(b"value = 2\n")
    assert first["environment_digest"] != fingerprint(root)["environment_digest"]


def test_editable_and_external_site_link_fail_closed(tmp_path: Path) -> None:
    fingerprint = load_fingerprint()
    root, site = venv(tmp_path)
    metadata = site / "example.dist-info"
    metadata.mkdir()
    (metadata / "direct_url.json").write_text('{"dir_info":{"editable":true}}')
    with pytest.raises(ValueError, match="editable distribution"):
        fingerprint(root)
    (metadata / "direct_url.json").unlink()
    outside = tmp_path.parent / "outside-module.py"
    outside.write_text("external")
    (site / "outside.py").symlink_to(outside)
    with pytest.raises(ValueError, match="site-packages symlink"):
        fingerprint(root)


def test_system_site_packages_fail_closed(tmp_path: Path) -> None:
    fingerprint = load_fingerprint()
    root, _ = venv(tmp_path)
    (root / "pyvenv.cfg").write_text("include-system-site-packages = true\n")
    with pytest.raises(ValueError, match="system site packages"):
        fingerprint(root)
