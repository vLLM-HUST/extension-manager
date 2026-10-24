"""Check install payloads without extracting or importing packaged code."""

from __future__ import annotations

import argparse
import configparser
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

PACKAGE = "vllm_hust_ext"
CONSOLE = {
    "vllm-hust-ext",
    "ecpa-formal-source",
    "ecpa-formal-observer",
    "ecpa-host-launch",
}


def safe(name: str) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        raise ValueError(f"Unsafe distribution member: {name}")
    if {"evidence", "results", "logs", "experiments", "paper"}.intersection(path.parts):
        raise ValueError(f"Evidence/research member: {name}")
    if path.suffix in {".csv", ".tsv", ".log", ".jsonl", ".parquet"}:
        raise ValueError(f"Evidence member: {name}")


def check(directory: Path, source_root: Path) -> None:
    wheels = list(directory.glob("*.whl"))
    sdists = list(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError("Expected exactly one wheel and sdist")
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Duplicate wheel member")
        for info in archive.infolist():
            safe(info.filename)
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("Wheel symlink")
        wheel = {n: archive.read(n) for n in names if not n.endswith("/")}
    with tarfile.open(sdists[0]) as archive:
        names = archive.getnames()
        if len(names) != len(set(names)):
            raise ValueError("Duplicate sdist member")
        roots = {PurePosixPath(n).parts[0] for n in names}
        if len(roots) != 1:
            raise ValueError("Expected one sdist root")
        source = {}
        for member in archive.getmembers():
            safe(member.name)
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("Non-regular sdist member")
            stream = archive.extractfile(member)
            assert stream is not None
            source[member.name.split("/", 1)[1]] = stream.read()
    runtime = {p: b for p, b in wheel.items() if p.startswith(PACKAGE + "/")}
    expected = {
        str(p.relative_to(source_root / "src")): p.read_bytes()
        for p in (source_root / "src" / PACKAGE).rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
    }
    if not runtime or runtime != expected:
        raise ValueError("Wheel runtime differs from source tree")
    if {"src/" + p: b for p, b in runtime.items()} != {
        p: b for p, b in source.items() if p.startswith("src/")
    }:
        raise ValueError("sdist runtime differs from wheel")
    allowed = {"README.md", "pyproject.toml", "PKG-INFO", ".gitignore"}
    if any(not p.startswith("src/") and p not in allowed for p in source):
        raise ValueError("Unexpected sdist payload")
    for name in ("README.md", "pyproject.toml"):
        if source.get(name) != (source_root / name).read_bytes():
            raise ValueError(f"Missing or changed {name}")
    metadata = {p.split("/", 1)[0] for p in wheel if ".dist-info/" in p}
    if len(metadata) != 1:
        raise ValueError("Expected one dist-info directory")
    dist = metadata.pop()
    if any(not p.startswith((PACKAGE + "/", dist + "/")) for p in wheel):
        raise ValueError("Unexpected wheel payload")
    for name in ("METADATA", "WHEEL", "RECORD", "entry_points.txt"):
        if dist + "/" + name not in wheel:
            raise ValueError(f"Missing wheel metadata: {name}")
    if any(
        p.startswith(dist + "/")
        and p[len(dist) + 1 :]
        not in {"METADATA", "WHEEL", "RECORD", "entry_points.txt"}
        for p in wheel
    ):
        raise ValueError("Unexpected wheel metadata payload")
    entries = configparser.ConfigParser()
    entries.read_string(wheel[dist + "/entry_points.txt"].decode())
    if set(entries["console_scripts"]) != CONSOLE:
        raise ValueError("Console entry points changed or missing")
    print("Verified source/wheel/sdist runtime parity and bounded install payload")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument(
        "--source-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    check(args.directory, args.source_root)
