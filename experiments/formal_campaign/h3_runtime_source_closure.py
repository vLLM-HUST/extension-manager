"""Fresh H3 interpreter/wheel/source closure; no model import or device execution.

The Ascend compatibility proof preserves the original genuine native compile and
checks unchanged inputs and exact native bytes. It never demands a new compile.
"""

from __future__ import annotations

import hashlib
import importlib.metadata as metadata
import importlib.util
import io
import json
import os
import subprocess
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

SCHEMA = "ecpa-h3-actual-runtime-source-closure/v1"
NATIVE_INPUTS = (
    "csrc",
    "cmake",
    "CMakeLists.txt",
    ".gitmodules",
    "setup.py",
    "build_version.py",
    "pyproject.toml",
    "requirements.txt",
    "vllm_ascend/envs.py",
    "vllm_ascend/device",
    "vllm_ascend/__init__.py",
    "vllm_ascend/_triton_compat.py",
)


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(ref):
    path = Path(ref["path"])
    require(
        path.is_absolute() and path.is_file() and not path.is_symlink(),
        "runtime proof reference is not a regular absolute file",
    )
    raw = path.read_bytes()
    require(
        sha(raw) == ref["sha256"].removeprefix("sha256:"),
        "runtime proof bytes changed: " + str(path),
    )
    return raw


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, timeout=240
    ).stdout


def _elfs(path):
    result = {}
    raw_wheel = path if type(path) is bytes else Path(path).read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw_wheel)) as archive:
        for name in archive.namelist():
            if name.endswith("/"):
                continue
            raw = archive.read(name)
            native = raw[:4] == b"\x7fELF"
            require(
                not name.endswith((".so", ".o", ".a")) or native,
                "native payload has no supported genuine ELF proof",
            )
            if native:
                result[name] = sha(raw)
    return result


def _build_proof(item, root, revision, wheel_elfs):
    proof = item.get("build_proof")
    if proof is None:
        require(not wheel_elfs, "native wheel needs its source/compile proof")
        return {}, set()
    report = json.loads(checked(proof["report"]))
    require(
        report.get("official_commit", report.get("commit")) == revision,
        "build proof official revision differs",
    )
    tree = report.get("tree", report.get("source_tree"))
    if tree is not None:
        require(
            tree == git(root, "rev-parse", revision + "^{tree}").decode().strip(),
            "build proof official source tree differs",
        )
    wheels = report.get("wheels", [])
    wheel_sha = item["wheel"]["sha256"].removeprefix("sha256:")
    require(
        any(row["sha256"] == wheel_sha for row in wheels)
        or report.get("wheel_sha256") == wheel_sha,
        "build proof does not bind exact wheel",
    )
    if not wheel_elfs:
        require(report.get("exit_code", 0) == 0, "source wheel build did not succeed")
        return {}, {"vllm/_version.py", "vllm_ascend/_version.py"}
    require(
        report.get("schema")
        == "ecpa-published-Ascend-Host47-compatible-wheel-build/v1",
        "unsupported native source proof; retain real compile provenance",
    )
    require(
        report["native_build_inputs_exact_base_unchanged"] is True
        and report["native_build_inputs_changed"] == []
        and report["native_compile_reexecuted"] is False
        and all(row["exitcode"] == 0 for row in report["commands"]),
        "native compatibility build proof differs",
    )
    parent = report["parent"]
    git(root, "merge-base", "--is-ancestor", parent, revision)
    expected_entries = report["native_build_input_Git_entries"]
    for commit in (parent, revision):
        entries = git(root, "ls-tree", "-r", commit, "--", *NATIVE_INPUTS)
        require(
            entries.decode().splitlines() == expected_entries,
            "native source inputs changed or proof inventory is incomplete",
        )
    parent_report = json.loads(checked(proof["parent_report"]))["ascend"]
    require(
        parent_report["official_commit"] == parent,
        "native parent proof names another source",
    )
    compile_report = json.loads(checked(parent_report["original_full_compile_record"]))
    require(
        compile_report["exit_code"] == 0
        and compile_report["native_cache_reuse_requested"] is False
        and compile_report["source_tree"]
        == parent_report["source_tree"]
        == git(root, "rev-parse", parent + "^{tree}").decode().strip(),
        "genuine original compile source/tree differs",
    )
    originals = compile_report["wheels"]
    require(len(originals) == 1, "original native compile wheel is ambiguous")
    original_ref = proof.get("original_compile_wheel", originals[0])
    require(
        original_ref["sha256"] == originals[0]["sha256"],
        "relocated original compile wheel has another digest",
    )
    original_raw = checked(original_ref)
    require(
        _elfs(original_raw) == wheel_elfs,
        "native wheel bytes differ from genuine original compile",
    )
    audit = json.loads(checked(proof["byte_audit"]))
    require(
        audit["official_commit"] == revision
        and audit["parent"] == parent
        and audit["ELF_sha256"] == wheel_elfs,
        "native byte audit differs from actual complete ELF inventory",
    )
    generated = {}
    for row in audit["generated_Python_sources"]:
        ref = {
            "path": row["original_genuine_generated_source"],
            "sha256": row["sha256"],
        }
        generated[row["path"]] = sha(checked(ref))
        with zipfile.ZipFile(io.BytesIO(original_raw)) as original_archive:
            require(
                sha(original_archive.read(row["path"])) == generated[row["path"]],
                "generated Python differs from the genuine compile wheel",
            )
    # setup.py generates this device-family declaration; it is not tracked Git
    # source. Its setup.py input is already in the unchanged native input set.
    build_info = "vllm_ascend/_build_info.py"
    rows = [row for row in audit["Python_sources"] if row["path"] == build_info]
    require(len(rows) == 1, "generated build-info byte audit missing")
    with zipfile.ZipFile(io.BytesIO(original_raw)) as original_archive:
        require(
            sha(original_archive.read(build_info)) == rows[0]["sha256"],
            "generated build-info differs from genuine native build",
        )
    generated[build_info] = rows[0]["sha256"]
    return generated, {"vllm_ascend/_version.py"}


def _source_members(item, root, revision):
    """Compare wheel Python against immutable Git objects, including src layout."""
    wheel = item["wheel"]
    wheel_raw = checked(wheel)
    wheel_elfs = _elfs(wheel_raw)
    generated, version_files = _build_proof(item, root, revision, wheel_elfs)
    tree = git(root, "ls-tree", "-r", revision).decode().splitlines()
    entries = {
        line.split("\t", 1)[1]: line.split()[2]
        for line in tree
        if line.split()[1] == "blob"
    }
    checked_members = {}
    process = subprocess.Popen(
        ["git", "-C", str(root), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_raw)) as archive:
            for name in archive.namelist():
                if not name.endswith(".py") or ".dist-info/" in name:
                    continue
                raw = archive.read(name)
                candidates = [p for p in (name, "src/" + name) if p in entries]
                if name in version_files:
                    # Generated version is pinned by its actual official build
                    # report + wheel; it is not represented as a Git source blob.
                    require(
                        revision[:7].encode() in raw,
                        "generated version does not name the admitted commit",
                    )
                elif name in generated:
                    require(
                        sha(raw) == generated[name],
                        "genuine generated Python bytes differ",
                    )
                else:
                    require(
                        len(candidates) == 1,
                        "wheel Python has no unique admitted source: " + name,
                    )
                    blob = entries[candidates[0]]
                    process.stdin.write((blob + "\n").encode())
                    process.stdin.flush()
                    header = process.stdout.readline().split()
                    require(
                        len(header) == 3
                        and header[0].decode() == blob
                        and header[1] == b"blob",
                        "Git blob header differs",
                    )
                    size = int(header[2])
                    source = process.stdout.read(size)
                    require(
                        process.stdout.read(1) == b"\n"
                        and hashlib.sha1(
                            b"blob " + str(size).encode() + b"\0" + source
                        ).hexdigest()
                        == blob,
                        "actual Git blob bytes differ",
                    )
                    require(source == raw, "wheel Python differs from source: " + name)
                checked_members[name] = sha(raw)
    finally:
        process.stdin.close()
        require(process.wait(timeout=240) == 0, "Git object reader failed")
    return {"Python": checked_members, "native_ELF": wheel_elfs}


def _probe_role(role, item):
    result = {}
    dist = metadata.distribution(item["distribution"])
    wheel = item["wheel"]
    require(dist.version == wheel["version"], "actual runtime version differs")
    payload, roots = {}, set()
    wheel_raw = checked(wheel)
    with zipfile.ZipFile(io.BytesIO(wheel_raw)) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "wheel has repeated members")
        for name in names:
            parts = PurePosixPath(name).parts
            require(
                parts and not name.startswith("/") and ".." not in parts,
                "unsafe wheel member",
            )
            if name.endswith("/") or name.endswith(".dist-info/RECORD"):
                continue
            relative = name
            if parts[0].endswith(".data"):
                require(
                    len(parts) > 2 and parts[1] in {"purelib", "platlib"},
                    "unsupported wheel relocation",
                )
                relative = str(PurePosixPath(*parts[2:]))
            path = Path(dist.locate_file(relative))
            require(
                path.is_file() and not path.is_symlink() and path.resolve() == path,
                "actual installed wheel payload path differs: " + name,
            )
            installed_raw = path.read_bytes()
            require(
                installed_raw == archive.read(name),
                "actual installed wheel payload differs: " + name,
            )
            payload[str(path)] = sha(installed_raw)
            if not parts[0].endswith(".dist-info"):
                roots.add(Path(dist.locate_file(PurePosixPath(relative).parts[0])))
    for root in roots:
        if root.is_dir():
            for path in root.rglob("*"):
                if path.is_file() and (
                    path.suffix in {".py", ".so", ".o", ".a"}
                    or path.read_bytes()[:4] == b"\x7fELF"
                ):
                    require(str(path) in payload, "unrecorded runtime payload")
    module = item["module"]
    require(module.isidentifier(), "probe module must be a top-level package")
    found = importlib.util.find_spec(module)
    require(
        found is not None and found.origin in payload,
        "actual import origin shadows the admitted installed wheel",
    )
    result[role] = {"origin": found.origin, "payload": payload}
    return result[role]


def _probe_roles(items):
    declarations = list(items.items())
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(_probe_role, role, item) for role, item in declarations
        ]
        observations = [future.result() for future in futures]
    return {
        role: result
        for (role, _), result in zip(declarations, observations, strict=True)
    }


def _probe(items):
    """Run under the exact child interpreter/environment, without importing Host."""
    result = _probe_roles(items)
    return {
        "python": sys.executable,
        "real_python": str(Path(sys.executable).resolve()),
        "python_sha256": sha(Path(sys.executable).read_bytes()),
        "cwd": os.getcwd(),
        "sys_path": sys.path,
        "distributions": result,
    }


def _source_role(role, revision, runtime_wheels, repositories, names):
    sources = {}
    item = runtime_wheels[role]
    if role in names:
        require(
            (item["distribution"].replace("_", "-").lower(), item["module"])
            == names[role],
            "runtime component distribution/module differs",
        )
    require(
        item["wheel"]["revision"] == revision,
        "runtime wheel and fixed source revision differ",
    )
    root = Path(repositories[role]["path"])
    sources[role] = _source_members(item, root, revision)
    return sources[role]


def _source_roles(expected, runtime_wheels, repositories, names):
    declarations = list(expected.items())
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(
                _source_role, role, revision, runtime_wheels, repositories, names
            )
            for role, revision in declarations
        ]
        observations = [future.result() for future in futures]
    return {
        role: result
        for (role, _), result in zip(declarations, observations, strict=True)
    }


def verify_runtime_source_closure(phase, fixed, repositories, runtime_wheels):
    """Recompute all source/wheel/runtime facts; no caller-issued validity token."""
    from experiments.formal_campaign.source_provenance import subjects

    expected = subjects(fixed)
    require(
        set(runtime_wheels) == set(expected), "runtime wheels miss full source tuple"
    )
    require(
        phase["argv"][0] == sys.executable,
        "Host must use the exact admitted runtime interpreter",
    )
    environment = phase["environment"]
    critical = {
        key
        for key in set(os.environ) | set(environment)
        if key.startswith(("PYTHON", "LD_")) or key == "PATH"
    }
    require(
        all(environment.get(k) == os.environ.get(k) for k in critical),
        "Host import/loader environment differs from admitted runtime",
    )
    names = {
        "manager": ("vllm-hust-ext", "vllm_hust_ext"),
        "host": ("vllm", "vllm"),
        "accelerator": ("vllm-ascend", "vllm_ascend"),
    }
    sources = _source_roles(expected, runtime_wheels, repositories, names)
    process = subprocess.run(
        [phase["argv"][0], str(Path(__file__).resolve()), "--probe"],
        input=json.dumps(runtime_wheels).encode(),
        cwd=phase["cwd"],
        env=environment,
        capture_output=True,
        check=True,
        timeout=240,
    )
    probe = json.loads(process.stdout)
    require(
        probe["python"] == phase["argv"][0]
        and probe["cwd"] == str(Path(phase["cwd"]).resolve()),
        "actual phase runtime interpreter/cwd differs",
    )
    return {
        "schema": SCHEMA,
        "sources": sources,
        "actual_runtime": probe,
        "formal_result": False,
    }


if __name__ == "__main__":
    require(
        sys.argv[1:] == ["--probe"], "only the private metadata probe is executable"
    )
    print(json.dumps(_probe(json.loads(sys.stdin.buffer.read())), sort_keys=True))
