"""Prepare exact new clean Host/KV sources; optionally run genuine wheel builders.

Never edits an existing source/env or starts NPU. This source/wheel handoff is not
hardware qualification or formal producer registration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).parent


def run(args, cwd=None, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def audit_wheel(source, wheel):
    errors = []
    count = 0
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if not name.endswith(".py") or name.startswith("vllm/_version"):
                continue
            relative = name
            if name.startswith("vllm_ascend_kvcompress/"):
                relative = "src/" + name
            path = source / relative
            if not path.is_file():
                errors.append({"path": name, "reason": "missing source"})
            elif path.read_bytes() != archive.read(name):
                errors.append({"path": name, "reason": "source bytes differ"})
            count += 1
    if errors:
        raise ValueError("genuine wheel source audit failed: " + json.dumps(errors))
    return {
        "wheel": str(wheel),
        "sha256": digest(wheel.read_bytes()),
        "packaged_python_count": count,
        "source_errors": errors,
    }


def prepare(*, host_repository, kv_repository, output, build=False, uv="uv"):
    manifest = json.loads((ROOT / "artifact-source/binding.json").read_text())
    if output.exists():
        raise ValueError("new handoff root must not already exist")
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    result = {
        "classification": "SOURCE_WHEEL_HANDOFF_UNQUALIFIED",
        "runtime_contract": "REAL_RUNTIME_UNQUALIFIED",
        "formal_registration": False,
        "GPU_qualification": None,
        "attention_consumption": None,
        "full_model_quality": None,
        "protocol_binding_sha256": digest(
            (ROOT / "artifact-source/binding.json").read_bytes()
        ),
        "sources": {},
    }
    from experiments.exposure_gate import native_semantic_collector

    collector = Path(native_semantic_collector.__file__).read_bytes()
    if digest(collector) != manifest["Host_existing_collector_sha256"]:
        raise ValueError(
            "collector dependency changed; regenerate explicit source binding"
        )
    for kind, repository, commit, patch in [
        (
            "Host",
            host_repository,
            manifest["Host_base_commit"],
            "host-private-tensor-artifact.patch",
        ),
        (
            "KV",
            kv_repository,
            manifest["KV_base_commit"],
            "kv-private-tensor-artifact.patch",
        ),
    ]:
        source = output / kind.lower()
        patch_path = ROOT / "artifact-source" / patch
        if digest(patch_path.read_bytes()) != manifest["patch_sha256"][patch]:
            raise ValueError("frozen source patch changed")
        run(["git", "worktree", "add", "--detach", str(source), commit], cwd=repository)
        run(["git", "apply", str(patch_path)], cwd=source)
        if kind == "Host":
            (source / "vllm/plugins/native_semantic_collector.py").write_bytes(
                collector
            )
            expected = {x["path"]: x["sha256"] for x in manifest["Host_new_files"]}
            expected["vllm/plugins/native_semantic_collector.py"] = digest(collector)
        else:
            expected = {x["path"]: x["postimage_sha256"] for x in manifest["KV_files"]}
        for relative, expected_sha in expected.items():
            if digest((source / relative).read_bytes()) != expected_sha:
                raise ValueError("prepared source bytes differ: " + relative)
        run(["git", "add", "."], cwd=source)
        run(
            [
                "git",
                "-c",
                "user.name=ECPA Source Builder",
                "-c",
                "user.email=ecpa-source-builder@localhost",
                "commit",
                "-m",
                "Freeze real-runtime-unqualified tensor artifact source",
            ],
            cwd=source,
        )
        if run(["git", "status", "--porcelain"], cwd=source):
            raise ValueError("new source is dirty")
        receipt = {
            "directory": str(source),
            "base_commit": commit,
            "commit": run(["git", "rev-parse", "HEAD"], cwd=source),
            "tree": run(["git", "rev-parse", "HEAD^{tree}"], cwd=source),
            "source_clean": True,
            "critical_source_sha256": expected,
        }
        if build:
            wheels = output / (kind.lower() + "-wheels")
            wheels.mkdir()
            # Same genuine empty Host target used for the established Ascend
            # tuple. This is a build target, not a device/runtime result.
            environment = os.environ | {"VLLM_TARGET_DEVICE": "empty"}
            with (output / (kind.lower() + "-build.log")).open("w") as log:
                subprocess.run(
                    [uv, "build", "--wheel", "--out-dir", str(wheels)],
                    cwd=source,
                    env=environment,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    check=True,
                )
            candidates = list(wheels.glob("*.whl"))
            if len(candidates) != 1:
                raise ValueError("builder did not produce exactly one genuine wheel")
            receipt["wheel"] = audit_wheel(source, candidates[0])
        result["sources"][kind] = receipt
        (output / "handoff.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-repository", type=Path, required=True)
    parser.add_argument("--kv-repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--uv", default="uv")
    args = parser.parse_args()
    print(
        json.dumps(
            prepare(
                host_repository=args.host_repository.resolve(),
                kv_repository=args.kv_repository.resolve(),
                output=args.output.resolve(),
                build=args.build,
                uv=args.uv,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
