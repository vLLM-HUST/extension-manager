"""Join already downloaded artifact parts and optionally reconstruct raw members.

Uses only the standard library. It makes no fresh OS or semantic claims.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath


def sha(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            result.update(block)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--extract-members", type=Path)
    args = parser.parse_args()
    bundle = args.bundle
    parts = json.loads((bundle / "parts.json").read_bytes())
    if parts["schema"] != "ecpa-live-bounded-response-artifact-parts/v1":
        raise ValueError("unexpected parts schema")
    target = bundle / "objects.tar.xz"
    temporary = bundle / "objects.tar.xz.partial"
    with temporary.open("xb") as output:
        for item in parts["parts"]:
            path = PurePosixPath(item["path"])
            if path.is_absolute() or ".." in path.parts or str(path) != item["path"]:
                raise ValueError("unsafe part path")
            source = bundle / str(path)
            if source.stat().st_size != item["bytes"] or sha(source) != item["sha256"]:
                raise ValueError("part integrity failed")
            with source.open("rb") as stream:
                for block in iter(lambda: stream.read(1048576), b""):
                    output.write(block)
        output.flush()
        os.fsync(output.fileno())
    if (
        temporary.stat().st_size != parts["container_bytes"]
        or sha(temporary) != parts["container_sha256"]
    ):
        raise ValueError("joined container integrity failed")
    temporary.replace(target)
    if args.extract_members:
        specification = importlib.util.spec_from_file_location(
            "portable_replay", Path(__file__).with_name("verify_live_bounded_observation.py")
        )
        verifier = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(verifier)
        files, _ = verifier.load_bundle(bundle)
        args.extract_members.mkdir(parents=True, exist_ok=False)
        for name, raw in files.items():
            destination = args.extract_members / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        print(
            json.dumps(
                {
                    "original_regular_members_reconstructed": len(files),
                    "formal_result": False,
                }
            )
        )
    else:
        print(
            json.dumps({"joined_bytes": target.stat().st_size, "sha256": sha(target)})
        )


if __name__ == "__main__":
    main()
