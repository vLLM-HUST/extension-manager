"""Check exact patch preimages/application and Python syntax without a device."""

from __future__ import annotations

import ast
import gzip
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path


def check(root: Path):
    binding = json.loads((root / "source-binding.json").read_text())
    for entry in binding["sources"]:
        label = entry["patch"].split(".")[0]
        data = gzip.decompress((root / f"{label}.source.gz").read_bytes())
        if hashlib.sha256(data).hexdigest() != entry["source_sha256"]:
            raise ValueError("native source preimage changed")
        patch = root / entry["patch"]
        if (
            hashlib.sha256(patch.read_bytes()).hexdigest()
            != binding["patch_sha256"][entry["patch"]]
        ):
            raise ValueError("native patch changed")
        with tempfile.TemporaryDirectory(prefix="ecpa-native-patch-cpu-") as directory:
            tree = Path(directory)
            source = tree / entry["path"]
            source.parent.mkdir(parents=True)
            source.write_bytes(data)
            subprocess.run(
                ["git", "apply", "--check", str(patch.resolve())], cwd=tree, check=True
            )
            subprocess.run(["git", "apply", str(patch.resolve())], cwd=tree, check=True)
            ast.parse(source.read_text())
            if label == "host":
                module = tree / "vllm/plugins/native_block_table_observer.py"
                ast.parse(module.read_text())
                if (
                    hashlib.sha256(module.read_bytes()).hexdigest()
                    != binding["native_observer_sha256"]
                ):
                    raise ValueError("observer module differs from patch")
    return {
        "classification": "CPU_PATCH_CONTRACT_CHECK_ONLY",
        "hardware_result": False,
        "formal_result": False,
    }


if __name__ == "__main__":
    print(json.dumps(check(Path(__file__).parent)))
