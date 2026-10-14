"""Explicit r3 failed-task profile; shared source/raw checks never grant success."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .verify_kv_materialized_partial import inspect, load_archive


def verify_archive(manifest, archive):
    return inspect(
        load_archive(manifest, archive, oracle_failure=True), oracle_failure=True
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_archive(args.manifest, args.archive), indent=2))


if __name__ == "__main__":
    main()
