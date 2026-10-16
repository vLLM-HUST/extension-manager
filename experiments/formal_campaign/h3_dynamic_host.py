#!/usr/bin/env python3
"""Exact source entry for real Manager and Host activation; no mock Host.

manager: delegate arguments to the installed source-admitted Manager CLI.
baseline/managed-host: delegate to the real vLLM activation entry, preserving
its independent baseline flags and Manager-owned environment checks.
"""

import sys


def main():
    if len(sys.argv) < 2:
        raise ValueError("explicit Manager or Host role required")
    mode = sys.argv[1]
    if mode == "manager":
        from vllm_hust_ext.cli import main as manager_main

        return manager_main(sys.argv[2:])
    if mode in {"baseline", "managed-host"}:
        from vllm_hust_ext.runtime_activation import main as host_main

        sys.argv = [sys.argv[0], *sys.argv[2:]]
        host_main()
        return 0
    raise ValueError("unknown real launch role")


if __name__ == "__main__":
    raise SystemExit(main())
