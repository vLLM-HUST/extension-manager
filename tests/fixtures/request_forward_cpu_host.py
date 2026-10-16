"""Synthetic tensor/model fixture with actual HTTP and separate Unix senders.

This file is exclusively a CPU wiring fixture; it is never model/NPU evidence.
"""

import argparse
import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from experiments.exposure_gate import native_semantic_collector as native


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--peer-source", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    children = []
    peers = []
    try:
        for role, rank in (("api-server", 0), ("worker", 0), ("worker", 1)):
            process = subprocess.Popen(
                [sys.executable, str(args.peer_source), role, str(rank)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            children.append(process)
            raw = process.stdout.readline()
            if not raw:
                raise ValueError(process.stderr.read())
            peers.append(json.loads(raw))
        print(
            json.dumps({"host": native.identity(os.getpid()), "peers": peers}),
            flush=True,
        )
        config = json.loads(sys.stdin.readline())

        def command(index, operation, runtime, **fields):
            process = children[index]
            request = {
                "op": operation,
                "runtime": runtime,
                "ready": config["ready"],
                "dir": config["directories"].get(str(process.pid)),
                **fields,
            }
            process.stdin.write(json.dumps(request) + "\n")
            process.stdin.flush()
            result = json.loads(process.stdout.readline())
            if "rejected" in result:
                raise ValueError(result["rejected"])

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                try:
                    body = json.loads(
                        self.rfile.read(int(self.headers["Content-Length"]))
                    )
                    phase = next(
                        p
                        for p in config["recipe"]["phases"]
                        if p["client_request_id"] == body["request_id"]
                    )
                    runtime = "CPU-runtime/" + body["request_id"]
                    command(
                        0, "mapping", runtime, external=phase["external_request_id"]
                    )
                    for index in (1, 2):
                        command(index, "facts", runtime)
                    for index in (1, 2):
                        command(index, "attention", runtime)
                    raw = native.canonical(
                        {
                            "id": phase["expected_response_id"],
                            "model": phase["payload"]["model"],
                            "choices": [
                                {
                                    "message": {
                                        "content": phase["response_oracle"]["expected"]
                                    },
                                    "finish_reason": "stop",
                                }
                            ],
                            "usage": {"prompt_tokens": 1201, "completion_tokens": 40},
                        }
                    )
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    self.wfile.flush()
                    for index in (1, 2):
                        command(index, "drain", runtime)
                except Exception as error:
                    print(str(error), file=sys.stderr, flush=True)
                    self.send_error(500)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
        print(json.dumps({"HTTP_ready": True}), flush=True)
        server.serve_forever()
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)


if __name__ == "__main__":
    main()
