"""CPU HTTP fixture with real response IDs; never model evidence."""

from __future__ import annotations

import argparse
import http.server
import json
import os
from pathlib import Path


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        request_id = self.headers.get("X-ECPA-Request-ID")
        admission_id = self.headers.get("X-ECPA-Admission-ID")
        body = json.dumps(
            {
                "id": "response/" + str(request_id),
                "model": value["model"],
                "model_generation": 0,
                "backend_pid": os.getpid(),
                "admission_id": admission_id,
                "choices": [{"index": 0, "text": "ECPA", "finish_reason": "stop"}],
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    args = parser.parse_args()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    args.ready.write_text(str(os.getpid()))
    server.serve_forever()


if __name__ == "__main__":
    main()
