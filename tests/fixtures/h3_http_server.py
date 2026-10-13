from __future__ import annotations

import argparse
import http.server
import os
from pathlib import Path


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            body = b"ok"
        elif self.path == "/request":
            body = b"completion"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("x-ecpa-tuple-supported", "true")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--pid-file", type=Path, required=True)
    args = parser.parse_args()
    args.pid_file.write_text(str(os.getpid()))
    http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
