"""Real CPU child-process fixture; this is never Host/model evidence."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


def fields(pid):
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()


if "--worker" in sys.argv:
    pid = int(os.environ.get("FIXTURE_OUTSIDE_PID", os.getpid()))
    ticks = int(fields(pid)[19])
    if "--stale" in sys.argv:
        ticks -= 1
    row = {
        "schema": "cpu-fixture-worker/v1",
        "launch_id": os.environ["VLLM_ECPA_LAUNCH_ID"],
        "plan_id": os.environ["VLLM_ECPA_PLAN_ID"],
        "observed_at_ns": time.time_ns(),
        "process": {
            "pid": pid,
            "start_ticks": ticks,
            "ordinal": 0,
            "process_epoch": int(os.environ.get("FIXTURE_EPOCH", pid)),
        },
    }
    target = Path(os.environ["VLLM_HUST_EXT_EVIDENCE_PATH"])
    temp = target.with_suffix(".tmp")
    temp.write_text(json.dumps(row) + "\n")
    temp.replace(target)
    if os.environ.get("FIXTURE_HTTP_PORT"):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(
                    self.rfile.read(int(self.headers["Content-Length"]))
                )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "model": request["model"],
                            "usage": {"completion_tokens": 1},
                            "choices": [
                                {
                                    "message": {
                                        "content": os.environ.get(
                                            "FIXTURE_HTTP_CONTENT", "ECPA-WORKER-READY"
                                        )
                                    },
                                    "finish_reason": "stop",
                                }
                            ],
                        }
                    ).encode()
                )

            def log_message(self, *args):
                pass

        ThreadingHTTPServer(
            ("127.0.0.1", int(os.environ["FIXTURE_HTTP_PORT"])), Handler
        ).serve_forever()
    else:
        time.sleep(60)
else:
    process = subprocess.Popen(
        [sys.executable, __file__, "--worker", *sys.argv[1:]],
        start_new_session="--nested" in sys.argv,
    )
    process.wait()
