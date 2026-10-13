from __future__ import annotations

import copy
import json
import os
import socketserver
import threading

import pytest

from experiments.native_challenge_candidate import collector_client as client
from experiments.native_challenge_candidate.request_runner import canonical, sha


def test_describe_authenticates_real_unix_peer_not_only_server_claim(tmp_path):
    os.chmod(tmp_path, 0o700)
    socket_path = tmp_path / "collector.sock"
    journal = tmp_path / "native.jsonl"
    journal.write_bytes(b"CPU fixture, not native Host/GPU evidence\n")
    os.chmod(journal, 0o600)
    spec_path = tmp_path / "spec.json"
    spec_path.write_bytes(b'{"CPU_fixture":true}')
    os.chmod(spec_path, 0o600)
    source = tmp_path / "source.py"
    source.write_text("# CPU describe-only fixture\n")
    source_hash = sha(source.read_bytes())
    kernel = client.identity(os.getpid())
    directory, archive_file = tmp_path.stat(), journal.stat()
    archive = {
        "directory_device": directory.st_dev,
        "directory_inode": directory.st_ino,
        "journal_device": archive_file.st_dev,
        "journal_inode": archive_file.st_ino,
    }
    status = {
        "schema": "ecpa-native-semantic-collector-status/v1",
        "spec_sha256": sha(spec_path.read_bytes()),
        "collector_source_sha256": source_hash,
        "collector": kernel,
        "archive_identity": archive,
        "socket_path": str(socket_path),
        "classification": "CPU_REVIEW_CANDIDATE_ONLY",
        "formal_producer_registration": False,
        "failed": False,
        "acknowledged_prefix": {"next_sequence": 1, "last_event_sha256": "1" * 64},
    }

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            assert json.loads(self.rfile.readline()) == {"op": "describe"}
            self.wfile.write(canonical(status) + b"\n")

    with socketserver.ThreadingUnixStreamServer(str(socket_path), Handler) as server:
        os.chmod(socket_path, 0o600)
        metadata = socket_path.stat()
        status["socket_identity"] = [metadata.st_dev, metadata.st_ino]
        descriptor = {
            "collector": kernel,
            "launcher_observed_identity": dict(kernel),
            "launcher_observed_cmdline_sha256": sha(
                client.Path(f"/proc/{os.getpid()}/cmdline").read_bytes()
            ),
            "collector_source_sha256": source_hash,
            "spec_sha256": sha(spec_path.read_bytes()),
            "socket_identity": status["socket_identity"],
            "archive_identity": archive,
        }
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = client.authenticate(socket_path, descriptor, spec_path, source)
            assert result["kernel_peer"]["pid"] == os.getpid()
            assert result["formal_result"] is False
            wrong = copy.deepcopy(descriptor)
            wrong["collector"]["start_ticks"] += 1
            with pytest.raises(ValueError, match="identity binding"):
                client.authenticate(socket_path, wrong, spec_path, source)
            wrong = copy.deepcopy(descriptor)
            wrong["collector_source_sha256"] = "0" * 64
            with pytest.raises(ValueError, match="source changed"):
                client.authenticate(socket_path, wrong, spec_path, source)
            wrong = copy.deepcopy(descriptor)
            wrong["socket_identity"][1] += 1
            with pytest.raises(ValueError, match="socket identity changed"):
                client.authenticate(socket_path, wrong, spec_path, source)
            status["failed"] = True
            with pytest.raises(ValueError, match="status differs"):
                client.authenticate(socket_path, descriptor, spec_path, source)
            status["failed"] = False
            status.pop("acknowledged_prefix")
            with pytest.raises(ValueError, match="acknowledged prefix missing"):
                client.authenticate(socket_path, descriptor, spec_path, source)
        finally:
            server.shutdown()
            thread.join(timeout=2)
