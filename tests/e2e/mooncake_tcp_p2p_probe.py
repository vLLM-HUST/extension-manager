"""Official Mooncake TransferEngine TCP/P2PHANDSHAKE data-path probe."""

from __future__ import annotations

import argparse
import ctypes
import json
import multiprocessing
import socket
import time
from typing import Any

from mooncake.engine import TransferEngine

_HOSTNAME = "localhost"
_METADATA_SERVER = "P2PHANDSHAKE"
_PROTOCOL = "tcp"
_DEVICE_NAME = ""


def _recv_json_line(sock: socket.socket) -> dict[str, Any]:
    chunks: list[bytes] = []
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
        if b"\n" in chunk:
            break
    payload = b"".join(chunks).split(b"\n", 1)[0]
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("coordination payload is not an object")
    return value


def _receiver(coordination_port: int, buffer_size: int) -> None:
    engine = TransferEngine()
    initialize_result = engine.initialize(
        _HOSTNAME, _METADATA_SERVER, _PROTOCOL, _DEVICE_NAME
    )
    session_id = f"{_HOSTNAME}:{engine.get_rpc_port()}"
    receiver_buffer = (ctypes.c_uint8 * buffer_size)()
    receiver_ptr = ctypes.addressof(receiver_buffer)
    if engine.register_memory(receiver_ptr, buffer_size) != 0:
        raise RuntimeError("receiver memory registration failed")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", coordination_port))
    listener.listen(1)
    listener.settimeout(30)
    try:
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(30)
            conn.sendall(
                json.dumps(
                    {
                        "session_id": session_id,
                        "ptr": receiver_ptr,
                        "len": buffer_size,
                        "initialize_result": initialize_result,
                    }
                ).encode("utf-8")
                + b"\n"
            )
            acknowledgement = _recv_json_line(conn)
            verified = bytes(receiver_buffer) == b"\x01" * buffer_size
            result = {
                "acknowledgement": acknowledgement,
                "verified": verified,
                "first_byte": receiver_buffer[0],
                "last_byte": receiver_buffer[-1],
            }
            conn.sendall(json.dumps(result).encode("utf-8") + b"\n")
            print(json.dumps({"receiver": result}, sort_keys=True), flush=True)
            if not verified:
                raise RuntimeError("receiver buffer does not match sender payload")
    finally:
        listener.close()
        if engine.unregister_memory(receiver_ptr) != 0:
            raise RuntimeError("receiver memory deregistration failed")


def _connect_with_retry(port: int) -> socket.socket:
    deadline = time.monotonic() + 30
    while True:
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=2)
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def _sender(coordination_port: int, buffer_size: int) -> dict[str, Any]:
    with _connect_with_retry(coordination_port) as sock:
        sock.settimeout(30)
        receiver = _recv_json_line(sock)
        engine = TransferEngine()
        initialize_result = engine.initialize(
            _HOSTNAME, _METADATA_SERVER, _PROTOCOL, _DEVICE_NAME
        )
        sender_buffer = (ctypes.c_uint8 * buffer_size)()
        sender_ptr = ctypes.addressof(sender_buffer)
        ctypes.memset(sender_ptr, 1, buffer_size)
        if engine.register_memory(sender_ptr, buffer_size) != 0:
            raise RuntimeError("sender memory registration failed")
        try:
            transferred = engine.transfer_sync_write(
                str(receiver["session_id"]),
                sender_ptr,
                int(receiver["ptr"]),
                min(buffer_size, int(receiver["len"])),
            )
            if transferred < 0:
                raise RuntimeError(f"Mooncake transfer failed with {transferred}")
            sock.sendall(
                json.dumps(
                    {
                        "transfer_result": transferred,
                        "initialize_result": initialize_result,
                    }
                ).encode("utf-8")
                + b"\n"
            )
            result = _recv_json_line(sock)
            if result.get("verified") is not True:
                raise RuntimeError(f"receiver verification failed: {result}")
            return {
                "receiver_session": receiver["session_id"],
                "transfer_result": transferred,
                "verified": True,
                "bytes": buffer_size,
            }
        finally:
            if engine.unregister_memory(sender_ptr) != 0:
                raise RuntimeError("sender memory deregistration failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--coordination-port", type=int, default=25555)
    parser.add_argument("--buffer-size", type=int, default=1024 * 1024)
    args = parser.parse_args()
    if args.buffer_size <= 0:
        parser.error("buffer size must be positive")

    receiver = multiprocessing.Process(
        target=_receiver,
        args=(args.coordination_port, args.buffer_size),
        name="mooncake-tcp-receiver",
    )
    receiver.start()
    sender_result: dict[str, Any] | None = None
    try:
        sender_result = _sender(args.coordination_port, args.buffer_size)
    finally:
        receiver.join(timeout=35)
        if receiver.is_alive():
            receiver.terminate()
            receiver.join(timeout=5)
    if receiver.exitcode != 0:
        raise RuntimeError(f"receiver exited with {receiver.exitcode}")
    print(json.dumps({"sender": sender_result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
