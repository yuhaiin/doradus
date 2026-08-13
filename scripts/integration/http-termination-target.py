#!/usr/bin/env python3
"""One-shot HTTP target used by the Go/Rust termination parity smoke."""

import socket
import sys
import time


def read_headers(conn: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > 64 * 1024:
            raise RuntimeError("HTTP request headers exceed the test bound")
    return bytes(data)


def main() -> int:
    port = int(sys.argv[1])
    expected_path = sys.argv[2]
    expected_host = sys.argv[3]
    expected_requests = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    if expected_requests < 1:
        raise SystemExit("expected request count must be positive")
    served = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen(1)
        while served < expected_requests:
            conn, _ = listener.accept()
            with conn:
                request = read_headers(conn)
                # The integration driver probes the inbound listener by
                # opening and immediately closing a TCP connection. Do not
                # let that probe consume the one-shot target.
                if not request:
                    continue
                first_line = request.split(b"\r\n", 1)[0]
                expected_prefix = f"GET {expected_path} HTTP/1.1".encode()
                if not first_line.startswith(expected_prefix):
                    raise RuntimeError(
                        f"unexpected request line: {first_line!r}, expected {expected_prefix!r}"
                    )
                lower = request.lower()
                if f"host: {expected_host}\r\n".encode() not in lower:
                    raise RuntimeError(f"missing target Host header: {request!r}")
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 21\r\n"
                    b"Connection: keep-alive\r\n\r\n"
                    b"termination-parity-ok"
                )
                served += 1
                # Keep the target-side connection visible briefly so the
                # integration driver can inspect the live connections entry.
                time.sleep(0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
