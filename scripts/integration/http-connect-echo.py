#!/usr/bin/env python3
"""Small deterministic HTTP CONNECT proxy used by live parity smoke tests."""

import socket
import sys
import threading


def serve(client: socket.socket) -> None:
    try:
        request = b""
        while b"\r\n\r\n" not in request and len(request) < 16384:
            chunk = client.recv(4096)
            if not chunk:
                return
            request += chunk
        print(f"request={request!r}", flush=True)
        if not request.startswith(b"CONNECT "):
            return
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        while True:
            chunk = client.recv(65536)
            if not chunk:
                return
            print(f"payload={chunk!r}", flush=True)
            if chunk.startswith((b"GET ", b"HEAD ")):
                client.sendall(
                    b"HTTP/1.1 204 No Content\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
            else:
                client.sendall(chunk)
            print("echoed", flush=True)
    finally:
        client.close()


port = int(sys.argv[1])
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("0.0.0.0", port))
listener.listen(32)

while True:
    client, _ = listener.accept()
    threading.Thread(target=serve, args=(client,), daemon=True).start()
