# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Tuple


def parse_peer(peer: str) -> Tuple[str, int]:
    """
    Parse "host:port" into (host, port).
    """
    if not isinstance(peer, str) or ":" not in peer:
        raise ValueError("peer must be 'host:port'")

    host, port_s = peer.rsplit(":", 1)
    host = host.strip()
    port_s = port_s.strip()

    if not host:
        raise ValueError("host is empty")

    try:
        port = int(port_s)
    except ValueError as e:
        raise ValueError("port must be an integer") from e

    if port <= 0 or port >= 65536:
        raise ValueError("port out of range")

    return host, port


@dataclass
class FrameIO:
    """
    Minimal framed IO over TCP socket.

    Frame format:
      [4 bytes big-endian length][payload bytes]
    """

    sock: socket.socket

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass

    def send_frame(self, payload: bytes) -> None:
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")

        data = bytes(payload)
        header = struct.pack(">I", len(data))
        self._sendall(header + data)

    def recv_frame(self, *, max_bytes: int) -> bytes:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be > 0")

        hdr = self._recvall(4)
        (n,) = struct.unpack(">I", hdr)

        if n > max_bytes:
            raise ValueError("frame too large")

        return self._recvall(n)

    def _sendall(self, data: bytes) -> None:
        view = memoryview(data)
        total = 0
        while total < len(view):
            sent = self.sock.send(view[total:])
            if sent == 0:
                raise ConnectionError("socket connection broken")
            total += sent

    def _recvall(self, n: int) -> bytes:
        chunks = []
        remaining = n
        while remaining > 0:
            chunk = self.sock.recv(remaining)
            if chunk == b"":
                raise ConnectionError("socket connection broken")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


def listen_and_accept(bind_peer: str, *, backlog: int = 1) -> FrameIO:
    host, port = parse_peer(bind_peer)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(backlog)
    conn, _addr = s.accept()
    s.close()
    return FrameIO(conn)


def connect_to(peer: str) -> FrameIO:
    host, port = parse_peer(peer)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return FrameIO(s)
