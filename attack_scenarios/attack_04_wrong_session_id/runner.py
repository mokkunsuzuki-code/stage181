# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import socket
import struct
import threading
import time

from qsp.errors import WrongSessionID
from qsp.sdk import QspSDK
from qsp.types import SDKConfig, PolicyHook


HOST = "127.0.0.1"
PORT_OK = 9104
PORT_BAD = 9105


class StrictPolicy(PolicyHook):
    policy_id = "strict-v1"

    def allow_mode(self, *, requested, observed):
        return True if observed is None else (requested == observed)

    def should_rekey(self, *, epoch, bytes_sent, bytes_recv):
        return False

    def on_failover(self, *, reason, from_mode, to_mode):
        print(f"[policy] failover: {from_mode} -> {to_mode} reason={reason}")


def _run_server_ok():
    sdk = QspSDK(cfg=SDKConfig(enable_qkd=True), policy=StrictPolicy())
    info = sdk.session_start(role="server", peer=f"0.0.0.0:{PORT_OK}")
    print(f"[OK/server] started session_id={info.session_id} epoch={info.epoch} mode={info.mode}")
    msg = sdk.recv()
    print(f"[OK/server] recv: {msg!r}")
    sdk.send(b"pong")
    print("[OK/server] sent pong")


def _run_client_ok():
    time.sleep(0.2)
    sdk = QspSDK(cfg=SDKConfig(enable_qkd=True), policy=StrictPolicy())
    info = sdk.session_start(role="client", peer=f"{HOST}:{PORT_OK}")
    print(f"[OK/client] started session_id={info.session_id} epoch={info.epoch} mode={info.mode}")
    sdk.send(b"ping")
    msg = sdk.recv()
    print(f"[OK/client] recv: {msg!r}")
    assert msg == b"pong"
    print("[OK] normal case PASS")


# -----------------------------
# BAD CASE (SID tamper)
# -----------------------------

def _recvall(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        b = sock.recv(remaining)
        if b == b"":
            raise ConnectionError("socket closed")
        chunks.append(b)
        remaining -= len(b)
    return b"".join(chunks)


def _recv_frame(sock: socket.socket) -> bytes:
    hdr = _recvall(sock, 4)
    (ln,) = struct.unpack(">I", hdr)
    return _recvall(sock, ln)


def _send_frame(sock: socket.socket, payload: bytes) -> None:
    hdr = struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)


def _run_server_bad_expect_wrong_session_id():
    """
    Start SDK server, then expect to fail-closed on recv due to wrong SID.
    """
    sdk = QspSDK(cfg=SDKConfig(enable_qkd=True), policy=StrictPolicy())
    info = sdk.session_start(role="server", peer=f"0.0.0.0:{PORT_BAD}")
    print(f"[BAD/server] started session_id={info.session_id} epoch={info.epoch} mode={info.mode}")

    try:
        _ = sdk.recv()
        raise AssertionError("expected WrongSessionID, but recv succeeded")
    except WrongSessionID as e:
        print(f"[OK] tamper rejected (WrongSessionID): {e}")
        print("[OK] tamper case PASS")


def _run_client_bad_tamper_sid():
    """
    Raw socket client:
      - connect
      - receive handshake SID frame ("SID:<sid>")
      - send APP frame with a DIFFERENT SID (8 bytes) + b"ping"
    """
    time.sleep(0.2)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT_BAD))

    # receive handshake SID frame
    hs = _recv_frame(s)
    # hs looks like b"SID:<digits>"
    # print only for visibility
    try:
        print(f"[BAD/client] got handshake: {hs.decode('ascii')}")
    except Exception:
        print(f"[BAD/client] got handshake (non-ascii): {hs!r}")

    # tamper: choose a wrong SID (flip one bit)
    # our APP frame format is: [8 bytes SID big-endian] + payload
    # We DO NOT need the real SID value; any different SID will do.
    wrong_sid = 0xDEADBEEFDEADBEEF
    app = struct.pack(">Q", wrong_sid) + b"ping"
    _send_frame(s, app)
    print("[BAD/client] sent tampered app frame (wrong SID)")

    try:
        # server will close on fail-closed
        time.sleep(0.2)
    finally:
        s.close()


def main() -> None:
    print("=== Attack-04: wrong_session_id (Stage180 SDK) ===")

    # Case 1: Normal PASS
    t1 = threading.Thread(target=_run_server_ok, daemon=True)
    t2 = threading.Thread(target=_run_client_ok, daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    print("\n---\n")

    # Case 2: Tamper SID should be rejected (PASS)
    t3 = threading.Thread(target=_run_server_bad_expect_wrong_session_id, daemon=True)
    t4 = threading.Thread(target=_run_client_bad_tamper_sid, daemon=True)
    t3.start()
    t4.start()
    t3.join(timeout=5)
    t4.join(timeout=5)


if __name__ == "__main__":
    main()
