# MIT License © 2025 Motohiro Suzuki
"""
Attack-04: Wrong Session ID

Goal:
- Prove that receiving an APP frame with a different SID is rejected (fail-closed).

Mechanism:
- FakeIO injects a single APP frame whose SID != victim's session_id.
- victim.recv() must raise WrongSessionID (FailClosed subclass).
"""

from __future__ import annotations

import os
import sys
import struct
import hashlib
from collections import deque

# --- Force imports to use THIS repo (stage181), not other editable installs ---
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from qsp.sdk import QspSDK
from qsp.errors import WrongSessionID, FailClosed
from qsp.types import SDKConfig


class AllowAllPolicy:
    policy_id = "test-allow-all"

    def should_rekey(self, *, epoch: int, bytes_sent: int, bytes_recv: int) -> bool:
        return False

    def allow_mode(self, *, requested: str, observed: str) -> bool:
        return True


class FakeIO:
    """Minimal FrameIO replacement for injecting frames."""

    def __init__(self, frames: list[bytes]):
        self._frames = list(frames)
        self.sent: list[bytes] = []
        self.closed = False

    def send_frame(self, frame: bytes) -> None:
        self.sent.append(bytes(frame))

    def recv_frame(self, *, max_bytes: int) -> bytes:
        if self.closed:
            raise RuntimeError("FakeIO closed")
        if not self._frames:
            raise RuntimeError("FakeIO: no more frames")
        frame = self._frames.pop(0)
        if len(frame) > max_bytes:
            raise RuntimeError("FakeIO: frame too large")
        return frame

    def close(self) -> None:
        self.closed = True


def pack_app_frame(sid: int, payload: bytes) -> bytes:
    return struct.pack(">Q", sid) + payload


def wire_handshake_state(sdk: QspSDK, *, sid: int) -> None:
    """Force SDK into post-handshake state without TCP (CI parity)."""
    sdk._started = True
    sdk._handshake_complete = True
    sdk._session_id = sid
    sdk._epoch = 1
    sdk._mode = "PQC_ONLY"

    # ---- Replay detection state (Stage181) ----
    # CI では recv() パスが「未初期化扱い」になることがあるため、
    # 可能性のある内部状態を“全部”埋めてパリティを確保する。
    sdk._replay_cache = set()

    # limit name observed in your local error: _replay_cache_limit
    if not hasattr(sdk, "_replay_cache_limit") or getattr(sdk, "_replay_cache_limit") is None:
        sdk._replay_cache_limit = 1024  # safe default (must be > 0)

    # some implementations also keep FIFO order for eviction
    if not hasattr(sdk, "_seen_app_frame_order") or getattr(sdk, "_seen_app_frame_order") is None:
        sdk._seen_app_frame_order = deque(maxlen=int(sdk._replay_cache_limit))

    # If implementation uses a separate container name, seed it too (harmless if unused)
    if not hasattr(sdk, "_seen_app_frame_hashes") or getattr(sdk, "_seen_app_frame_hashes") is None:
        sdk._seen_app_frame_hashes = set()

    # ---- Other post-handshake internals used by recv() / receipts ----
    sdk._transcript_hasher = hashlib.sha256()
    sdk._receipt_chain_hash = hashlib.sha256(str(sid).encode()).hexdigest()


def main() -> None:
    print("=== attack-04 wrong-session-id ===")

    cfg = SDKConfig(
        enable_qkd=False,
        key_len=32,
        sig_alg="ed25519",
        kem_alg="toy_kem",
        app_aead="aes-gcm",
    )

    victim = QspSDK(cfg=cfg, policy=AllowAllPolicy())

    sid_expected = 111
    sid_wrong = 222
    payload = b"BADSID"

    bad_frame = pack_app_frame(sid_wrong, payload)
    fake = FakeIO([bad_frame])

    victim._io = fake
    wire_handshake_state(victim, sid=sid_expected)

    try:
        _ = victim.recv(max_bytes=1_048_576)
        print("[NG] wrong session id NOT rejected")
        sys.exit(1)
    except WrongSessionID:
        print("[OK] wrong session id rejected (expected)")
        return
    except FailClosed as e:
        print(f"[NG] unexpected FailClosed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
