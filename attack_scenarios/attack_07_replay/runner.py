# MIT License © 2025 Motohiro Suzuki
"""
Attack-07: Replay (Stage181)

Proof:
- Inject the SAME valid APP frame twice into recv()
- Expected: second recv raises qsp.errors.ReplayDetected (FailClosed)

Deterministic (no TCP).
"""

import os
import sys
import struct
import hashlib
import inspect
import traceback
from typing import Any

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from qsp.errors import ReplayDetected
from qsp.sdk import QspSDK
from qsp.types import SDKConfig


class DummyPolicy:
    def allow_mode(self, *, requested: Any, observed: Any) -> bool:
        return True

    def should_rekey(self, *, epoch: int, bytes_sent: int, bytes_recv: int) -> bool:
        return False

    @property
    def policy_id(self) -> str:
        return "DUMMY"


class FakeIO:
    def __init__(self, frames: list[bytes]):
        self._frames = list(frames)

    def recv_frame(self, max_bytes: int = 1_048_576) -> bytes:
        if not self._frames:
            raise RuntimeError("FakeIO: no more frames")
        fr = self._frames.pop(0)
        if len(fr) > max_bytes:
            raise RuntimeError("FakeIO: frame exceeds max_bytes")
        return fr

    def send_frame(self, frame: bytes) -> None:
        pass

    def close(self) -> None:
        pass


def ok(msg: str) -> None:
    print(f"[OK] {msg}")


def ng(msg: str) -> None:
    print(f"[NG] {msg}")
    raise SystemExit(1)


def make_sdk_config() -> SDKConfig:
    sig = inspect.signature(SDKConfig)
    kwargs = {}
    defaults = {
        "enable_qkd": False,
        "key_len": 32,
        "sig_alg": "ed25519",
        "kem_alg": "toy_kem",
        "app_aead": "aes-gcm",
        "qkd_seed": 1234,
    }
    for name, param in sig.parameters.items():
        if name in defaults:
            kwargs[name] = defaults[name]
        elif param.default is not inspect._empty:
            pass
        else:
            kwargs[name] = defaults.get(name, None)
    return SDKConfig(**kwargs)  # type: ignore[arg-type]


def wire_handshake_state(sdk: QspSDK, sid: int) -> None:
    sdk._started = True
    sdk._handshake_complete = True
    sdk._session_id = sid
    sdk._epoch = 1
    sdk._mode = "PQC_ONLY"

    sdk._transcript_hasher = hashlib.sha256()
    sdk._receipt_chain_hash = hashlib.sha256(str(sid).encode()).hexdigest()

    # Stage181 replay cache init (in case session_start not called)
    sdk._seen_app_frame_hashes = set()
    from collections import deque
    sdk._seen_app_frame_order = deque(maxlen=sdk._replay_cache_size)

    sdk._role = "client"
    sdk._peer = "127.0.0.1:0000"


def main() -> None:
    cfg = make_sdk_config()
    policy = DummyPolicy()
    s = QspSDK(cfg=cfg, policy=policy)

    sid = 0x1111111111111111
    payload = b"attack-07-replay"
    frame = struct.pack(">Q", sid) + payload

    wire_handshake_state(s, sid=sid)

    # Inject same frame twice
    s._io = FakeIO([frame, frame])

    try:
        p1 = s.recv()
        if p1 != payload:
            ng("first recv payload mismatch")

        # second recv should be rejected as replay
        _ = s.recv()
        ng("ReplayDetected was NOT raised on duplicate frame")
    except ReplayDetected:
        ok("replay rejected (expected)")
        return
    except Exception as e:
        print(traceback.format_exc())
        ng(f"unexpected exception: {e.__class__.__name__}: {e}")


if __name__ == "__main__":
    main()
