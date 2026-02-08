# MIT License © 2025 Motohiro Suzuki
"""
Attack-04: Wrong Session ID (Stage181)

Proof:
- Inject an APP frame with a different SID into recv()
- Expected: qsp.errors.WrongSessionID (FailClosed)

This avoids real TCP so CI is deterministic.
"""

import os
import sys
import struct
import hashlib
import inspect
import traceback
from typing import Any, Optional

# Ensure repo root importable
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from qsp.errors import WrongSessionID
from qsp.sdk import QspSDK
from qsp.types import SDKConfig


class DummyPolicy:
    # matches what QspSDK uses in sdk.py
    def allow_mode(self, *, requested: Any, observed: Any) -> bool:
        return True

    def should_rekey(self, *, epoch: int, bytes_sent: int, bytes_recv: int) -> bool:
        return False


class FakeIO:
    """
    Minimal FrameIO-like object:
      - recv_frame(max_bytes=...) -> bytes
      - send_frame(frame: bytes)  (not used here)
    """
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
        # not needed for this attack
        pass


def ok(msg: str) -> None:
    print(f"[OK] {msg}")


def ng(msg: str) -> None:
    print(f"[NG] {msg}")
    raise SystemExit(1)


def make_sdk_config() -> SDKConfig:
    """
    Create SDKConfig even if fields evolve.
    We fill common fields by name when present.
    """
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
            # leave default
            pass
        else:
            # required but unknown -> safe placeholder
            # (if this trips, paste the error and we’ll set it properly)
            kwargs[name] = defaults.get(name, None)

    return SDKConfig(**kwargs)  # type: ignore[arg-type]


def wire_handshake_state(sdk: QspSDK, sid: int) -> None:
    """
    Force minimal 'handshake complete' state for deterministic unit attack.
    We set exactly the fields used by recv()/fail-closed paths.
    """
    sdk._started = True
    sdk._handshake_complete = True
    sdk._session_id = sid
    sdk._epoch = 1
    sdk._mode = "PQC_ONLY"

    # transcript/receipt are referenced by update paths in sdk.py
    sdk._transcript_hasher = hashlib.sha256()
    sdk._receipt_chain_hash = hashlib.sha256(str(sid).encode()).hexdigest()

    # role/peer just for completeness
    sdk._role = "client"
    sdk._peer = "127.0.0.1:0000"


def main() -> None:
    cfg = make_sdk_config()
    policy = DummyPolicy()

    # This is our "Session B" (victim)
    victim = QspSDK(cfg=cfg, policy=policy)

    sid_victim = 0x1111111111111111
    sid_attacker = 0x2222222222222222  # different SID

    # Craft an APP frame with wrong SID: 8 bytes SID + payload
    payload = b"attack-04-wrong-sid"
    forged_frame = struct.pack(">Q", sid_attacker) + payload

    # Wire deterministic state + inject forged frame into recv path
    wire_handshake_state(victim, sid=sid_victim)
    victim._io = FakeIO([forged_frame])

    try:
        _ = victim.recv(max_bytes=1_048_576)
        ng("WrongSessionID was NOT raised (attack succeeded unexpectedly)")
    except WrongSessionID:
        ok("wrong session id rejected (expected)")
        return
    except Exception as e:
        print(traceback.format_exc())
        ng(f"unexpected exception: {e.__class__.__name__}: {e}")


if __name__ == "__main__":
    main()
