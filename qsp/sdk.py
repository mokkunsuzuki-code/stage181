# MIT License © 2025 Motohiro Suzuki
"""
Stage180 SDK entrypoint.

This implementation provides:
- Real TCP transport with framed messages
- Minimal handshake binding: server sends SID, client adopts SID
- Session binding for application frames: each APP frame carries SID

Stage181 update:
- Replay detection for APP frames (duplicate frame within a session) -> ReplayDetected (FailClosed)

Crypto is still stubbed (plaintext). Stage178/179 components will replace internals.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, cast
import hashlib
import secrets
import time
import struct
from collections import deque

from .types import (
    SDKConfig,
    SessionInfo,
    RekeyResult,
    KeyReceipt,
    PolicyHook,
    Role,
    Mode,
)
from .errors import (
    QspError,
    FailClosed,
    HandshakeNotComplete,
    DowngradeDetected,
    EpochViolation,
    TransportError,
    WrongSessionID,
    ReplayDetected,
)

from .wire.io_async import FrameIO, listen_and_accept, connect_to, parse_peer


def _encode_sid_handshake(sid: int) -> bytes:
    return f"SID:{sid}".encode("ascii")


def _decode_sid_handshake(frame: bytes) -> int:
    try:
        s = frame.decode("ascii")
    except Exception as e:
        raise FailClosed("handshake: SID frame not ascii") from e
    if not s.startswith("SID:"):
        raise FailClosed("handshake: missing SID prefix")
    num = s[4:].strip()
    if not num.isdigit():
        raise FailClosed("handshake: SID not numeric")
    sid = int(num)
    if sid < 0 or sid >= (1 << 64):
        raise FailClosed("handshake: SID out of range")
    return sid


def _pack_app_frame(sid: int, payload: bytes) -> bytes:
    # 8 bytes session_id (big-endian) + payload
    return struct.pack(">Q", sid) + payload


def _unpack_app_frame(frame: bytes) -> tuple[int, bytes]:
    if len(frame) < 8:
        raise FailClosed("app frame too short")
    sid = struct.unpack(">Q", frame[:8])[0]
    payload = frame[8:]
    return sid, payload


@dataclass
class QspSDK:
    cfg: SDKConfig
    policy: PolicyHook

    _started: bool = False
    _handshake_complete: bool = False

    _session_id: Optional[int] = None
    _epoch: int = 0
    _mode: Mode = "PQC_ONLY"

    _bytes_sent: int = 0
    _bytes_recv: int = 0

    _receipt_chain_hash: Optional[str] = None
    _transcript_hasher: Optional[hashlib._Hash] = None

    _io: Optional[FrameIO] = None
    _peer: Optional[str] = None
    _role: Optional[Role] = None

    # Stage181: replay cache (bounded)
    _seen_app_frame_hashes: Optional[set[str]] = None
    _seen_app_frame_order: Optional[deque[str]] = None
    _replay_cache_size: int = 1024

    # -----------------------------------------------------------------
    # (1) session_start
    # -----------------------------------------------------------------
    def session_start(self, *, role: Role, peer: str) -> SessionInfo:
        if self._started:
            raise FailClosed("session already started")

        if role not in ("client", "server"):
            raise QspError("role must be 'client' or 'server'")

        try:
            parse_peer(peer)
        except Exception as e:
            raise QspError(f"invalid peer: {e}") from e

        self._role = role
        self._peer = peer

        try:
            if role == "server":
                self._io = listen_and_accept(peer)
            else:
                self._io = connect_to(peer)

            io = self._require_io()

            self._mode = cast(Mode, "QKD_MIXED" if self.cfg.enable_qkd else "PQC_ONLY")

            # --- Minimal handshake SID binding ---
            if role == "server":
                sid = secrets.randbits(64)
                io.send_frame(_encode_sid_handshake(sid))
                self._session_id = sid
            else:
                frame = io.recv_frame(max_bytes=64)
                sid = _decode_sid_handshake(frame)
                self._session_id = sid

            self._epoch = 1

            self._transcript_hasher = hashlib.sha256()
            self._transcript_hasher.update(
                f"hs:{role}:{peer}:{self._session_id}:{self._mode}:{self.cfg.key_len}:{self.cfg.sig_alg}:{self.cfg.kem_alg}:{self.cfg.app_aead}".encode()
            )
            self._transcript_hasher.update(f"sid:{self._session_id}".encode())

            self._receipt_chain_hash = hashlib.sha256(str(self._session_id).encode()).hexdigest()

            # Stage181: init replay cache (per-session)
            self._seen_app_frame_hashes = set()
            self._seen_app_frame_order = deque(maxlen=self._replay_cache_size)

            self._started = True
            self._handshake_complete = True

            return SessionInfo(session_id=self._session_id, epoch=self._epoch, mode=self._mode)

        except FailClosed:
            self._close_transport()
            raise
        except Exception as e:
            self._close_transport()
            raise TransportError(str(e)) from e

    # -----------------------------------------------------------------
    # (2) rekey
    # -----------------------------------------------------------------
    def rekey(self, *, reason: str = "MANUAL") -> RekeyResult:
        self._require_handshake()

        next_epoch = self._epoch + 1
        if next_epoch <= self._epoch:
            self._fail_closed(EpochViolation("epoch rollback detected"))

        requested_mode: Mode = self._mode
        observed_mode: Mode = self._mode

        if not self.policy.allow_mode(requested=requested_mode, observed=observed_mode):
            self._fail_closed(DowngradeDetected(f"policy rejected mode {requested_mode}"))

        self._epoch = next_epoch
        self._update_transcript(f"rekey:{reason}:{self._epoch}")
        self._update_receipt_chain()

        return RekeyResult(epoch=self._epoch, mode=self._mode, reason=reason)

    # -----------------------------------------------------------------
    # (3) send
    # -----------------------------------------------------------------
    def send(self, data: bytes, *, aad: bytes = b"") -> None:
        self._require_handshake()

        if not isinstance(data, (bytes, bytearray)):
            self._fail_closed(FailClosed("send expects bytes"))
        if not isinstance(aad, (bytes, bytearray)):
            self._fail_closed(FailClosed("aad expects bytes"))

        io = self._require_io()
        sid = self._require_sid()

        try:
            payload = bytes(data)
            aad_b = bytes(aad)

            frame = _pack_app_frame(sid, payload)
            io.send_frame(frame)

            self._bytes_sent += len(payload)
            self._update_transcript(b"send:" + payload + b":aad:" + aad_b)

            if self.policy.should_rekey(epoch=self._epoch, bytes_sent=self._bytes_sent, bytes_recv=self._bytes_recv):
                self.rekey(reason="POLICY")

        except FailClosed:
            self._close_transport()
            raise
        except Exception as e:
            self._close_transport()
            raise TransportError(str(e)) from e

    # -----------------------------------------------------------------
    # (4) recv
    # -----------------------------------------------------------------
    def recv(self, *, max_bytes: int = 1_048_576) -> bytes:
        self._require_handshake()

        if not isinstance(max_bytes, int) or max_bytes <= 0:
            raise QspError("max_bytes must be a positive int")

        io = self._require_io()
        sid_expected = self._require_sid()

        try:
            frame = io.recv_frame(max_bytes=max_bytes)

            # Stage181: replay detect (duplicate APP frame bytes within a session)
            self._check_replay(frame)

            sid_got, payload = _unpack_app_frame(frame)

            if sid_got != sid_expected:
                self._fail_closed(WrongSessionID(f"expected {sid_expected} got {sid_got}"))

            self._bytes_recv += len(payload)
            self._update_transcript(b"recv:" + payload)
            return payload

        except ValueError as e:
            self._fail_closed(FailClosed(str(e)))
            raise
        except FailClosed:
            self._close_transport()
            raise
        except Exception as e:
            self._close_transport()
            raise TransportError(str(e)) from e

    # -----------------------------------------------------------------
    # (5) export_key_receipt
    # -----------------------------------------------------------------
    def export_key_receipt(self) -> KeyReceipt:
        self._require_handshake()
        sid = self._require_sid()

        if not self._receipt_chain_hash or not self._transcript_hasher:
            self._fail_closed(FailClosed("receipt state corrupted"))

        return KeyReceipt(
            session_id=sid,
            epoch=self._epoch,
            mode=self._mode,
            policy_id=self.policy.policy_id,
            transcript_hash=self._transcript_hasher.hexdigest(),
            receipt_chain_hash=self._receipt_chain_hash,
            meta={
                "bytes_sent": self._bytes_sent,
                "bytes_recv": self._bytes_recv,
                "timestamp": int(time.time()),
                "sdk_version": "0.180.0",
                "peer": self._peer or "",
                "role": self._role or "",
            },
        )

    # -----------------------------------------------------------------
    # (6) policy_hook
    # -----------------------------------------------------------------
    def policy_hook(self, new_policy: PolicyHook) -> None:
        if not hasattr(new_policy, "policy_id"):
            raise QspError("policy must define policy_id")
        if self._started:
            self._fail_closed(FailClosed("policy change during active session is forbidden"))
        self.policy = new_policy

    # -----------------------------------------------------------------
    # internal helpers
    # -----------------------------------------------------------------
    def _require_handshake(self) -> None:
        if not self._handshake_complete:
            raise HandshakeNotComplete("handshake not completed")

    def _require_io(self) -> FrameIO:
        if self._io is None:
            self._fail_closed(FailClosed("transport missing"))
        return self._io

    def _require_sid(self) -> int:
        if self._session_id is None:
            self._fail_closed(FailClosed("session_id missing"))
        return self._session_id

    def _update_transcript(self, data: bytes | str) -> None:
        if self._transcript_hasher is None:
            self._fail_closed(FailClosed("transcript state missing"))
        if isinstance(data, str):
            data = data.encode()
        self._transcript_hasher.update(data)

    def _update_receipt_chain(self) -> None:
        if self._receipt_chain_hash is None:
            self._fail_closed(FailClosed("receipt chain missing"))
        h = hashlib.sha256()
        h.update(self._receipt_chain_hash.encode())
        h.update(str(self._epoch).encode())
        h.update(self.policy.policy_id.encode())
        self._receipt_chain_hash = h.hexdigest()

    def _check_replay(self, frame: bytes) -> None:
        """
        Stage181: detect duplicate APP frames within a session.
        Deterministic & bounded memory (FIFO eviction).
        """
        if self._seen_app_frame_hashes is None or self._seen_app_frame_order is None:
            # If state is missing, treat it as fail-closed (security-relevant corruption)
            self._fail_closed(FailClosed("replay cache missing"))

        fh = hashlib.sha256(frame).hexdigest()
        if fh in self._seen_app_frame_hashes:
            self._fail_closed(ReplayDetected("duplicate app frame detected"))

        # Insert into bounded cache
        if len(self._seen_app_frame_order) >= self._seen_app_frame_order.maxlen:
            oldest = self._seen_app_frame_order.popleft()
            self._seen_app_frame_hashes.discard(oldest)

        self._seen_app_frame_order.append(fh)
        self._seen_app_frame_hashes.add(fh)

    def _close_transport(self) -> None:
        if self._io is not None:
            try:
                self._io.close()
            except Exception:
                pass
        self._io = None
        self._handshake_complete = False

    def _fail_closed(self, err: Exception) -> None:
        self._close_transport()
        raise err
