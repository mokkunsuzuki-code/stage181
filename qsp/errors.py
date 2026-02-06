# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations


class QspError(Exception):
    """SDK base exception."""


# -----------------------------
# Fail-closed (security/state)
# -----------------------------

class FailClosed(QspError):
    """
    Security-relevant failure. The session MUST be considered closed/invalid.
    """
    pass


class HandshakeNotComplete(FailClosed):
    """Attempted to use send/recv/rekey/receipt before handshake completion."""
    pass


class DowngradeDetected(FailClosed):
    """Detected a downgrade attempt or invalid mode transition."""
    pass


class PhaseConfusionDetected(FailClosed):
    """Protocol phase/state contradicts received message type or internal state."""
    pass


class ReplayDetected(FailClosed):
    """Detected replay / transcript reuse / nonce reuse patterns (as defined)."""
    pass


class WrongSessionID(FailClosed):
    """Session binding failed (session_id mismatch)."""
    pass


class EpochViolation(FailClosed):
    """Epoch monotonicity violated (rollback / invalid jump)."""
    pass


# -----------------------------
# Transport / IO errors
# -----------------------------

class TransportError(QspError):
    """
    IO/network framing errors. Implementation may escalate to FailClosed
    when security requires (e.g., ambiguous integrity failure).
    """
    pass
