# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Protocol, Literal


# -----------------------------
# Public literals / aliases
# -----------------------------

Mode = Literal["PQC_ONLY", "QKD_MIXED"]
Role = Literal["client", "server"]


# -----------------------------
# Public SDK config
# -----------------------------

@dataclass(frozen=True)
class SDKConfig:
    """
    Stage180: minimal public configuration for SDK users.

    Keep this small. Anything protocol-internal belongs to qsp/protocol/*.
    """
    enable_qkd: bool = True
    key_len: int = 32

    # Algorithm identifiers (strings) for agility. Real mapping is internal.
    app_aead: str = "aes-gcm"
    sig_alg: str = "ed25519"
    kem_alg: str = "toy_kem"


# -----------------------------
# Public SDK result types
# -----------------------------

@dataclass(frozen=True)
class SessionInfo:
    session_id: int
    epoch: int
    mode: Mode


@dataclass(frozen=True)
class RekeyResult:
    epoch: int
    mode: Mode
    reason: str  # "TIME" / "BYTES" / "MANUAL" / "QKD_UNAVAILABLE" / ...


@dataclass(frozen=True)
class KeyReceipt:
    """
    A first-class artifact: "How this key was born and evolved".
    """
    session_id: int
    epoch: int
    mode: Mode
    policy_id: str

    transcript_hash: str
    receipt_chain_hash: str

    meta: Mapping[str, Any]


# -----------------------------
# Policy hook (public extension point)
# -----------------------------

class PolicyHook(Protocol):
    """
    Stage180 핵: external users can swap policy decisions,
    while SDK enforces safety invariants (fail-closed).
    """

    policy_id: str

    def allow_mode(self, *, requested: Mode, observed: Optional[Mode]) -> bool:
        """
        Decide whether the SDK may operate in 'requested' mode.
        'observed' may be the mode derived from peer / transcript / device.
        If observed is not None, a strict policy typically requires equality.
        """
        ...

    def should_rekey(self, *, epoch: int, bytes_sent: int, bytes_recv: int) -> bool:
        """
        Decide whether SDK should proactively rekey.
        This is advisory: SDK still enforces epoch monotonicity and safety.
        """
        ...

    def on_failover(self, *, reason: str, from_mode: Mode, to_mode: Mode) -> None:
        """
        Notification hook (no return value).
        SDK may call this when it switches modes (e.g., QKD unavailable).
        """
        ...
