# QSP SDK API (Stage180) — v0.1

**Copyright © 2025 Motohiro Suzuki**  
This project is released under the MIT License. See `LICENSE` at repository root.

---

## 0. Design Contract (Non-Negotiable)

This SDK is designed to be:

- **Minimal**: external users only need one entrypoint (`QspSDK`) and **six methods**.
- **Misuse-resistant**: unsafe states are not representable (or immediately fail-closed).
- **Fail-closed by default**: security violations terminate the session via exceptions.

### Success/Failure Rule

- **On success**: methods return the minimal success result (`SessionInfo`, `RekeyResult`, `bytes`, `KeyReceipt`) or `None`.
- **On failure**: methods raise exceptions (never return `False` / `None` to signal errors).

---

## 1. Public Entrypoint

### `class QspSDK`

The only public SDK entrypoint. External users must not import internal modules (`protocol/`, `crypto/`, `wire/`) directly.

Constructor:

- `QspSDK(cfg: SDKConfig, policy: PolicyHook)`

---

## 2. Types

### `SDKConfig` (minimum public config)

Fields (defaults are suggested; final defaults are implementation-defined but MUST be documented):

- `enable_qkd: bool = True`
- `key_len: int = 32`
- `app_aead: str = "aes-gcm"`
- `sig_alg: str = "ed25519"`
- `kem_alg: str = "toy_kem"`

### `SessionInfo`

- `session_id: int`
- `epoch: int`
- `mode: "PQC_ONLY" | "QKD_MIXED"`

### `RekeyResult`

- `epoch: int`
- `mode: "PQC_ONLY" | "QKD_MIXED"`
- `reason: str` (e.g. `"TIME"`, `"BYTES"`, `"MANUAL"`, `"QKD_UNAVAILABLE"`)

### `KeyReceipt`

A first-class artifact for auditability and external review.

Required fields:

- `session_id: int`
- `epoch: int`
- `mode: "PQC_ONLY" | "QKD_MIXED"`
- `policy_id: str`
- `transcript_hash: str`
- `receipt_chain_hash: str`
- `meta: Mapping[str, Any]`

---

## 3. Exceptions (Fail-Closed Semantics)

All SDK exceptions inherit from:

- `QspError`

### Security / State failures (fail-closed)

- `FailClosed(QspError)` — base class for security-relevant failures; session MUST be closed.
- `HandshakeNotComplete(FailClosed)` — attempted `send/recv/rekey/receipt` before handshake completion.
- `DowngradeDetected(FailClosed)` — downgrade / policy violation detected.
- `PhaseConfusionDetected(FailClosed)` — protocol state contradicts received message type.
- `ReplayDetected(FailClosed)` — replay / transcript reuse detected.
- `WrongSessionID(FailClosed)` — session_id mismatch.
- `EpochViolation(FailClosed)` — epoch monotonicity violated.

### Transport / IO failures

- `TransportError(QspError)` — IO errors (disconnect, timeout, framing errors).
  - Implementation MAY escalate transport anomalies to `FailClosed` if security requires.

---

## 4. Six Public Methods (API Fixed)

### 4.1 `session_start()`

```python
def session_start(self, *, role: Role, peer: str) -> SessionInfo
Purpose
Start a session and complete handshake using SDK-controlled state machine.

Args

role: "client" or "server"

peer: peer identifier / address string (format is implementation-defined)

Returns

SessionInfo(session_id, epoch, mode)

Raises

TransportError

FailClosed (including downgrade/phase confusion/session mismatch, etc.)

Postconditions

On success: handshake is complete, session is usable.

SDK internal counters (bytes_sent/recv) start at 0.

4.2 rekey()
def rekey(self, *, reason: str = "MANUAL") -> RekeyResult
Purpose
Advance epoch and derive new traffic keys. SDK MUST enforce epoch monotonicity and mode integrity.

Args

reason: string label used for logs/receipts ("TIME", "BYTES", "MANUAL", "QKD_UNAVAILABLE", etc.)

Returns

RekeyResult(epoch, mode, reason)

Raises

HandshakeNotComplete

TransportError

FailClosed

Invariants

epoch MUST strictly increase by 1 on success.

Any mode change MUST be policy-approved, else DowngradeDetected.

4.3 send()
def send(self, data: bytes, *, aad: bytes = b"") -> None
Purpose
Encrypt + authenticate application data and send it.

Args

data: application payload

aad: optional additional authenticated data

Returns

None

Raises

HandshakeNotComplete

TransportError

FailClosed

Notes

SDK MUST prevent sending application data before handshake completion.

SDK MUST update bytes_sent counter on success.

4.4 recv()
def recv(self, *, max_bytes: int = 1_048_576) -> bytes
Purpose
Receive, verify, and decrypt application data. Only returns plaintext on success.

Args

max_bytes: upper bound to mitigate DoS / oversized frames

Returns

plaintext bytes

Raises

HandshakeNotComplete

TransportError

FailClosed (replay, phase confusion, wrong session, etc.)

Notes

SDK MUST update bytes_recv counter on success.

4.5 export_key_receipt()
def export_key_receipt(self) -> KeyReceipt
Purpose
Export a verifiable artifact describing the key lifecycle/provenance for the current session state.

Returns

KeyReceipt

Raises

HandshakeNotComplete

FailClosed

Requirements

policy_id MUST be included.

transcript_hash MUST be included (hash of negotiated transcript material as defined by implementation).

receipt_chain_hash MUST be included (hash-chained receipts across epochs).

4.6 policy_hook()
def policy_hook(self, new_policy: PolicyHook) -> None
Purpose
Replace the policy object. Policy expresses decisions (allow mode, rekey triggers), while SDK enforces safety.

Returns

None

Raises

QspError (invalid policy object)

FailClosed (if policy swap conflicts with active session invariants, implementation-defined)

Rules

SDK MUST remain fail-closed even under policy changes.

Policy MUST expose a stable identifier: policy_id: str.

5. Minimal PolicyHook Interface
A PolicyHook MUST provide:

policy_id: str

allow_mode(requested: Mode, observed: Optional[Mode]) -> bool

should_rekey(epoch: int, bytes_sent: int, bytes_recv: int) -> bool

on_failover(reason: str, from_mode: Mode, to_mode: Mode) -> None

SDK MAY call these hooks, but MUST enforce core safety invariants regardless of hook behavior.

6. Security Guarantees (SDK-level)
The SDK MUST enforce:

No application data before handshake completion (HandshakeNotComplete).

Epoch monotonicity (no rollback; violations => EpochViolation).

Session binding (mismatches => WrongSessionID).

Downgrade detection / prevention (violations => DowngradeDetected).

Phase confusion detection (violations => PhaseConfusionDetected).

Replay detection where applicable (violations => ReplayDetected).

Default behavior is fail-closed on integrity/security uncertainty.

7. What This API Does NOT Promise (Non-Goals Pointer)
This API document defines interfaces and fail-closed semantics only.
Threat model boundaries and non-goals are specified in:

docs/NonGoals.md

docs/ThreatModel.md