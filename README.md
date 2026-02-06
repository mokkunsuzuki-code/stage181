# QSP Stage180 — SDK Entry Point (v2.0 Preview)

**QSP (Quantum-Safe Protocol)** Stage180 is the point where value shifts from  
**“correctness” → “being used.”**

Stage180 fixes a **minimal, misuse-resistant SDK interface** and proves — by execution —
that security properties are enforced **in real communication**, not just on paper.

> ✅ Touch it  
> ✅ Break it  
> ✅ See attacks fail  

---

## What Stage180 Delivers

### Fixed SDK API (6 functions only)

```python
sdk.session_start(role, peer)   # establish session
sdk.send(data)                  # send application data
sdk.recv()                      # receive application data
sdk.rekey()                     # advance epoch
sdk.export_key_receipt()        # cryptographic provenance artifact
sdk.policy_hook(policy)         # (pre-session) policy injection
This API is stable.
All future work (crypto, QKD, PQC, proofs) plugs behind this boundary.

Why Stage180 Is the Value Jump
Stage	Value Source
170–179	Correctness, formal reasoning, proofs
180+	Usability, adoption, experiential review
At Stage180:

Review shifts from “Does this look correct?”
→ “I ran it. Attacks fail.”

SDK users do not need protocol knowledge.

CI can execute attacks, not just unit tests.

Quick Start (1 minute)
Requirements
Python 3.10+

macOS / Linux

Setup
git clone <this-repo>
cd stage180
python -m venv .venv
source .venv/bin/activate
pip install -e .
10-Line Demo (Real TCP Communication)
Terminal 1 — Server
python examples/hello_10lines_server.py
Expected output (example):

[server] started session_id=1532634194952149445 epoch=1 mode=QKD_MIXED
[server] recv: ping
[server] receipt: session_id=1532634194952149445 epoch=1 mode=QKD_MIXED chain=...
Terminal 2 — Client
python examples/hello_10lines_client.py
Expected output:

[client] started session_id=1532634194952149445 epoch=1 mode=QKD_MIXED
[client] recv: pong
[client] receipt: session_id=1532634194952149445 epoch=1 mode=QKD_MIXED chain=...
✔ Real TCP
✔ Shared session_id
✔ Identical receipt chain

Security as an Experience: Attack-04 (Wrong Session ID)
Stage180 does not claim security — it demonstrates rejection.

Run the attack
./attack_scenarios/attack_04_wrong_session_id/run.sh
What this test does
Normal case

SDK ↔ SDK communication

PASS

Tampered case

Attacker injects a frame with a forged session_id

SDK detects mismatch

Fail-closed with WrongSessionID

Expected output (excerpt)
[OK] normal case PASS
[OK] tamper rejected (WrongSessionID): expected X got Y
[OK] tamper case PASS
This is not a unit test.
This is live attack execution.

What Is Being Enforced (Stage180 Scope)
Guaranteed
Session binding (SID)

Fail-closed semantics

Epoch monotonicity

Misuse resistance at API boundary

Verifiable key provenance (KeyReceipt)

Explicitly Out of Scope (for this stage)
AEAD encryption (stubbed)

PQC / QKD internals

Performance optimization

These are added behind the same SDK interface in later stages.

KeyReceipt: First-Class Security Artifact
Every session can export:

receipt = sdk.export_key_receipt()
Includes:

session_id

epoch

mode (PQC_ONLY / QKD_MIXED)

transcript hash

receipt chain hash

policy id

traffic metadata

This enables:

audit

compliance

cross-implementation comparison

Design Philosophy
Fail closed, always

Small API surface

Attacks must be runnable

Formal proofs must map to code

“Looks secure” is not enough

License
MIT License
© 2026 Motohiro Suzuki