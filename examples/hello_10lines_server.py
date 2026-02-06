# MIT License © 2025 Motohiro Suzuki
from qsp.sdk import QspSDK
from qsp.types import SDKConfig, PolicyHook


class StrictPolicy(PolicyHook):
    policy_id = "strict-v1"

    def allow_mode(self, *, requested, observed):
        return True if observed is None else (requested == observed)

    def should_rekey(self, *, epoch, bytes_sent, bytes_recv):
        return False

    def on_failover(self, *, reason, from_mode, to_mode):
        print(f"[policy] failover: {from_mode} -> {to_mode} reason={reason}")


def main() -> None:
    sdk = QspSDK(cfg=SDKConfig(enable_qkd=True), policy=StrictPolicy())
    info = sdk.session_start(role="server", peer="0.0.0.0:9000")
    print(f"[server] started session_id={info.session_id} epoch={info.epoch} mode={info.mode}")

    msg = sdk.recv()
    print(f"[server] recv: {msg.decode('utf-8', errors='replace')}")
    sdk.send(b"pong")

    r = sdk.export_key_receipt()
    print(f"[server] receipt: session_id={r.session_id} epoch={r.epoch} mode={r.mode} chain={r.receipt_chain_hash}")


if __name__ == "__main__":
    main()
