"""Deploy committed WaiverClock and exercise a synthetic live review on StudioNet."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from eth_account import Account
from eth_utils import to_checksum_address
from genlayer_py import create_client
from genlayer_py.assertions import tx_execution_succeeded
from genlayer_py.chains import studionet
from genlayer_py.exceptions import GenLayerError
from genlayer_py.types import TransactionHashVariant, TransactionStatus


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "contracts" / "WaiverClock.py"
BASE = "https://raw.githubusercontent.com/Demigodd00/waiver-clock/"
CONTROL = (
    "DOC-001: Pilot release notes must use prose, not markdown tables. A temporary "
    "exception may be granted for one named synthetic documentation file when a "
    "three-column compatibility mapping must exercise a table-rendering test. "
    "Mitigation must include an accessible prose alternative, named owner, "
    "one-hour maximum, and a rollback path. This control says nothing about "
    "production security, dependencies, or data handling."
)


def git(*args: str) -> bytes:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True).stdout


def tx_hex(value: object) -> str:
    rendered = str(value)
    return rendered if rendered.startswith("0x") else "0x" + bytes(value).hex()


def wait(client, tx) -> dict:
    receipt = None
    for attempt in range(10):
        try:
            receipt = client.wait_for_transaction_receipt(
                transaction_hash=tx_hex(tx),
                status=TransactionStatus.FINALIZED,
                interval=5_000,
                retries=120,
                full_transaction=True,
            )
            break
        except GenLayerError as error:
            print(json.dumps({
                "step": "poll_retry", "transaction": tx_hex(tx),
                "attempt": attempt + 1, "error": str(error)[:180],
            }), flush=True)
            time.sleep(5)
    if receipt is None:
        raise RuntimeError("receipt polling failed repeatedly: " + tx_hex(tx))
    if (receipt.get("status_name") or receipt.get("statusName")) != TransactionStatus.FINALIZED.value:
        raise RuntimeError("transaction did not finalize: " + tx_hex(tx))
    if not tx_execution_succeeded(receipt):
        raise RuntimeError("execution failed: " + json.dumps(receipt, default=str))
    if (receipt.get("result_name") or receipt.get("resultName")) not in (None, "AGREE", "MAJORITY_AGREE"):
        raise RuntimeError("consensus not reached: " + json.dumps(receipt, default=str))
    return receipt


def write(client, address: str, name: str, args: list) -> str:
    tx = client.write_contract(address=address, function_name=name, args=args)
    print(json.dumps({"step": name, "transaction": tx_hex(tx)}), flush=True)
    wait(client, tx)
    return tx_hex(tx)


def read_request(client, address: str) -> dict:
    raw = client.read_contract(
        address=address,
        function_name="get_request",
        args=[1],
        transaction_hash_variant=TransactionHashVariant.LATEST_FINAL,
    )
    return json.loads(raw) if isinstance(raw, str) else raw


def public_file(commit: str, path: str) -> tuple[str, str]:
    expected = git("show", "HEAD:" + path)
    url = BASE + commit + "/" + path
    with urllib.request.urlopen(url, timeout=30) as response:
        actual = response.read()
    if actual != expected:
        raise RuntimeError("public file differs from committed bytes: " + path)
    return url, hashlib.sha256(expected).hexdigest()


def main() -> None:
    if git("status", "--porcelain"):
        raise RuntimeError("commit and push before deploying")
    commit = git("rev-parse", "HEAD").decode().strip()
    source = SOURCE.read_text(encoding="utf-8").replace("\r\n", "\n")
    tracked = git("show", "HEAD:contracts/WaiverClock.py").decode().replace("\r\n", "\n")
    if source != tracked:
        raise RuntimeError("local source differs from committed source")
    source_url, source_sha = public_file(commit, "contracts/WaiverClock.py")
    necessity_url, necessity_sha = public_file(commit, "evidence/demo/necessity.md")
    mitigation_url, mitigation_sha = public_file(commit, "evidence/demo/mitigation.md")

    owner = Account.create()
    client = create_client(chain=studionet, account=owner)
    deployment = client.deploy_contract(code=source, account=owner, args=[])
    print(json.dumps({"step": "deploy", "transaction": tx_hex(deployment)}), flush=True)
    receipt = wait(client, deployment)
    address = None
    for key in ("tx_data_decoded", "data"):
        item = receipt.get(key)
        if isinstance(item, dict) and item.get("contract_address"):
            address = to_checksum_address(str(item["contract_address"]))
            break
    if address is None:
        raise RuntimeError("deployment receipt omitted contract address")
    print(json.dumps({"step": "deployed", "address": address}), flush=True)
    encoded = client.provider.make_request("gen_getContractCode", [address]).get("result")
    if not isinstance(encoded, str):
        raise RuntimeError("deployed source unavailable")
    deployed = base64.b64decode(encoded, validate=True).decode().replace("\r\n", "\n")
    if deployed != source:
        raise RuntimeError("deployed source does not match public commit")

    transactions = {}
    transactions["create_control"] = write(client, address, "create_control", ["DOC-001", CONTROL, 3600])
    transactions["request_waiver"] = write(client, address, "request_waiver", [
        "DOC-001",
        "docs/release-notes-2.0.md",
        "Allow one three-column markdown table for a synthetic pilot mapping test.",
        3600,
        necessity_url,
        necessity_sha,
        mitigation_url,
        mitigation_sha,
    ])
    transactions["assess_necessity"] = write(client, address, "assess_necessity", [1])
    first = read_request(client, address)
    print(json.dumps({"step": "necessity_result", "finding": first["necessity"]}), flush=True)
    transactions["assess_mitigation"] = write(client, address, "assess_mitigation", [1])
    second = read_request(client, address)
    print(json.dumps({"step": "mitigation_result", "finding": second["mitigation"]}), flush=True)
    transactions["finalize_request"] = write(client, address, "finalize_request", [1])
    result = read_request(client, address)
    if result["status"] not in ("ACTIVE", "DENIED", "REVIEW_REQUIRED"):
        raise RuntimeError("unexpected finalized status: " + json.dumps(result))
    print(json.dumps({
        "network": "studionet",
        "chain_id": 61999,
        "source_commit": commit,
        "source_url": source_url,
        "source_sha256": source_sha,
        "contract_address": address,
        "explorer": "https://explorer-studio.genlayer.com/address/" + address,
        "deployed_at": datetime.now(timezone.utc).isoformat(),
        "deploy_transaction": tx_hex(deployment),
        "owner": owner.address,
        "wallet_policy": "disposable StudioNet-only owner; private key not retained",
        "necessity": {"url": necessity_url, "sha256": necessity_sha},
        "mitigation": {"url": mitigation_url, "sha256": mitigation_sha},
        "transactions": transactions,
        "observed_request": result,
        "status": "VERIFIED_SOURCE_AND_DEMO",
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
