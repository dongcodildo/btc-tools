#!/usr/bin/env python3
"""Send a Bitcoin transaction using keys piped from btc_keygen.py.

Usage:
    python btc_keygen.py --json --show-private | \
        python btc_send.py --to <address> --amount <btc> --path bip84
"""

import argparse
import json
import math
import sys
import urllib.error
import urllib.request

from bit import Key, PrivateKeyTestnet
from bit.network.meta import Unspent


BLOCKSTREAM_MAINNET = "https://blockstream.info/api"
BLOCKSTREAM_TESTNET = "https://blockstream.info/testnet/api"

SUPPORTED_PATHS = {
    "bip44": {"unspent_type": "p2pkh", "address_key": "address"},
    "bip84": {"unspent_type": "p2wkh", "address_key": "address"},
}


def api_base(network):
    return BLOCKSTREAM_TESTNET if network == "testnet" else BLOCKSTREAM_MAINNET


def fetch_utxos(address, network, unspent_type):
    """Fetch UTXOs for an address from Blockstream."""
    base = api_base(network)
    url = f"{base}/address/{address}/utxo"
    try:
        resp = urllib.request.urlopen(url)
        data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"Error fetching UTXOs: HTTP {e.code}", file=sys.stderr)
        sys.exit(1)

    unspents = []
    for u in data:
        unspents.append(Unspent(
            amount=u["value"],
            confirmations=u["status"].get("block_height", 0),
            script="",
            txid=u["txid"],
            txindex=u["vout"],
            type=unspent_type,
        ))
    return unspents


def fetch_fee_rate(network, target_blocks=6):
    """Fetch fee rate in sat/vbyte from Blockstream."""
    base = api_base(network)
    url = f"{base}/fee-estimates"
    try:
        resp = urllib.request.urlopen(url)
        data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"Error fetching fee estimates: HTTP {e.code}", file=sys.stderr)
        sys.exit(1)

    rate = data.get(str(target_blocks))
    if rate is None:
        # Fall back to the closest available target
        targets = sorted(data.keys(), key=int)
        for t in targets:
            if int(t) >= target_blocks:
                rate = data[t]
                break
        if rate is None:
            rate = data[targets[-1]]

    return math.ceil(rate)


def broadcast(raw_tx_hex, network):
    """Broadcast a signed transaction via Blockstream."""
    base = api_base(network)
    url = f"{base}/tx"
    req = urllib.request.Request(url, data=raw_tx_hex.encode(), method="POST")
    try:
        resp = urllib.request.urlopen(req)
        return resp.read().decode().strip()
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"Broadcast failed: HTTP {e.code}: {body}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Send Bitcoin using keys from btc_keygen.py (piped via stdin)"
    )
    parser.add_argument(
        "--to",
        required=True,
        help="Destination Bitcoin address",
    )
    parser.add_argument(
        "--amount",
        required=True,
        type=float,
        help="Amount to send in BTC",
    )
    parser.add_argument(
        "--path",
        required=True,
        choices=["bip44", "bip84"],
        help="Which derivation path to spend from",
    )
    parser.add_argument(
        "--fee-rate",
        type=int,
        default=None,
        help="Fee rate in sat/vbyte (default: auto from network)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build and display the transaction without broadcasting",
    )
    args = parser.parse_args()

    # Read keygen JSON from stdin
    if sys.stdin.isatty():
        print("Error: Pipe btc_keygen.py --json --show-private output to stdin.", file=sys.stderr)
        sys.exit(1)

    data = json.load(sys.stdin)
    network = data["network"]
    path_data = data[args.path]

    wif = path_data.get("private_key_wif")
    if not wif:
        print("Error: No private key in input. Run btc_keygen.py with --show-private.", file=sys.stderr)
        sys.exit(1)

    address = path_data["address"]
    path_config = SUPPORTED_PATHS[args.path]

    # Create key
    if network == "testnet":
        key = PrivateKeyTestnet(wif)
    else:
        key = Key(wif)

    # Fetch UTXOs
    unspents = fetch_utxos(address, network, path_config["unspent_type"])
    if not unspents:
        print(f"Error: No UTXOs found for {address}", file=sys.stderr)
        sys.exit(1)

    balance = sum(u.amount for u in unspents)
    amount_sat = int(args.amount * 1e8)

    print(f"  From     : {address}", file=sys.stderr)
    print(f"  To       : {args.to}", file=sys.stderr)
    print(f"  Amount   : {args.amount} BTC ({amount_sat} sat)", file=sys.stderr)
    print(f"  Balance  : {balance} sat ({balance / 1e8:.8f} BTC)", file=sys.stderr)
    print(f"  UTXOs    : {len(unspents)}", file=sys.stderr)

    # Fee rate
    if args.fee_rate:
        fee_rate = args.fee_rate
    else:
        fee_rate = fetch_fee_rate(network)
    print(f"  Fee rate : {fee_rate} sat/vbyte", file=sys.stderr)

    # Build transaction
    outputs = [(args.to, amount_sat, "satoshi")]
    try:
        raw_tx = key.create_transaction(
            outputs,
            unspents=unspents,
            fee=fee_rate,
            absolute_fee=False,
            leftover=address,
        )
    except Exception as e:
        print(f"Error building transaction: {e}", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        print(f"\n  Raw transaction ({len(raw_tx) // 2} bytes):", file=sys.stderr)
        print(raw_tx)
        return

    # Broadcast
    txid = broadcast(raw_tx, network)
    print(f"  Tx ID    : {txid}", file=sys.stderr)
    print(txid)


if __name__ == "__main__":
    main()
