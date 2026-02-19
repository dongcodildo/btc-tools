#!/usr/bin/env python3
"""Send a Bitcoin transaction (P2WPKH / native SegWit) using keys from a JSON file.

Usage:
    # Pipe operational account JSON directly
    cat /run/secrets/operational_account | python btc_send.py --to <address> --amount <btc>

    # Or pass a key file
    python btc_send.py --key-file wallet.json --to <address> --amount 0.001

    # Dry run (build and display without broadcasting)
    cat /run/secrets/operational_account | python btc_send.py --to <address> --amount 0.001 --dry-run

The key JSON must contain a bip84.private_key_wif field.
"""

import argparse
import hashlib
import json
import struct
import sys
import urllib.error
import urllib.request

import base58
import bech32
import ecdsa


MEMPOOL_API = "https://mempool.space/api"
MEMPOOL_TESTNET_API = "https://mempool.space/testnet/api"


def api_base(network):
    return MEMPOOL_TESTNET_API if network == "testnet" else MEMPOOL_API


def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def varint(n):
    if n < 0xFD:
        return bytes([n])
    elif n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def pushdata(data):
    return varint(len(data)) + data


def decode_wif(wif):
    decoded = base58.b58decode_check(wif)
    if decoded[0] not in (0x80, 0xEF):
        raise ValueError(f"Unexpected WIF prefix: {decoded[0]:#x}")
    return decoded[1:33]


def compressed_pubkey(privkey_bytes):
    sk = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big"), sk


def fetch_utxos(address, network):
    base = api_base(network)
    url = f"{base}/address/{address}/utxo"
    try:
        resp = urllib.request.urlopen(url)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"Error fetching UTXOs: HTTP {e.code}", file=sys.stderr)
        sys.exit(1)


def fetch_fee_rate(network, target_blocks=6):
    base = api_base(network)
    url = f"{base}/v1/fees/recommended"
    try:
        resp = urllib.request.urlopen(url)
        data = json.loads(resp.read())
        # halfHourFee ≈ 3-block, hourFee ≈ 6-block
        return max(1, data.get("hourFee", data.get("halfHourFee", 5)))
    except urllib.error.HTTPError:
        return 5  # fallback


def broadcast(raw_tx_hex, network):
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


def build_and_sign_p2wpkh(privkey_bytes, pubkey, from_addr, to_addr, utxo, send_sat, fee, network):
    """Build and sign a P2WPKH transaction using BIP143 sighash."""
    from_pkh = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()

    # Decode destination address
    hrp = "tb" if network == "testnet" else "bc"
    _, to_witprog = bech32.decode(hrp, to_addr)
    if to_witprog is None:
        print(f"Error: Invalid bech32 address: {to_addr}", file=sys.stderr)
        sys.exit(1)
    to_pkh = bytes(to_witprog)

    utxo_value = utxo["value"]
    change_sat = utxo_value - send_sat - fee

    txid_le = bytes.fromhex(utxo["txid"])[::-1]
    vout_n = utxo["vout"]

    spk_to = b"\x00\x14" + to_pkh
    spk_change = b"\x00\x14" + from_pkh

    # BIP143 sighash components
    hash_prevouts = hash256(txid_le + struct.pack("<I", vout_n))
    hash_sequence = hash256(struct.pack("<I", 0xFFFFFFFF))

    # scriptCode for P2WPKH = OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG
    scriptcode = b"\x19\x76\xa9\x14" + from_pkh + b"\x88\xac"

    out1 = struct.pack("<q", send_sat) + pushdata(spk_to)
    outputs = out1
    if change_sat > 546:
        outputs += struct.pack("<q", change_sat) + pushdata(spk_change)
    hash_outputs = hash256(outputs)

    preimage = (
        struct.pack("<I", 2)
        + hash_prevouts
        + hash_sequence
        + txid_le
        + struct.pack("<I", vout_n)
        + scriptcode
        + struct.pack("<q", utxo_value)
        + struct.pack("<I", 0xFFFFFFFF)
        + hash_outputs
        + struct.pack("<I", 0)
        + struct.pack("<I", 1)
    )
    sighash = hash256(preimage)

    sk = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1)
    sig_raw = sk.sign_digest(sighash, sigencode=ecdsa.util.sigencode_der_canonize)
    sig_with_hashtype = sig_raw + b"\x01"

    input_raw = txid_le + struct.pack("<I", vout_n) + b"\x00" + struct.pack("<I", 0xFFFFFFFF)
    n_outputs = 1 + (1 if change_sat > 546 else 0)
    witness_raw = b"\x02" + pushdata(sig_with_hashtype) + pushdata(pubkey)

    tx_raw = (
        struct.pack("<I", 2)
        + b"\x00\x01"
        + b"\x01"
        + input_raw
        + bytes([n_outputs])
        + outputs
        + witness_raw
        + struct.pack("<I", 0)
    )
    return tx_raw, change_sat


def main():
    parser = argparse.ArgumentParser(description="Send P2WPKH Bitcoin transaction (BIP143)")
    parser.add_argument("--to", required=True, help="Destination bech32 address")
    parser.add_argument("--amount", required=True, type=float, help="Amount in BTC")
    parser.add_argument("--key-file", default=None, help="Path to key JSON file (default: stdin)")
    parser.add_argument("--fee-rate", type=int, default=None, help="Fee rate in sat/vbyte")
    parser.add_argument("--dry-run", action="store_true", help="Build tx without broadcasting")
    args = parser.parse_args()

    if args.key_file:
        with open(args.key_file) as f:
            data = json.load(f)
    elif not sys.stdin.isatty():
        data = json.load(sys.stdin)
    else:
        print("Error: pipe key JSON to stdin or pass --key-file", file=sys.stderr)
        sys.exit(1)

    network = data.get("network", "mainnet")
    path_data = data.get("bip84")
    if not path_data or "private_key_wif" not in path_data:
        print("Error: bip84.private_key_wif not found in key data", file=sys.stderr)
        sys.exit(1)

    privkey_bytes = decode_wif(path_data["private_key_wif"])
    pubkey, _ = compressed_pubkey(privkey_bytes)
    from_addr = path_data["address"]

    utxos = fetch_utxos(from_addr, network)
    if not utxos:
        print(f"Error: No UTXOs found for {from_addr}", file=sys.stderr)
        sys.exit(1)

    # Use largest confirmed UTXO
    confirmed = [u for u in utxos if u["status"].get("confirmed")]
    if not confirmed:
        print("Error: No confirmed UTXOs available", file=sys.stderr)
        sys.exit(1)
    utxo = max(confirmed, key=lambda u: u["value"])

    balance = utxo["value"]
    send_sat = int(args.amount * 1e8)
    fee_rate = args.fee_rate or fetch_fee_rate(network)
    fee = max(fee_rate * 141, 300)  # ~141 vbytes for 1-in 2-out P2WPKH

    if send_sat + fee > balance:
        print(
            f"Error: Insufficient funds. Balance: {balance} sat, need: {send_sat + fee} sat",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"  Network  : {network}", file=sys.stderr)
    print(f"  From     : {from_addr}", file=sys.stderr)
    print(f"  To       : {args.to}", file=sys.stderr)
    print(f"  Amount   : {args.amount} BTC ({send_sat} sat)", file=sys.stderr)
    print(f"  Balance  : {balance} sat ({balance / 1e8:.8f} BTC)", file=sys.stderr)
    print(f"  Fee rate : {fee_rate} sat/vbyte (~{fee} sat)", file=sys.stderr)
    print(f"  Change   : {balance - send_sat - fee} sat", file=sys.stderr)

    tx_raw, change = build_and_sign_p2wpkh(
        privkey_bytes, pubkey, from_addr, args.to, utxo, send_sat, fee, network
    )

    if args.dry_run:
        print(f"\n  Raw transaction ({len(tx_raw)} bytes):", file=sys.stderr)
        print(tx_raw.hex())
        return

    txid = broadcast(tx_raw.hex(), network)
    print(f"  Tx ID    : {txid}", file=sys.stderr)
    print(txid)


if __name__ == "__main__":
    main()
