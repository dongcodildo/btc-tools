#!/usr/bin/env python3
"""BTC wallet balance checker.

Accepts a zpub/xpub (or wallet secret JSON) and scans all used addresses
across both external and change chains, reporting the total wallet balance.

Usage:
  python3 btc_wallet_balance.py <zpub>
  python3 btc_wallet_balance.py <zpub> --json
  cat /run/secrets/ops_wallet | python3 btc_wallet_balance.py
"""

import argparse
import hashlib
import hmac
import json
import struct
import sys
import time

import base58
import bech32 as bech32lib
import ecdsa
import requests

BLOCKSTREAM_API = "https://blockstream.info/api"
BTC_PRICE_USD = None  # fetched lazily


# ---------------------------------------------------------------------------
# BIP32 / HD key derivation (public-only)
# ---------------------------------------------------------------------------

def decode_extended_key(key_str):
    """Decode xpub/zpub into (pub_key_bytes, chain_code_bytes, key_type)."""
    raw = base58.b58decode(key_str)
    payload = raw[:-4]
    chain_code = payload[13:45]
    pub_key    = payload[45:78]
    key_type = "bip84" if key_str.startswith(("zpub", "vpub")) else "bip44"
    return pub_key, chain_code, key_type


def derive_child_pub(pub_key, chain_code, index):
    """Derive a child public key (non-hardened)."""
    data = pub_key + struct.pack(">I", index)
    I    = hmac.new(chain_code, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    curve  = ecdsa.SECP256k1
    tweak  = ecdsa.SigningKey.from_string(IL, curve=curve).verifying_key.pubkey.point
    parent = ecdsa.VerifyingKey.from_string(pub_key, curve=curve).pubkey.point
    child  = tweak + parent
    prefix = b"\x02" if child.y() % 2 == 0 else b"\x03"
    return prefix + child.x().to_bytes(32, "big"), IR


def hash160(data):
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def pub_to_p2wpkh(pub):
    h    = hash160(pub)
    prog = bech32lib.convertbits(h, 8, 5)
    return bech32lib.bech32_encode("bc", [0] + prog)


def pub_to_p2pkh(pub):
    h    = hash160(pub)
    versioned = b"\x00" + h
    checksum  = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58.b58encode(versioned + checksum).decode()


# ---------------------------------------------------------------------------
# Blockchain queries
# ---------------------------------------------------------------------------

def get_btc_price():
    global BTC_PRICE_USD
    if BTC_PRICE_USD is not None:
        return BTC_PRICE_USD
    try:
        resp = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd", timeout=5)
        resp.raise_for_status()
        BTC_PRICE_USD = resp.json().get("bitcoin", {}).get("usd", 0)
    except Exception:
        BTC_PRICE_USD = 0
    return BTC_PRICE_USD


def get_address_stats(address):
    """Return (confirmed_sat, unconfirmed_sat, tx_count) for an address."""
    url = f"{BLOCKSTREAM_API}/address/{address}"
    for attempt in range(3):
        try:
            time.sleep(0.3)
            resp = requests.get(url, timeout=5)
            if resp.status_code == 429 and attempt < 2:
                time.sleep(2 * (attempt + 1))
                continue
            resp.raise_for_status()
            data = resp.json()
            chain   = data["chain_stats"]
            mempool = data["mempool_stats"]
            confirmed   = chain["funded_txo_sum"]   - chain["spent_txo_sum"]
            unconfirmed = mempool["funded_txo_sum"] - mempool["spent_txo_sum"]
            tx_count    = chain["tx_count"] + mempool["tx_count"]
            return confirmed, unconfirmed, tx_count
        except requests.exceptions.HTTPError as e:
            print(f"  Error querying {address}: HTTP {e.response.status_code}", file=sys.stderr)
            return 0, 0, 0
        except Exception as e:
            if attempt < 2:
                time.sleep(1)
                continue
            print(f"  Error querying {address}: {e}", file=sys.stderr)
            return 0, 0, 0
    return 0, 0, 0


# ---------------------------------------------------------------------------
# Wallet scanning
# ---------------------------------------------------------------------------

def scan_wallet(pub_key, chain_code, key_type, gap_limit=20):
    """
    Scan external (0) and change (1) chains up to gap_limit consecutive unused
    addresses. Returns list of dicts with address, chain, index, and balances.
    """
    results = []
    for chain_idx, chain_name in ((0, "external"), (1, "change")):
        chain_pub, chain_cc = derive_child_pub(pub_key, chain_code, chain_idx)
        consecutive = 0
        index = 0
        while consecutive < gap_limit:
            child_pub, _ = derive_child_pub(chain_pub, chain_cc, index)
            address = pub_to_p2wpkh(child_pub) if key_type == "bip84" else pub_to_p2pkh(child_pub)
            confirmed, unconfirmed, tx_count = get_address_stats(address)
            if tx_count > 0:
                consecutive = 0
                results.append({
                    "chain": chain_name,
                    "index": index,
                    "address": address,
                    "confirmed_sat": confirmed,
                    "unconfirmed_sat": unconfirmed,
                    "total_sat": confirmed + unconfirmed,
                })
            else:
                consecutive += 1
            index += 1
    return results


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------

def extract_key_from_json(raw):
    data = json.loads(raw)
    for path in ("bip84", "bip44"):
        if path in data:
            for field in ("zpub", "xpub"):
                if field in data[path]:
                    return data[path][field]
    raise ValueError("No xpub/zpub found in JSON input")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Check total balance of a BIP44/BIP84 HD wallet from zpub/xpub"
    )
    parser.add_argument("key", nargs="?",
                        help="Extended public key (xpub/zpub). Omit to read wallet JSON from stdin.")
    parser.add_argument("--gap", type=int, default=20,
                        help="Gap limit for address scanning (default: 20)")
    parser.add_argument("--json", action="store_true",
                        help="Output in JSON format")
    parser.add_argument("--show-addresses", action="store_true",
                        help="Show individual address breakdown")
    args = parser.parse_args()

    if args.key:
        key_str = args.key
    else:
        if sys.stdin.isatty():
            parser.print_help()
            sys.exit(1)
        raw = sys.stdin.read().strip()
        try:
            key_str = extract_key_from_json(raw)
        except (json.JSONDecodeError, ValueError):
            key_str = raw

    pub_key, chain_code, key_type = decode_extended_key(key_str)
    addresses = scan_wallet(pub_key, chain_code, key_type, args.gap)

    total_confirmed   = sum(a["confirmed_sat"]   for a in addresses)
    total_unconfirmed = sum(a["unconfirmed_sat"] for a in addresses)
    total_sat         = sum(a["total_sat"]        for a in addresses)
    total_btc         = total_sat / 1e8
    price             = get_btc_price()
    total_usd         = total_btc * price if price else 0

    if args.json:
        output = {
            "confirmed_sat": total_confirmed,
            "unconfirmed_sat": total_unconfirmed,
            "total_sat": total_sat,
            "total_btc": total_btc,
            "btc_price_usd": price,
            "total_usd": round(total_usd, 2),
            "addresses": addresses if args.show_addresses else [],
        }
        print(json.dumps(output, indent=2))
    else:
        if args.show_addresses and addresses:
            print("Addresses with balance:")
            for a in addresses:
                usd = a["total_sat"] / 1e8 * price if price else 0
                unconf = f" (+{a['unconfirmed_sat']} unconfirmed)" if a["unconfirmed_sat"] else ""
                print(f"  {a['chain']}#{a['index']}: {a['address']}")
                print(f"    {a['total_sat']} sat ({a['total_sat']/1e8:.8f} BTC  ~${usd:,.2f}){unconf}")
        unconf_str = f" (+{total_unconfirmed} unconfirmed)" if total_unconfirmed else ""
        print(f"\nTotal: {total_sat} sat ({total_btc:.8f} BTC  ~${total_usd:,.2f}){unconf_str}")


if __name__ == "__main__":
    main()
