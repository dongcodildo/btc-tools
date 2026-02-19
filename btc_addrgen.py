#!/usr/bin/env python3
"""BIP44/BIP84 address generator from an extended public key (xpub/zpub).

Derives receiving addresses sequentially, scanning the blockchain via
mempool.space to find used/unused addresses.

Usage:
  # From wallet secret JSON (via pipe):
  cat /run/secrets/treasury_account | python3 btc_addrgen.py [options]

  # From explicit key argument:
  python3 btc_addrgen.py <xpub|zpub> [options]

Dependencies: base58, bech32, ecdsa (no bip_utils needed)
"""

import argparse
import hashlib
import hmac
import json
import struct
import sys
import urllib.request
import urllib.error

import base58
import bech32 as bech32lib
import ecdsa

MEMPOOL_API = "https://mempool.space/api"


# ---------------------------------------------------------------------------
# BIP32 / HD key derivation (public-only)
# ---------------------------------------------------------------------------

def decode_extended_key(key_str):
    """Decode xpub/zpub into (pub_key_bytes, chain_code_bytes, key_type)."""
    raw = base58.b58decode_check(key_str)
    # version (4) | depth (1) | fingerprint (4) | index (4) | chain (32) | key (33)
    chain_code = raw[13:45]
    pub_key    = raw[45:78]
    if key_str.startswith(("zpub", "vpub")):
        key_type = "bip84"
    else:
        key_type = "bip44"
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
    child_pub = prefix + child.x().to_bytes(32, "big")
    return child_pub, IR


def hash160(data):
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def pub_to_p2wpkh(pub):
    """Compress public key → native segwit (bech32) address."""
    h    = hash160(pub)
    prog = bech32lib.convertbits(h, 8, 5)
    return bech32lib.bech32_encode("bc", [0] + prog)


def pub_to_p2pkh(pub):
    """Compress public key → legacy P2PKH address."""
    h    = hash160(pub)
    versioned = b"\x00" + h
    checksum  = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58.b58encode(versioned + checksum).decode()


def derive_addresses(pub_key, chain_code, key_type, count, gap_limit=20):
    """
    Derive external-chain (index 0) addresses and return up to `count` unused ones.
    Stops scanning after `gap_limit` consecutive unused addresses.
    """
    # External chain: child 0
    ext_pub, ext_chain = derive_child_pub(pub_key, chain_code, 0)

    unused      = []
    consecutive = 0
    index       = 0

    while len(unused) < count and consecutive < gap_limit:
        child_pub, _ = derive_child_pub(ext_pub, ext_chain, index)
        if key_type == "bip84":
            address = pub_to_p2wpkh(child_pub)
        else:
            address = pub_to_p2pkh(child_pub)

        used = is_address_used(address)
        if used:
            consecutive = 0
            print(f"  #{index}: {address} (used)", file=sys.stderr)
        else:
            consecutive += 1
            unused.append({"index": index, "address": address})

        index += 1

    return unused


# ---------------------------------------------------------------------------
# Blockchain query
# ---------------------------------------------------------------------------

def is_address_used(address):
    url = f"{MEMPOOL_API}/address/{address}"
    try:
        resp = urllib.request.urlopen(url)
        data = json.loads(resp.read())
        return (data["chain_stats"]["tx_count"] + data["mempool_stats"]["tx_count"]) > 0
    except urllib.error.HTTPError as e:
        print(f"Error querying {address}: HTTP {e.code}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------

def extract_key_from_json(raw):
    """Extract zpub/xpub from wallet secret JSON."""
    data = json.loads(raw)
    for path in ("bip84", "bip44"):
        if path in data and "zpub" in data[path]:
            return data[path]["zpub"]
        if path in data and "xpub" in data[path]:
            return data[path]["xpub"]
    raise ValueError("No xpub/zpub found in JSON input")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Derive unused Bitcoin addresses from xpub/zpub or wallet secret JSON"
    )
    parser.add_argument(
        "key",
        nargs="?",
        help="Extended public key (xpub/zpub). Omit to read wallet JSON from stdin.",
    )
    parser.add_argument("-n", "--count", type=int, default=1,
                        help="Number of unused addresses to find (default: 1)")
    parser.add_argument("--gap", type=int, default=20,
                        help="Gap limit for address scanning (default: 20)")
    parser.add_argument("--json", action="store_true",
                        help="Output in JSON format")
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
            # Treat as raw key string
            key_str = raw

    pub_key, chain_code, key_type = decode_extended_key(key_str)
    unused = derive_addresses(pub_key, chain_code, key_type, args.count, args.gap)

    if args.json:
        print(json.dumps(unused, indent=2))
    else:
        for entry in unused:
            print(f"#{entry['index']}: {entry['address']}")


if __name__ == "__main__":
    main()
