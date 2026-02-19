#!/usr/bin/env python3
"""BIP44/BIP84 address generator from an extended public key (xpub/zpub).

Derives receiving addresses sequentially, scanning the blockchain via
Blockstream's API to find the first N unused addresses.
"""

import argparse
import json
import sys
import urllib.request
import urllib.error

from bip_utils import (
    Bip44,
    Bip44Changes,
    Bip44Coins,
    Bip84,
    Bip84Coins,
)

BLOCKSTREAM_MAINNET = "https://blockstream.info/api"
BLOCKSTREAM_TESTNET = "https://blockstream.info/testnet/api"

# Stop scanning after this many consecutive unused addresses
def detect_key_type(key):
    """Detect whether the key is xpub (BIP44) or zpub (BIP84) and return
    the appropriate bip_utils class, coin type, and API base URL."""
    if key.startswith("xpub"):
        return Bip44, Bip44Coins.BITCOIN, BLOCKSTREAM_MAINNET
    elif key.startswith("zpub"):
        return Bip84, Bip84Coins.BITCOIN, BLOCKSTREAM_MAINNET
    elif key.startswith("tpub"):
        return Bip44, Bip44Coins.BITCOIN_TESTNET, BLOCKSTREAM_TESTNET
    elif key.startswith("vpub"):
        return Bip84, Bip84Coins.BITCOIN_TESTNET, BLOCKSTREAM_TESTNET
    else:
        print("Error: Unrecognized key prefix. Expected xpub, zpub, tpub, or vpub.")
        sys.exit(1)


def is_address_used(address, api_base):
    """Check if an address has any transaction history on the blockchain."""
    url = f"{api_base}/address/{address}"
    try:
        resp = urllib.request.urlopen(url)
        data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"Error querying {address}: HTTP {e.code}")
        sys.exit(1)
    tx_count = data["chain_stats"]["tx_count"] + data["mempool_stats"]["tx_count"]
    return tx_count > 0


def find_unused_addresses(key, count):
    """Scan addresses sequentially, returning the first `count` unused ones."""
    bip_cls, coin, api_base = detect_key_type(key)
    ctx = bip_cls.FromExtendedKey(key, coin)

    unused = []
    index = 0

    while len(unused) < count:
        addr = ctx.Change(Bip44Changes.CHAIN_EXT).AddressIndex(index)
        address = addr.PublicKey().ToAddress()

        if is_address_used(address, api_base):
            print(f"  #{index}: {address} (used)")
        else:
            print(f"  #{index}: {address}")
            unused.append((index, address))

        index += 1

    return unused


def main():
    parser = argparse.ArgumentParser(
        description="Find unused Bitcoin addresses from an extended public key (xpub/zpub)"
    )
    parser.add_argument(
        "key",
        help="Extended public key (xpub, zpub, tpub, or vpub)",
    )
    parser.add_argument(
        "-n", "--count",
        type=int,
        default=1,
        help="Number of unused addresses to find (default: 1)",
    )
    args = parser.parse_args()

    find_unused_addresses(args.key, args.count)


if __name__ == "__main__":
    main()
