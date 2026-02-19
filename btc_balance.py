#!/usr/bin/env python3
"""BTC balance checker.

Reads addresses from stdin and queries mempool.space for balances.

Supported stdin formats:
  1. Wallet secret JSON (from /run/secrets/): {"bip84": {"address": "bc1q..."}, ...}
  2. btc_addrgen --json output:              [{"index": 0, "address": "bc1q..."}, ...]
  3. Plain text, one address per line

Usage:
  cat /run/secrets/operational_account | python3 btc_balance.py
  python3 btc_addrgen.py zpub... --json | python3 btc_balance.py
  echo "bc1q..." | python3 btc_balance.py
"""

import json
import sys
import urllib.request
import urllib.error

MEMPOOL_API = "https://mempool.space/api"
BTC_PRICE_USD = None  # fetched lazily


def get_btc_price():
    global BTC_PRICE_USD
    if BTC_PRICE_USD is not None:
        return BTC_PRICE_USD
    try:
        resp = urllib.request.urlopen(f"{MEMPOOL_API}/v1/prices")
        data = json.loads(resp.read())
        BTC_PRICE_USD = data.get("USD", 0)
    except Exception:
        BTC_PRICE_USD = 0
    return BTC_PRICE_USD


def get_balance(address):
    url = f"{MEMPOOL_API}/address/{address}"
    try:
        resp = urllib.request.urlopen(url)
        data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"Error querying {address}: HTTP {e.code}", file=sys.stderr)
        return None

    chain = data["chain_stats"]
    mempool = data["mempool_stats"]

    confirmed = chain["funded_txo_sum"] - chain["spent_txo_sum"]
    unconfirmed = mempool["funded_txo_sum"] - mempool["spent_txo_sum"]
    total = confirmed + unconfirmed

    return {
        "address": address,
        "confirmed_sat": confirmed,
        "unconfirmed_sat": unconfirmed,
        "total_sat": total,
        "total_btc": total / 1e8,
    }


def parse_addresses(raw):
    """Parse stdin into a list of (label, address) tuples."""
    addresses = []
    try:
        data = json.loads(raw)
        # Wallet secret format
        if isinstance(data, dict):
            for path in ("bip84", "bip44"):
                if path in data and "address" in data[path]:
                    addresses.append((path.upper(), data[path]["address"]))
        # btc_addrgen --json format
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "address" in item:
                    label = f"index {item.get('index', '?')}"
                    addresses.append((label, item["address"]))
        return addresses
    except json.JSONDecodeError:
        # Plain text: one address per line
        for line in raw.strip().splitlines():
            line = line.strip()
            if line:
                addresses.append((line, line))
        return addresses


def main():
    raw = sys.stdin.read().strip()
    if not raw:
        print("Error: no input provided", file=sys.stderr)
        sys.exit(1)

    addresses = parse_addresses(raw)
    if not addresses:
        print("Error: no addresses found in input", file=sys.stderr)
        sys.exit(1)

    price = get_btc_price()

    total_sat = 0
    for label, addr in addresses:
        result = get_balance(addr)
        if result is None:
            continue
        total_sat += result["total_sat"]
        usd = result["total_btc"] * price if price else 0
        unconf_str = f" (+{result['unconfirmed_sat']} unconfirmed)" if result["unconfirmed_sat"] else ""
        print(f"{label}: {addr}")
        print(f"  {result['total_sat']} sat ({result['total_btc']:.8f} BTC  ~${usd:,.2f}){unconf_str}")

    if len(addresses) > 1:
        total_btc = total_sat / 1e8
        total_usd = total_btc * price if price else 0
        print(f"\nTotal: {total_sat} sat ({total_btc:.8f} BTC  ~${total_usd:,.2f})")


if __name__ == "__main__":
    main()
