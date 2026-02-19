# Bitcoin Key & Transaction Tools

Command-line tools for BIP39 key derivation, address generation, and transaction broadcasting.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

All examples below assume the venv is activated.

## Scripts

### btc_keygen.py

Interactively prompts for a BIP39 seed phrase and derives Bitcoin keys.

```bash
# 12-word seed, human-readable output
python btc_keygen.py

# 24-word seed with private keys shown
python btc_keygen.py --words 24 --show-private

# Testnet
python btc_keygen.py --network testnet

# JSON output (for piping to other tools)
python btc_keygen.py --json --show-private
```

Example output:

```
============================================================
  Network : mainnet
============================================================

  BIP44 (m/44'/0'/0'/0/0) — Legacy
  Address    : 1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA
  Public Key : 03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e
  xpub       : xpub6BosfCnifzxcF...

  BIP84 (m/84'/0'/0'/0/0) — Native SegWit
  Address    : bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
  Public Key : 0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c
  zpub       : zpub6rFR7y4Q2AijB...
```

### btc_addrgen.py

Generates unused receiving addresses from an extended public key (xpub/zpub). Scans the blockchain via Blockstream's API to skip addresses that have already been used.

```bash
# Next unused address
python btc_addrgen.py "zpub6rFR7y4Q2AijB..."

# Next 5 unused addresses
python btc_addrgen.py "zpub6rFR7y4Q2AijB..." -n 5

# JSON output
python btc_addrgen.py "zpub6rFR7y4Q2AijB..." -n 3 --json
```

Example output (`-n 3` — finds the first 3 unused addresses, skipping used ones):

```
  #0: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu (used)
  #1: bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g (used)
  #2: bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z
  #3: bc1qgl5vlg0zdl7yvprgxj9fevsc6q6x5dmcyk3cn3 (used)
  #4: bc1qm97vqzgj934vnaq9s53ynkyf9dgr05rargr04n
  #5: bc1qnpzzqjzet8gd5gl8l6gzhuc4s9xv0djt0rlu7a
```

Supported key prefixes:

| Prefix | Type | Network |
|--------|------|---------|
| `xpub` | BIP44 (Legacy) | Mainnet |
| `zpub` | BIP84 (SegWit) | Mainnet |
| `tpub` | BIP44 (Legacy) | Testnet |
| `vpub` | BIP84 (SegWit) | Testnet |

### btc_send.py

Sends a Bitcoin transaction. Reads key data from `btc_keygen.py` via stdin, fetches UTXOs and fee estimates from Blockstream, and broadcasts the signed transaction.

```bash
# Send 0.001 BTC using BIP84 (SegWit) keys
python btc_keygen.py --json --show-private | \
    python btc_send.py --to <destination_address> --amount 0.001 --path bip84

# Dry run (build transaction without broadcasting)
python btc_keygen.py --json --show-private | \
    python btc_send.py --to <destination_address> --amount 0.001 --path bip84 --dry-run

# Custom fee rate
python btc_keygen.py --json --show-private | \
    python btc_send.py --to <destination_address> --amount 0.001 --path bip44 --fee-rate 5
```

## Typical workflow

```bash
# 1. Generate keys from your seed phrase
python btc_keygen.py --show-private
#    Save the zpub/xpub for address generation
#    Save the WIF private key for signing

# 2. Share the zpub with whoever needs to generate receiving addresses
python btc_addrgen.py "zpub6rFR7y4Q2AijB..." -n 3

# 3. Send bitcoin
python btc_keygen.py --json --show-private | \
    python btc_send.py --to bc1q... --amount 0.001 --path bip84
```

## Key concepts

- **xpub/zpub**: Extended public keys at the account level. Share these to let someone generate receiving addresses without being able to spend.
- **WIF private key**: Required for signing transactions. Never share this.
- **BIP44** (`m/44'/0'/0'/0/N`): Legacy addresses starting with `1`.
- **BIP84** (`m/84'/0'/0'/0/N`): Native SegWit addresses starting with `bc1q`. Lower fees, preferred for most use cases.
- BIP44 and BIP84 derive **different key pairs** from the same seed. Funds sent to a BIP84 address are only accessible via the BIP84 path.
