#!/usr/bin/env python3
"""BIP39 Seed Phrase Key Generator.

Interactively prompts for each word of a BIP39 seed phrase,
validates the mnemonic, and derives Bitcoin keys via BIP44 and BIP84.
"""

import argparse
import sys

from bip_utils import (
    Bip39Languages,
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip44,
    Bip44Changes,
    Bip44Coins,
    Bip84,
    Bip84Coins,
)
from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter


def get_wordlist():
    """Return the set of valid BIP39 English words."""
    wl = Bip39WordsListGetter.Instance().GetByLanguage(Bip39Languages.ENGLISH)
    return set(wl.m_words_to_idx.keys())


def prompt_words(num_words):
    """Prompt the user for each seed word, validating against the BIP39 wordlist."""
    wordlist = get_wordlist()
    words = []
    print(f"\nEnter your {num_words}-word BIP39 seed phrase, one word at a time.\n")
    for i in range(1, num_words + 1):
        while True:
            try:
                word = input(f"  Word {i}/{num_words}: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\nAborted.")
                sys.exit(1)
            if not word:
                print("    (empty — try again)")
                continue
            if word not in wordlist:
                print(f"    '{word}' is not a valid BIP39 word. Try again.")
                continue
            words.append(word)
            break
    return words


def validate_mnemonic(words):
    """Validate the complete mnemonic (including checksum)."""
    mnemonic = " ".join(words)
    validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)
    if not validator.IsValid(mnemonic):
        print("\nError: Invalid mnemonic — checksum verification failed.")
        print("Double-check your words and try again.")
        sys.exit(1)
    return mnemonic


def derive_keys(mnemonic, network, show_private):
    """Derive and display BIP44 and BIP84 keys from the mnemonic."""
    seed = Bip39SeedGenerator(mnemonic, Bip39Languages.ENGLISH).Generate()

    if network == "testnet":
        bip44_coin = Bip44Coins.BITCOIN_TESTNET
        bip84_coin = Bip84Coins.BITCOIN_TESTNET
    else:
        bip44_coin = Bip44Coins.BITCOIN
        bip84_coin = Bip84Coins.BITCOIN

    # BIP44: m/44'/0'/0'/0/0  (Legacy P2PKH)
    bip44_acc = (
        Bip44.FromSeed(seed, bip44_coin)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )

    # BIP84: m/84'/0'/0'/0/0  (Native SegWit P2WPKH)
    bip84_acc = (
        Bip84.FromSeed(seed, bip84_coin)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )

    print("\n" + "=" * 60)
    print(f"  Network : {network}")
    print("=" * 60)

    print(f"\n  BIP44 (m/44'/0'/0'/0/0) — Legacy")
    print(f"  Address    : {bip44_acc.PublicKey().ToAddress()}")
    print(f"  Public Key : {bip44_acc.PublicKey().RawCompressed().ToHex()}")
    if show_private:
        print(f"  Private Key (WIF): {bip44_acc.PrivateKey().ToWif()}")

    print(f"\n  BIP84 (m/84'/0'/0'/0/0) — Native SegWit")
    print(f"  Address    : {bip84_acc.PublicKey().ToAddress()}")
    print(f"  Public Key : {bip84_acc.PublicKey().RawCompressed().ToHex()}")
    if show_private:
        print(f"  Private Key (WIF): {bip84_acc.PrivateKey().ToWif()}")

    print()


def main():
    parser = argparse.ArgumentParser(description="BIP39 Seed Phrase Key Generator")
    parser.add_argument(
        "--words",
        type=int,
        choices=[12, 24],
        default=12,
        help="Number of seed words (default: 12)",
    )
    parser.add_argument(
        "--network",
        choices=["mainnet", "testnet"],
        default="mainnet",
        help="Bitcoin network (default: mainnet)",
    )
    parser.add_argument(
        "--show-private",
        action="store_true",
        help="Display WIF private keys",
    )
    args = parser.parse_args()

    words = prompt_words(args.words)
    mnemonic = validate_mnemonic(words)
    print("\nMnemonic is valid.")
    derive_keys(mnemonic, args.network, args.show_private)


if __name__ == "__main__":
    main()
