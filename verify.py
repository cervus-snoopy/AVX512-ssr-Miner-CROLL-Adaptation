#!/usr/bin/env python3
"""Verifikasi rumus hash CROLL lawan keccak Python.

Pemakaian:
    python3 verify.py <challenge_hex> <miner_hex> <target_hex> <nonce>
        Menghitung keccak256(challenge 32 byte || miner 20 byte ||
        nonce 32 byte big-endian) lalu membandingkan dengan target
        (hash < target = lolos, below_target 1).

Keluar 0 kalau lolos, 1 kalau tidak lolos, 2 kalau input salah.
Butuh pycryptodome: pip install pycryptodome
"""

import sys

try:
    from Crypto.Hash import keccak
except ImportError:
    print("pycryptodome belum terpasang. Jalankan: pip install pycryptodome")
    sys.exit(2)


def parse_hex(s, nbytes, name):
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    if len(s) != nbytes * 2:
        raise ValueError(f"{name} harus {nbytes} byte ({nbytes * 2} digit hex)")
    return bytes.fromhex(s)


def main(argv):
    if len(argv) != 5:
        print(__doc__)
        return 2
    try:
        challenge = parse_hex(argv[1], 32, "challenge")
        miner = parse_hex(argv[2], 20, "miner")
        target = parse_hex(argv[3], 32, "target")
        nonce = int(argv[4])
        if nonce < 0 or nonce >= 2**64:
            raise ValueError("nonce harus 0..2^64-1")
    except ValueError as e:
        print(f"input salah: {e}")
        return 2
    k = keccak.new(digest_bits=256)
    k.update(challenge + miner + nonce.to_bytes(32, "big"))
    digest = k.digest()
    below = 1 if digest < target else 0
    print(f"hash: 0x{digest.hex()}")
    print(f"below_target: {below}")
    return 0 if below else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
