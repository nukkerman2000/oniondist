#!/usr/bin/env python3
"""
util/onion.py -- convert a 64-hex tor v3 secret key into its .onion hostname.

    python3 onion.py <hex64>            # print the onion hostname
    python3 onion.py <hex64> --check PREFIX

Requires PyNaCl (pip install pynacl) for the ed25519 base multiply.
"""
import binascii
import base64
import hashlib
import sys

try:
    import nacl.bindings
except Exception as e:  # pragma: no cover
    print("PyNaCl required: pip install pynacl  (%s)" % e)
    raise SystemExit(2)


def onion_from_key(hex_key: str) -> str:
    pub = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(binascii.unhexlify(hex_key))
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + pub + version).digest()[:2]
    return base64.b32encode(pub + checksum + version).decode().lower()


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    key = sys.argv[1].strip()
    onion = onion_from_key(key)
    print("%s.onion" % onion)
    if "--check" in sys.argv:
        i = sys.argv.index("--check")
        prefix = sys.argv[i + 1].lower() if i + 1 < len(sys.argv) else ""
        ok = onion.startswith(prefix)
        print("PREFIX_OK:", ok)
        return 0 if ok else 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
