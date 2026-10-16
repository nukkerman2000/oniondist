#!/bin/env python3

import base64
import hashlib
import os,sys
import pwd
import grp
from pathlib import Path

import time    
epoch_time = int(time.time())

import binascii
import nacl.bindings

edwards_add = nacl.bindings.crypto_core_ed25519_add
inv = nacl.bindings.crypto_core_ed25519_scalar_invert
scalar_add = nacl.bindings.crypto_core_ed25519_scalar_add
scalarmult_B = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp
scalarmult = nacl.bindings.crypto_scalarmult_ed25519_noclamp

H = binascii.unhexlify(
    "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"
)

def scalarmult_H(v):
    return scalarmult(v, H)


def scalar_reduce(v):
    return nacl.bindings.crypto_core_ed25519_scalar_reduce(v + (64 - len(v)) * b"\0")


def public_from_secret_hex(hk):
    try:
        return binascii.hexlify(scalarmult_B(binascii.unhexlify(hk))).decode()
    except nacl.exceptions.RuntimeError:
        raise ValueError("Invalid secret key")

def expand_private_key(secret_key) -> bytes:
    hashi = hashlib.sha256(os.urandom(1024)).digest()
    hashi = bytearray(secret_key + hashi)
    return bytes(hashi)


def onion_address_from_public_key(public_key: bytes) -> str:
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
    onion_address = "{}.onion".format(
        base64.b32encode(public_key + checksum + version).decode().lower()
    )
    return onion_address


def verify_v3_onion_address(onion_address: str) -> list[bytes, bytes, bytes]:
    # v3 spec https://gitweb.torproject.org/torspec.git/plain/rend-spec-v3.txt
    try:
        decoded = base64.b32decode(onion_address.replace(".onion", "").upper())
        public_key = decoded[:32]
        checksum = decoded[32:34]
        version = decoded[34:]
        if (
            checksum
            != hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
        ):
            raise ValueError
        return public_key, checksum, version
    except:
        raise ValueError("Invalid v3 onion address")


def create_hs_ed25519_secret_key_content(signing_key: bytes) -> bytes:
    return b"== ed25519v1-secret: type0 ==\x00\x00\x00" + expand_private_key(
        signing_key
    )


def create_hs_ed25519_public_key_content(public_key: bytes) -> bytes:
    assert len(public_key) == 32
    return b"== ed25519v1-public: type0 ==\x00\x00\x00" + public_key


def store_bytes_to_file(
    bytes: bytes, filename: str, uid: int = None, gid: int = None
) -> str:
    with open(filename, "wb") as binary_file:
        binary_file.write(bytes)
    if uid and gid:
        os.chown(filename, uid, gid)
    return filename


def store_string_to_file(
    string: str, filename: str, uid: int = None, gid: int = None
) -> str:
    with open(filename, "w") as file:
        file.write(string)
    if uid and gid:
        os.chown(filename, uid, gid)
    return filename

def derive_pub(
        priv_key: str,
) -> bytes:
    return bytes.fromhex(public_from_secret_hex(priv_key))

def create_hidden_service_files(
    private_key: str,
    hidden_service_dir: str,
) -> None:

    public_key = derive_pub(private_key)
    private_key = bytes.fromhex(private_key)
    
    uid = os.getuid()
    gid = os.getgid()
    
    file_content_secret = create_hs_ed25519_secret_key_content(private_key)
    
    onion_address = onion_address_from_public_key(public_key)
    print(onion_address)
    os.mkdir(f"{hidden_service_dir}/{onion_address}") 
    store_bytes_to_file(
        file_content_secret, f"{hidden_service_dir}/{onion_address}/hs_ed25519_secret_key", uid, gid
    )

    file_content_public = create_hs_ed25519_public_key_content(public_key)
    store_bytes_to_file(
        file_content_public, f"{hidden_service_dir}/{onion_address}/hs_ed25519_public_key", uid, gid
    )

    store_string_to_file(onion_address, f"{hidden_service_dir}/{onion_address}/hostname", uid, gid)


if __name__ == "__main__":
    try:
        keyfile = sys.argv[1]
    except:
        print("\n Please provide keyfile filepath.\n Examples: /home/user/keys.txt\n           666.keys\n")
        sys.exit(1)
        
    path = os.getcwd()+ f"/generated-{epoch_time}"
    try:
        os.mkdir(path)
    except:
        pass

    with open(keyfile) as f:
        for line in f:
            try:
                create_hidden_service_files(
                    line.rstrip('\n'),
                    path,
                )
            except:
                pass
