import random
from typing import cast

from pwn import xor

from ciphergeist.encrypters.xorxer import derive_xor_key, single_byte_xor


def gen_key() -> int:
    KEY_128_BIT = 128 % 15
    KEY = random.getrandbits(KEY_128_BIT)
    return KEY


def encrypt(message: bytes) -> bytes:
    KEY = gen_key()
    return cast(bytes, xor(message, KEY))


ciphertext = b"\x8c\x9c\x9b\xa4\xa7\xef\xad\x80\xbd\xad\xaa\xab\xec\x80\xec\xe6\xbd\xba\xef\xed\xb9\xb9\xa2"
known_plaintext = b"SCD{"

key = derive_xor_key(ciphertext, known_plaintext)
print(f"Key: {key[0]}")

decrypted = single_byte_xor(ciphertext, key[0])
print(f"Decrypted: {decrypted!r}")
