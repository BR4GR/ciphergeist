# xoxo
## Description
After I tried to persuade Dave into just reinstalling all Windows machines, he just gave me this to distract me... Can you recover the flag?

## Author
Coderion

```bash
b'\x8c\x9c\x9b\xa4\xa7\xef\xad\x80\xbd\xad\xaa\xab\xec\x80\xec\xe6\xbd\xba\xef\xed\xb9\xb9\xa2'
```

```python
import random
from pwn import xor


def gen_key():
    KEY_128_BIT = 128 % 15
    KEY = random.getrandbits(KEY_128_BIT)
    return KEY


def encrypt(message):
    KEY = gen_key()
    return xor(message, KEY)


print(encrypt(b"SCD{fake_flag}"))
```

## Solution

```python
from ciphergeist.encrypters.xorxer import derive_xor_key, single_byte_xor

ciphertext = b"\x8c\x9c\x9b\xa4\xa7\xef\xad\x80\xbd\xad\xaa\xab\xec\x80\xec\xe6\xbd\xba\xef\xed\xb9\xb9\xa2"
known_plaintext = b"SCD{"

key = derive_xor_key(ciphertext, known_plaintext)
print(f"Key: {key[0]}")

decrypted = single_byte_xor(ciphertext, key[0])
print(f"Decrypted: {decrypted}")
```

Key: 223
Decrypted: b'SCD{x0r_brut3_39be02ff}'
