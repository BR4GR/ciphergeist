# Implement repeating-key XOR
Here is the opening stanza of an important work of the English language:
```plaintext
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
Encrypt it, under the key "ICE", using repeating-key XOR.
```


In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:
```bash
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
```
Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.

## Solution

```python
def repeating_key_xor(plaintext: bytes, key: bytes) -> bytes:
    """Perform repeating-key XOR encryption/decryption.

    XORs the plaintext with a key that repeats cyclically.
    Since XOR is symmetric, this function works for both encryption and decryption.

    Args:
        plaintext (bytes): The data to encrypt/decrypt.
        key (bytes): The key to repeat cyclically.

    Returns:
        bytes: The encrypted/decrypted data.

    Raises:
        ValueError: If the key is empty.
    """
    if not key:
        raise ValueError("Key cannot be empty")

    result = bytearray()
    for i, byte in enumerate(plaintext):
        key_byte = key[i % len(key)]
        result.append(byte ^ key_byte)

    return bytes(result)
```
