# office encryption

## Description
I heard about this nation state actor
I'm not sure why actors would attack companies but we need encryption to secure our systems.
Please add the encryption program I made to every software we had so we are secure!

## Author
xnull

cyphertext:
```
swo2024{jytmm_ruvs_opgbzu_mum}
```

cypher map:
```
{'a': 'k', 'b': 'n', 'c': 'o', 'd': 'r', 'e': 'v', 'f': 'q', 'g': 'i', 'h': 'w', 'i': 'x', 'j': 'd', 'k': 'h', 'l': 'm', 'm': 'l', 'n': 'y', 'o': 'u', 'p': 'b', 'q': 'f', 'r': 'p', 's': 's', 't': 'z', 'u': 't', 'v': 'a', 'w': 'c', 'x': 'j', 'y': 'g', 'z': 'e'}
```

encryption code:
```python
from random import shuffle
from collections import Counter


def generate_substitution_cipher(text):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    shuffled_alphabet = list(alphabet)
    shuffle(shuffled_alphabet)
    cipher_map = {
        original: substituted
        for original, substituted in zip(alphabet, shuffled_alphabet)
    }

    encrypted_text = ""
    for char in text:
        if char.lower() in cipher_map:
            encrypted_char = cipher_map[char.lower()]
            if char.isupper():
                encrypted_char = encrypted_char.upper()
            encrypted_text += encrypted_char
        else:
            encrypted_text += char

    return encrypted_text, cipher_map


text = "shc2024{fake_flag}"

encrypted_text, cipher_map = generate_substitution_cipher(text)

print(encrypted_text, cipher_map)
```

## Solution

```python
def reverse_cipher_map(cipher_map: dict[str, str]) -> dict[str, str]:
    """Reverse a cipher map to create the decryption key.

    Args:
        cipher_map (dict[str, str]): The original cipher map.

    Returns:
        dict[str, str]: The reversed cipher map for decryption.
    """
    return {v: k for k, v in cipher_map.items()}


def apply_substitution_cipher(text: str, cipher_map: dict[str, str]) -> str:
    """Apply a substitution cipher to text using the given cipher map.

    Args:
        text (str): The text to encrypt/decrypt.
        cipher_map (dict[str, str]): Mapping from original to substituted characters.

    Returns:
        str: The text with substitutions applied. Same length as input.
    """
    result = ""
    for char in text:
        if char in cipher_map:
            result += cipher_map[char]
        else:
            result += char
    return result


reversed_map = reverse_cipher_map(known_cipher_map)
decrypted = apply_substitution_cipher(ciphertext, reversed_map)
print(f"Decrypted: {decrypted}")
```

Decrypted: shc2024{xnull_does_crypto_lol}
