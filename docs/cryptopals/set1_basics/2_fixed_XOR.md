# Fixed XOR

Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

```plaintext
1c0111001f010100061a024b53535009181c
```

... after hex decoding, and when XOR'd against:

```plaintext
686974207468652062756c6c277320657965
```

... should produce:

```plaintext
746865206b696420646f6e277420706c6179
```

## Solution

```python
def fixed_xor(a: bytes, b: bytes) -> bytes:
    """Perform a fixed XOR operation on two byte strings."""
    if len(a) != len(b):
        raise ValueError("Input byte strings must be of the same length.")
    return bytes(x ^ y for x, y in zip(a, b))

a = bytes.fromhex("1c0111001f010100061a024b53535009181c")
b = bytes.fromhex("686974207468652062756c6c277320657965")
result = fixed_xor(a, b)
print(result)
```

"the kid don't play"
