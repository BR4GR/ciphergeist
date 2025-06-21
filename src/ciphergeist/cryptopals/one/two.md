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

```
746865206b696420646f6e277420706c6179
```

Here's a solution in Python:

```python
def fixed_xor(a: bytes, b: bytes) -> bytes:
    """Perform a fixed XOR operation on two byte strings."""
    if len(a) != len(b):
        raise ValueError("Input byte strings must be of the same length.")
    return bytes(x ^ y for x, y in zip(a, b))

def test_fixed_xor_normal_case():
    a = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    b = bytes.fromhex("686974207468652062756c6c277320657965")
    result = fixed_xor(a, b)
    expected_result = bytes.fromhex("746865206b696420646f6e277420706c6179")
    assert result == expected_result, "XOR operation did not match expected output."
```

The test case produces `"the kid don't play"` when decoded from hex, demonstrating the XOR operation worked correctly.
