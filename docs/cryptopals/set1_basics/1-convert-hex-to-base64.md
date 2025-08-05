
# Convert hex to base64

The string:

```plaintext
49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
```

Should produce:

```plaintext
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
```

So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

Cryptopals Rule:
Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.

## Solution

```python
def convert_hex_to_base64(hex_string):
    """
    Convert a hexadecimal string to a Base64 encoded string.

    :param hex_string: A string representing a hexadecimal number.
    :return: A Base64 encoded string.
    """
    bytes_data = bytes.fromhex(hex_string)
    base64_encoded = base64.b64encode(bytes_data)
    return base64_encoded.decode('ascii')
```

```python
if __name__ == "__main__":
    input_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expectred_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    base64_string = convert_hex_to_base64(input_string)
    print(f"Base64 Encoded: {base64_string}")
    assert base64_string == expectred_base64, "Conversion did not match expected output."
    print("Conversion successful!")
    print(base64.b64decode(base64_string))
```

Base64 Encoded: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
Conversion successful!

b"I'm killing your brain like a poisonous mushroom"
