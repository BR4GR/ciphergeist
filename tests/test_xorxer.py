import pytest

from ciphergeist.encrypters.xorxer import (
    fixed_xor,
    guess_single_key_xor,
    quick_guess_single_byte_xor,
    score_text,
    single_byte_xor,
)


def test_fixed_xor_normal_case():
    a = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    b = bytes.fromhex("686974207468652062756c6c277320657965")
    result = fixed_xor(a, b)
    expected_result = bytes.fromhex("746865206b696420646f6e277420706c6179")
    assert result == expected_result, "XOR operation did not match expected output."


def test_fixed_xor_different_length():
    a = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    with pytest.raises(ValueError):
        fixed_xor(a, a + b"\x00")  # Append an extra byte to make lengths different


def test_guess_single_key_xor():
    ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    guess = guess_single_key_xor(ciphertext)
    assert guess.key == 88, "Expected key 88 for the given ciphertext."
    expected_plaintext = b"Cooking MC's like a pound of bacon"
    assert guess.plaintext == expected_plaintext, "Decrypted plaintext did not match expected."


def test_quick_guess_single_byte_xor():
    ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    guess = quick_guess_single_byte_xor(ciphertext)
    assert guess.key == 88, "Expected key 88 for the quick guess."


def test_quick_guess_single_byte_xor_2():
    plaintext = b"Hello, World!"
    key = 42
    ciphertext = single_byte_xor(plaintext, key)
    guess = quick_guess_single_byte_xor(ciphertext)
    assert guess.key == key, "Expected key 42 for the quick guess."


def test_score_text_empty_input():
    """Test that score_text raises ValueError for empty input."""
    with pytest.raises(ValueError, match="Input text cannot be empty"):
        score_text(b"")


def test_single_byte_xor_invalid_key():
    """Test that single_byte_xor raises ValueError for invalid key."""
    plaintext = b"Hello, World!"

    with pytest.raises(ValueError, match="Key must be int \\(0-255\\)"):
        single_byte_xor(plaintext, 256)

    with pytest.raises(ValueError, match="Key must be int \\(0-255\\)"):
        single_byte_xor(plaintext, -1)
