import pytest

from ciphergeist.encrypters.xorxer import (
    derive_xor_key,
    find_minimal_pattern,
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


def test_find_minimal_pattern_single_byte():
    """Test finding minimal pattern with single byte repetition."""
    assert find_minimal_pattern(b"aaaa") == b"a"
    assert find_minimal_pattern(b"bbbbbb") == b"b"


def test_find_minimal_pattern_multi_byte():
    """Test finding minimal pattern with multi-byte repetition."""
    assert find_minimal_pattern(b"abcabcabc") == b"abc"
    assert find_minimal_pattern(b"xyzxyzxyz") == b"xyz"
    assert find_minimal_pattern(b"1212121212") == b"12"


def test_find_minimal_pattern_no_pattern():
    """Test when there's no repeating pattern."""
    assert find_minimal_pattern(b"abcdef") == b"abcdef"
    assert find_minimal_pattern(b"123456789") == b"123456789"


def test_find_minimal_pattern_empty():
    """Test with empty input."""
    assert find_minimal_pattern(b"") == b""


def test_find_minimal_pattern_single_char():
    """Test with single character."""
    assert find_minimal_pattern(b"a") == b"a"


def test_derive_xor_key_single_byte():
    """Test deriving single-byte XOR key."""
    plaintext = b"Hello"
    key = 42
    ciphertext = single_byte_xor(plaintext, key)

    derived_key = derive_xor_key(ciphertext, plaintext)
    assert derived_key == bytes([key])


def test_derive_xor_key_partial_plaintext():
    """Test deriving key when plaintext is shorter than ciphertext."""
    plaintext = b"Hello, World!"
    key = 123
    ciphertext = single_byte_xor(plaintext, key)

    # Use only part of the plaintext
    partial_plaintext = b"Hello"
    derived_key = derive_xor_key(ciphertext, partial_plaintext)
    assert derived_key == bytes([key])


def test_derive_xor_key_multi_byte_pattern():
    """Test deriving multi-byte repeating key."""
    plaintext = b"Hello, World! This is a test message."
    key_pattern = b"KEY"

    # Create extended key
    extended_key = (key_pattern * ((len(plaintext) // len(key_pattern)) + 1))[: len(plaintext)]
    ciphertext = fixed_xor(plaintext, extended_key)

    # Use enough plaintext to detect the pattern
    test_plaintext = plaintext[:9]  # "Hello, Wo" - should be enough to detect "KEY" pattern
    derived_key = derive_xor_key(ciphertext, test_plaintext)
    assert derived_key == key_pattern


def test_derive_xor_key_plaintext_too_long():
    """Test error when plaintext is longer than ciphertext."""
    ciphertext = b"short"
    plaintext = b"much longer plaintext"

    with pytest.raises(ValueError, match="Known plaintext cannot be longer than ciphertext"):
        derive_xor_key(ciphertext, plaintext)
