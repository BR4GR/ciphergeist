#!/usr/bin/env python3
"""
Main script demonstrating the ciphergeist package functionality.

This script shows how to use various modules from the ciphergeist package
including XOR encryption/decryption and other cryptographic utilities.
"""

from ciphergeist.encrypters.xorxer import (
    fixed_xor,
    guess_single_key_xor,
    quick_guess_single_byte_xor,
    single_byte_xor,
)
from ciphergeist.foo import foo


def demo_foo_function():
    """Demonstrate the foo function from ciphergeist.foo module."""
    print("=== Demo: foo function ===")
    test_input = "Hello, CipherGeist!"
    result = foo(test_input)
    print(f"Input: {test_input}")
    print(f"Output: {result}")
    print()


def demo_xor_encryption():
    """Demonstrate XOR encryption and decryption."""
    print("=== Demo: XOR Encryption ===")

    # Single-byte XOR
    plaintext = b"Hello, World!"
    key = 42

    print(f"Original text: {plaintext}")
    print(f"XOR key: {key}")

    # Encrypt
    ciphertext = single_byte_xor(plaintext, key)
    print(f"Encrypted: {ciphertext.hex()}")

    # Decrypt
    decrypted = single_byte_xor(ciphertext, key)
    print(f"Decrypted: {decrypted}")
    print()


def demo_xor_key_guessing():
    """Demonstrate XOR key guessing functionality."""
    print("=== Demo: XOR Key Guessing ===")

    # Create a simple cipher
    original_text = b"This is a secret message that has been encrypted with a single-byte XOR cipher!"
    secret_key = 73  # Random key

    ciphertext = single_byte_xor(original_text, secret_key)
    print(f"Original: {original_text}")
    print(f"Secret key: {secret_key}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print()

    # Try to guess the key
    print("Attempting to guess the key...")
    guess = guess_single_key_xor(ciphertext)

    print(f"Guessed key: {guess.key}")
    print(f"Confidence score: {guess.score:.4f}")
    print(f"Decrypted text: {guess.plaintext}")
    print(f"Key guess correct: {guess.key == secret_key}")
    print()


def demo_fixed_xor():
    """Demonstrate fixed XOR between two byte strings."""
    print("=== Demo: Fixed XOR ===")

    data1 = b"Hello"
    data2 = b"World"

    print(f"Data 1: {data1} ({data1.hex()})")
    print(f"Data 2: {data2} ({data2.hex()})")

    try:
        result = fixed_xor(data1, data2)
        print(f"XOR result: {result.hex()}")

        # XOR again to get back original
        back_to_original = fixed_xor(result, data2)
        print(f"XOR back: {back_to_original}")

    except ValueError as e:
        print(f"Error: {e}")
    print()


def demo_quick_guess():
    """Demonstrate quick XOR key guessing."""
    print("=== Demo: Quick XOR Key Guessing ===")

    # Test with a shorter message for quick guessing
    message = b"Secret!"
    key = 99

    encrypted = single_byte_xor(message, key)
    print(f"Original: {message}")
    print(f"Key: {key}")
    print(f"Encrypted: {encrypted.hex()}")

    quick_guess = quick_guess_single_byte_xor(encrypted)
    print(f"Quick guess key: {quick_guess.key}")
    print(f"Quick guess result: {quick_guess.plaintext}")
    print()


def main():
    """Main function that runs all demonstrations."""
    print("CipherGeist Package Demo")
    print("=" * 50)
    print()

    # Run all demonstrations
    demo_foo_function()
    demo_xor_encryption()
    demo_xor_key_guessing()
    demo_fixed_xor()
    demo_quick_guess()

    print("Demo completed!")


if __name__ == "__main__":
    main()
