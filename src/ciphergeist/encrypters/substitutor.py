"""
Substitution cipher implementation with frequency analysis-based decryption.

This module provides tools for creating and breaking substitution ciphers,
where each letter of the alphabet is consistently replaced with another letter.
"""

import string
from collections import Counter
from dataclasses import dataclass

from ciphergeist.frequencies.lowercase_frequencies import letter_frequencies as lowercase_frequencies


@dataclass(order=True)
class SubstitutionGuess:
    """Represents a guess for a substitution cipher key and resulting plaintext."""

    score: float
    cipher_map: dict[str, str]
    ciphertext: str
    plaintext: str

    def __init__(self, ciphertext: str, cipher_map: dict[str, str], is_empty: bool = False):
        self.ciphertext = ciphertext
        self.cipher_map = cipher_map.copy()
        if is_empty:
            self.plaintext = ""
            self.score = float("inf")
            return
        self.plaintext = apply_substitution_cipher(ciphertext, cipher_map)
        self.score = score_substitution_text(self.plaintext)

    @classmethod
    def empty(cls) -> "SubstitutionGuess":
        """Create an empty guess with infinite score for comparison."""
        return cls("", {}, is_empty=True)


def score_substitution_text(text: str) -> float:
    """Score a text string based on letter frequency analysis.

    Compares the frequency of letters in the text against the expected
    frequency distribution of lowercase letters in English text.

    Args:
        text (str): The text string to score.

    Returns:
        float: The score representing the difference in letter frequencies.
            A lower score indicates a closer match to expected frequencies.
    """
    if len(text) == 0:
        return float("inf")

    text_lower = "".join(c.lower() for c in text if c.isalpha())
    if len(text_lower) == 0:
        return float("inf")

    counts_text: Counter[str] = Counter()
    for letter in lowercase_frequencies:
        counts_text[letter] = text_lower.count(letter)

    total = sum(counts_text.values())
    if total == 0:
        return float("inf")

    frequencies_text = {letter: counts_text[letter] / total for letter in lowercase_frequencies}
    errors = {abs(lowercase_frequencies[letter] - frequencies_text[letter]) for letter in lowercase_frequencies}
    return sum(errors)


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


def reverse_cipher_map(cipher_map: dict[str, str]) -> dict[str, str]:
    """Reverse a cipher map to create the decryption key.

    Args:
        cipher_map (dict[str, str]): The original cipher map.

    Returns:
        dict[str, str]: The reversed cipher map for decryption.
    """
    return {v: k for k, v in cipher_map.items()}


def _create_frequency_mapping(cipher_letters: str) -> dict[str, str]:
    """Create a cipher mapping based on letter frequency analysis."""
    cipher_freq = Counter(cipher_letters)
    cipher_sorted = [letter for letter, _ in cipher_freq.most_common()]
    english_sorted = sorted(lowercase_frequencies.keys(), key=lambda x: lowercase_frequencies[x], reverse=True)

    cipher_map = {}
    for i, cipher_letter in enumerate(cipher_sorted):
        if i < len(english_sorted):
            cipher_map[cipher_letter] = english_sorted[i]

    used_english = set(cipher_map.values())
    remaining_english = [letter for letter in string.ascii_lowercase if letter not in used_english]
    remaining_cipher = [letter for letter in string.ascii_lowercase if letter not in cipher_map]

    for cipher_letter, english_letter in zip(remaining_cipher, remaining_english):
        cipher_map[cipher_letter] = english_letter

    return cipher_map


def frequency_analysis_attack(ciphertext: str) -> SubstitutionGuess:
    """Attempt to break a substitution cipher using frequency analysis.

    Analyzes the frequency of letters in the ciphertext and maps them
    to the most common letters in English based on expected frequencies.

    Args:
        ciphertext (str): The ciphertext to analyze.

    Returns:
        SubstitutionGuess: The best guess for the substitution cipher.
    """
    cipher_letters = "".join(c.lower() for c in ciphertext if c.isalpha())

    if len(cipher_letters) == 0:
        return SubstitutionGuess.empty()

    cipher_map = _create_frequency_mapping(cipher_letters)
    return SubstitutionGuess(ciphertext, cipher_map)


if __name__ == "__main__":
    ciphertext = "swo2024{jytmm_ruvs_opgbzu_mum}"

    print("Attempting frequency analysis attack...")
    guess = frequency_analysis_attack(ciphertext)
    print(f"Score: {guess.score:.4f}")
    print(f"Plaintext: {guess.plaintext}")
    print(f"Cipher map: {guess.cipher_map}")
    print()

    known_cipher_map = {
        "a": "k",
        "b": "n",
        "c": "o",
        "d": "r",
        "e": "v",
        "f": "q",
        "g": "i",
        "h": "w",
        "i": "x",
        "j": "d",
        "k": "h",
        "l": "m",
        "m": "l",
        "n": "y",
        "o": "u",
        "p": "b",
        "q": "f",
        "r": "p",
        "s": "s",
        "t": "z",
        "u": "t",
        "v": "a",
        "w": "c",
        "x": "j",
        "y": "g",
        "z": "e",
    }
    reversed_map = reverse_cipher_map(known_cipher_map)

    print("Using reversed known cipher map...")
    decrypted = apply_substitution_cipher(ciphertext, reversed_map)
    print(f"Decrypted: {decrypted}")
