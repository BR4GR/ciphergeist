from collections import Counter
from dataclasses import dataclass
from typing import Optional

from ciphergeist.frequencies.lowercase import lowercase_frequencies


@dataclass(order=True)
class Guess:
    score: float = float("inf")
    key: Optional[int] = None
    ciphertext: Optional[bytes] = None
    plaintext: Optional[bytes] = None

    @classmethod
    def score_key(cls, ciphertext, key):
        plaintext = single_byte_xor(ciphertext, key)
        score = score_text(plaintext)
        return cls(score, key, ciphertext, plaintext)


def score_text(text: bytes) -> float:
    """Score a byte string based on letter frequency analysis.

    This function compares the frequency of letters in the text against
    a predefined frequency distribution of lowercase letters in English text.

    Args:
        text (bytes): The byte string to score.

    Returns:
        float: The score representing the difference in letter frequencies.
            A lower score indicates a closer match to expected frequencies.
    """
    if len(text) == 0:
        raise ValueError("Input text cannot be empty")
    counts_text = Counter()
    for letter in lowercase_frequencies:
        counts_text[letter] = text.count(letter.encode())
    total = sum(counts_text.values())
    if total == 0:
        return float("inf")

    frequencies_text = {letter: counts_text[letter] / total for letter in lowercase_frequencies}
    errors = {abs(lowercase_frequencies[letter] - frequencies_text[letter]) for letter in lowercase_frequencies}
    score = sum(errors)
    return score


def fixed_xor(a: bytes, b: bytes) -> bytes:
    """Perform a fixed XOR operation on two byte strings.

    Args:
        a (bytes): The first byte string.
        b (bytes): The second byte string.

    Returns:
        bytes: The result of the XOR operation.

    Raises:
        ValueError: If the input byte strings are of different lengths.
    """
    if len(a) != len(b):
        raise ValueError("Input must be of the same length.")
    return bytes(x ^ y for x, y in zip(a, b))


def single_byte_xor(input_bytes: bytes, key: int) -> bytes:
    """Perform a single-byte XOR operation on a byte string.

    Args:
        input_bytes (bytes): The byte string to be XORed.
        key (int): The single-byte key to XOR with (0-255).

    Returns:
        bytes: The result of the XOR operation.

    Raises:
        ValueError: If the key is not an integer in the range 0-255.
    """
    if not (0 <= key <= 255):
        raise ValueError("Key must be int (0-255).")
    return bytes(b ^ key for b in input_bytes)


def guess_single_key_xor(ciphertext: bytes) -> Guess:
    """Guess the single-byte XOR key for a given ciphertext.

    Iterates through all possible single-byte keys (0-255)
    and scores the resulting plaintext using letter frequency analysis.

    Args:
        ciphertext (bytes): The ciphertext to analyze.

    Returns:
        Guess: The best guess containing the key, plaintext, and score.
    """
    best_guess = Guess()
    for key in range(256):
        current_guess = Guess.score_key(ciphertext, key)
        best_guess = min(best_guess, current_guess)
    return best_guess


def quick_guess_single_byte_xor(ciphertext: bytes) -> Guess:
    """Quickly guess a single-byte XOR key.

    Using letter frequency analysis.
    Asuming the most common byte in the ciphertext corresponds to
    the most common letter in English text (e.g., 'e', 't', 'a').

    Args:
        ciphertext (bytes): The ciphertext to analyze.

    Returns:
        list[tuple[float, int, bytes]]: A sorted list of tuples containing the score,
            key, and plaintext for each candidate key.
    """
    frequencies = Counter(ciphertext)
    most_common_byte = frequencies.most_common(1)[0][0]
    common_chars = set(" etaoinshrdlu")
    best_guess = Guess()
    for char in common_chars:
        current_guess = Guess.score_key(ciphertext, most_common_byte ^ ord(char))
        best_guess = min(best_guess, current_guess)
    return best_guess


if __name__ == "__main__":
    ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    guess = quick_guess_single_byte_xor(ciphertext)
    print(f"Best guess: {guess.key}, Score: {guess.score} - {guess.plaintext.decode()}")
