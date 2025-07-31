from collections import Counter
from dataclasses import dataclass

from ciphergeist.frequencies.lowercase_frequencies import letter_frequencies as lowercase_frequencies


@dataclass(order=True)
class Guess:
    score: float
    key: int
    ciphertext: bytes
    plaintext: bytes

    def __init__(self, ciphertext: bytes, key: int, is_empty: bool = False):
        self.ciphertext = ciphertext
        self.key = key
        if is_empty:
            self.plaintext = b""
            self.score = float("inf")
            return
        self.plaintext = single_byte_xor(ciphertext, key)
        self.score = score_text(self.plaintext)

    @classmethod
    def empty(cls) -> "Guess":
        """Create an empty guess with infinite score for comparison."""
        return cls(b"", 0, is_empty=True)


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
    counts_text: Counter[str] = Counter()
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
    best_guess = Guess.empty()
    for key in range(256):
        current_guess = Guess(ciphertext, key)
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
    best_guess = Guess.empty()
    for char in common_chars:
        current_guess = Guess(ciphertext, most_common_byte ^ ord(char))
        best_guess = min(best_guess, current_guess)
    return best_guess


def find_minimal_pattern(data: bytes) -> bytes:
    """Find the shortest repeating pattern in the data.

    Args:
        data (bytes): The data to analyze for repeating patterns.

    Returns:
        bytes: The shortest repeating pattern, or the original data if no pattern found.
    """
    if not data:
        return data

    for pattern_len in range(1, len(data) // 2 + 1):
        pattern = data[:pattern_len]
        is_repeating = True
        for i in range(len(data)):
            if data[i] != pattern[i % pattern_len]:
                is_repeating = False
                break
        if is_repeating:
            return pattern

    return data


def derive_xor_key(ciphertext: bytes, known_plaintext: bytes) -> bytes:
    """Derive the XOR key from known plaintext and ciphertext.

    The known plaintext can be shorter than the ciphertext. This function
    will derive the repeating key pattern and return the minimal key.

    Args:
        ciphertext (bytes): The encrypted data.
        known_plaintext (bytes): The known plaintext (can be shorter than ciphertext).

    Returns:
        bytes: The minimal repeating XOR key.

    Raises:
        ValueError: If known_plaintext is longer than ciphertext.
    """
    if len(known_plaintext) > len(ciphertext):
        raise ValueError("Known plaintext cannot be longer than ciphertext")

    raw_key = fixed_xor(ciphertext[: len(known_plaintext)], known_plaintext)

    return find_minimal_pattern(raw_key)


if __name__ == "__main__":
    example_ciphertext = b"\x8c\x9c\x9b\xa4\xa7\xef\xad\x80\xbd\xad\xaa\xab\xec\x80\xec\xe6\xbd\xba\xef\xed\xb9\xb9\xa2"
    example_plaintext = b"SCD{"

    derived_key = derive_xor_key(example_ciphertext, example_plaintext)
    print(f"Derived key: {derived_key!r}")
    print(f"Key as hex: {derived_key.hex()}")
    print(f"Key length: {len(derived_key)} bytes")

    if len(derived_key) == 1:
        decrypted = single_byte_xor(example_ciphertext, derived_key[0])
        print(f"Decrypted (single-byte): {decrypted!r}")
    else:
        extended_key = (derived_key * ((len(example_ciphertext) // len(derived_key)) + 1))[: len(example_ciphertext)]
        decrypted = fixed_xor(example_ciphertext, extended_key)
        print(f"Decrypted (multi-byte): {decrypted!r}")
