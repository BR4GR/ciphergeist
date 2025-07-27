
# Single-byte XOR cipher

The hex encoded string:

```plaintext
1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
```

... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.

## Solution

### Approach

This challenge requires us to:
1. Try all possible single-byte XOR keys (0-255)
2. Decrypt the ciphertext with each key
3. Score the resulting plaintext to determine which looks most like English
4. Return the key and plaintext with the best score

### Implementation

The solution is implemented in `src/ciphergeist/encrypters/xorxer.py` with the following key components:

#### 1. Single-byte XOR Function
```python
def single_byte_xor(input_bytes: bytes, key: int) -> bytes:
    """Perform a single-byte XOR operation on a byte string."""
    if not (0 <= key <= 255):
        raise ValueError("Key must be int (0-255).")
    return bytes(b ^ key for b in input_bytes)
```

#### 2. Text Scoring Algorithm
The scoring function uses English letter frequency analysis:

```python
def score_text(text: bytes) -> float:
    """Score a byte string based on letter frequency analysis."""
    # Count letter frequencies in the text
    counts_text = Counter()
    for letter in lowercase_frequencies:
        counts_text[letter] = text.count(letter.encode())

    total = sum(counts_text.values())
    if total == 0:
        return float("inf")

    # Calculate frequency differences from expected English frequencies
    frequencies_text = {letter: counts_text[letter] / total for letter in lowercase_frequencies}
    errors = {abs(lowercase_frequencies[letter] - frequencies_text[letter]) for letter in lowercase_frequencies}
    score = sum(errors)
    return score
```

The scoring compares the frequency of letters in the decrypted text against known English letter frequencies. A lower score indicates text that's more likely to be English.

#### 3. Brute Force Key Guessing
```python
def guess_single_key_xor(ciphertext: bytes) -> Guess:
    """Guess the single-byte XOR key for a given ciphertext."""
    best_guess = Guess.empty()
    for key in range(256):
        current_guess = Guess(ciphertext, key)
        best_guess = min(best_guess, current_guess)
    return best_guess
```

#### 4. Optimized Quick Guess
For faster results, there's also a heuristic approach:

```python
def quick_guess_single_byte_xor(ciphertext: bytes) -> Guess:
    """Quickly guess a single-byte XOR key using frequency heuristics."""
    frequencies = Counter(ciphertext)
    most_common_byte = frequencies.most_common(1)[0][0]
    common_chars = set(" etaoinshrdlu")  # Most common English characters

    best_guess = Guess.empty()
    for char in common_chars:
        current_guess = Guess(ciphertext, most_common_byte ^ ord(char))
        best_guess = min(best_guess, current_guess)
    return best_guess
```

This assumes the most frequent byte in the ciphertext corresponds to a common English character.
