
# Detect single-character XOR

One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)

```python
input_file = Path("docs/cryptopals/inputs/set1_basics/4.txt")

if not input_file.exists():
    print(f"Error: Input file not found at {input_file}")
    return

best_result = None
best_probability = 0.0

with open(input_file) as f:
    for line_num, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue

        try:
            ciphertext = bytes.fromhex(line)
            guess, analysis = guess_single_byte_xor_with_english_analysis(ciphertext)

            if analysis.english_probability > best_probability:
                best_probability = analysis.english_probability
                best_result = (line_num, guess, analysis)

        except ValueError:
            print(f"Warning: Could not decode line {line_num}")

if best_result:
    line_num, guess, analysis = best_result
    print(f"Found English text on line {line_num}:")
    print(f"Text: '{guess.plaintext.decode('utf-8', errors='replace').strip()}'")
    print(f"XOR Key: {guess.key} (0x{guess.key:02x})")
    print(f"English Probability: {analysis.english_probability:.1%}")
else:
    print("No English text found!")
```

Found English text on line 171:
Text: 'Now that the party is jumping'
XOR Key: 53 (0x35)
English Probability: 38.0%
