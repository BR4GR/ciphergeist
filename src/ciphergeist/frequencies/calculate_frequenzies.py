import json
import os
import string
from collections import Counter


def calculate_and_save_frequencies(
    books_dir: str = "src/ciphergeist/books", output_dir: str = "src/ciphergeist/frequencies"
) -> None:
    """Calculate letter frequencies from text files in a specified directory and save them as JSON files.

    Args:
        books_dir (str): Directory containing text files of books.
        output_dir (str): Directory where the frequency JSON files will be saved.

    Returns:
        None
    """
    lowercase_counts: Counter[str] = Counter()
    uppercase_counts: Counter[str] = Counter()
    mixed_counts: Counter[str] = Counter()
    total_letters: int = 0

    for filename in os.listdir(books_dir):
        if filename.endswith(".txt"):
            filepath = os.path.join(books_dir, filename)
            with open(filepath, encoding="utf-8") as f:
                text = f.read()
                total_letters += len(text)
                for char in text:
                    if char in string.ascii_lowercase:
                        lowercase_counts[char] += 1
                        mixed_counts[char.lower()] += 1
                    elif char in string.ascii_uppercase:
                        uppercase_counts[char] += 1
                        mixed_counts[char.lower()] += 1

    def normalize_counts(counts: Counter[str]) -> dict[str, float]:
        total = sum(counts.values())
        return {char: count / total for char, count in counts.items()}

    lowercase_frequencies = normalize_counts(lowercase_counts)
    uppercase_frequencies = normalize_counts(uppercase_counts)
    mixed_frequencies = normalize_counts(mixed_counts)

    os.makedirs(output_dir, exist_ok=True)  # Ensure the output directory exists

    def save_json(data: dict[str, float], filename: str) -> None:
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    save_json(lowercase_frequencies, "lowercase_frequencies.json")
    save_json(uppercase_frequencies, "uppercase_frequencies.json")
    save_json(mixed_frequencies, "mixed_frequencies.json")

    print(f"Processed {total_letters} letters from books in {books_dir}")
    print(f"Frequencies saved to {output_dir}")


if __name__ == "__main__":
    calculate_and_save_frequencies()
