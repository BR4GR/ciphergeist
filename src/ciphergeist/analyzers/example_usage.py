"""
Example of using the text analyzer with XOR decryption.

This shows how to get absolute confidence (English probability)
rather than just relative confidence (best among options).
"""

from ciphergeist.analyzers import analyze_english_probability
from ciphergeist.encrypters.xorxer import guess_single_key_xor


def enhanced_xor_analysis(ciphertext: bytes) -> tuple:
    """Analyze XOR decryption with both relative and absolute confidence."""

    # Get the best guess using existing method
    best_guess = guess_single_key_xor(ciphertext)

    # Analyze the English probability of the result
    analysis = analyze_english_probability(best_guess.plaintext)

    print("=== XOR Analysis Results ===")
    print(f"Best key: {best_guess.key}")
    print(f"Frequency score: {best_guess.score:.4f}")
    print(f"Plaintext: {best_guess.plaintext.decode(errors='replace')}")
    print()
    print("=== English Analysis ===")
    print(f"English probability: {analysis.english_probability:.1%}")
    print(f"Confidence level: {analysis.confidence_level}")
    print(f"Printable ratio: {analysis.printable_ratio:.1%}")
    print(f"Space ratio: {analysis.space_ratio:.1%}")

    return best_guess, analysis


def test_analyzer_on_books() -> None:
    """Test the English analyzer on real English text from books."""
    import os

    books_dir = os.path.join(os.path.dirname(__file__), "..", "books")
    available_books = ["alice_in_wonderland.txt", "dracula.txt", "frankenstein.txt", "sherlock_holmes.txt"]

    print("=== Testing English Analyzer on Real Books ===")

    for book_name in available_books:
        book_path = os.path.join(books_dir, book_name)
        try:
            with open(book_path, "rb") as f:
                # Read first 1000 bytes as a sample
                text_sample = f.read(1000)

            analysis = analyze_english_probability(text_sample)

            print(f"\n{book_name}:")
            print(f"  English probability: {analysis.english_probability:.1%}")
            print(f"  Confidence level: {analysis.confidence_level}")
            print(f"  Frequency score: {analysis.frequency_score:.4f}")
            print(f"  Printable ratio: {analysis.printable_ratio:.1%}")
            print(f"  Space ratio: {analysis.space_ratio:.1%}")
            print(f"  Sample text: {text_sample[:100].decode(errors='replace')}...")

        except FileNotFoundError:
            print(f"  {book_name}: File not found")
        except Exception as e:
            print(f"  {book_name}: Error - {e}")


if __name__ == "__main__":
    # Test with the Cryptopals challenge
    ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

    print("=== Cryptopals Challenge Analysis ===")
    enhanced_xor_analysis(ciphertext)

    print("\n" + "=" * 60 + "\n")

    # Test analyzer on real English books
    test_analyzer_on_books()
