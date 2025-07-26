"""
Command-line interface for CipherGeist.

Provides easy access to cryptographic utilities via the command line.
"""

import argparse
import asyncio
import sys
from pathlib import Path

from ciphergeist.encoders.pixelator import Pixelator
from ciphergeist.encrypters.xorxer import (
    guess_single_key_xor,
    quick_guess_single_byte_xor,
)


def multi_byte_xor(text: bytes, key: bytes) -> bytes:
    """XOR text with a repeating multi-byte key."""
    result = bytearray()
    key_len = len(key)

    for i, byte in enumerate(text):
        result.append(byte ^ key[i % key_len])

    return bytes(result)


def cmd_xor_encrypt_with_key(text: str, key: str) -> None:
    """Encrypt text with a multi-byte string key."""
    text_bytes = text.encode("utf-8")
    key_bytes = key.encode("utf-8")

    encrypted = multi_byte_xor(text_bytes, key_bytes)

    print(f"Original: {text}")
    print(f"Key: {key}")
    print(f"Encrypted (hex): {encrypted.hex()}")

    # Show how to decrypt it
    print(f'To decrypt: ciphergeist xor "{encrypted.hex()}" "{key}"')
    print(f'Or if you forgot the key: ciphergeist xor --guess "{encrypted.hex()}"')


def cmd_xor_guess(ciphertext: str, quick: bool = False) -> None:
    """Guess XOR key for single-byte XOR cipher."""
    try:
        # Try to interpret as hex first
        if all(c in "0123456789abcdefABCDEF" for c in ciphertext.replace(" ", "")):
            cipher_bytes = bytes.fromhex(ciphertext.replace(" ", ""))
        else:
            # Treat as raw bytes
            cipher_bytes = ciphertext.encode("utf-8")
    except ValueError:
        print("Error: Invalid hex string")
        return

    guess = quick_guess_single_byte_xor(cipher_bytes) if quick else guess_single_key_xor(cipher_bytes)

    print(f"Ciphertext: {cipher_bytes.hex()}")
    print(f"Guessed key: {guess.key}")
    print(f"Confidence score: {guess.score:.4f}")
    print(f"Decrypted text: {guess.plaintext!r}")  # Use !r to explicitly show bytes representation

    # Try to decode as UTF-8 for readability
    try:
        readable = guess.plaintext.decode("utf-8", errors="replace")
        print(f"Readable text: {readable}")
    except UnicodeDecodeError:
        pass


async def cmd_pixelator_encode(args: argparse.Namespace) -> None:
    """Encode a document to images using Pixelator."""
    input_path = Path(args.input)
    output_dir = Path(args.output) if args.output else Path("output")

    if not input_path.exists():
        print(f"Error: Input file '{input_path}' not found")
        return

    # Use encryption key if provided, otherwise no encryption
    encryption_key = getattr(args, "password", None)

    async with Pixelator(encryption_key=encryption_key) as pixelator:
        try:
            result = await pixelator.encode_document(input_path, output_dir)
            print(f"✅ Successfully encoded '{input_path}' to {result.chunk_count} images")
            print(f"📁 Output directory: {output_dir}")
            print(f"🖼️  Metadata image: {result.metadata_image}")
            print(f"📊 Total size: {result.total_size} bytes")
            if encryption_key:
                print(f"🔐 Encrypted with XOR key: {encryption_key}")
            else:
                print("🔓 No encryption applied")
        except Exception as e:
            print(f"❌ Encoding failed: {e}")


async def cmd_pixelator_decode(args: argparse.Namespace) -> None:
    """Decode images back to document using Pixelator."""
    metadata_path = Path(args.metadata)
    output_path = Path(args.output)
    images_dir = Path(args.images_dir) if args.images_dir else metadata_path.parent

    if not metadata_path.exists():
        print(f"Error: Metadata image '{metadata_path}' not found")
        return

    # Use decryption key if provided
    decryption_key = getattr(args, "password", None)

    async with Pixelator(encryption_key=decryption_key) as pixelator:
        try:
            success = await pixelator.decode_document(metadata_path, output_path, images_dir)
            if success:
                print(f"✅ Successfully decoded to '{output_path}'")
                if decryption_key:
                    print(f"🔐 Decrypted with XOR key: {decryption_key}")
            else:
                print("❌ Decoding failed")
        except Exception as e:
            print(f"❌ Decoding failed: {e}")


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="ciphergeist",
        description="CipherGeist - Cryptographic utilities and riddles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # XOR encrypt with string key
  ciphergeist xor "Hello World" "mykey"
  ciphergeist xor "Secret message" "password123"

  # XOR decrypt by guessing single-byte key
  ciphergeist xor "52656c6c6f20576f726c64" guess
  ciphergeist xor --guess "52656c6c6f20576f726c64"

  # Quick guessing algorithm
  ciphergeist xor --guess "52656c6c6f20576f726c64" --quick

  # Encode document to images (no encryption)
  ciphergeist pixelator encode --input document.pdf --output ./images/

  # Encode document to images with XOR encryption
  ciphergeist pixelator encode --input document.pdf --output ./images/ --password "mykey"

  # Decode images back to document (no decryption)
  ciphergeist pixelator decode --metadata ./images/metadata.png --output decoded.pdf

  # Decode images back to document with XOR decryption
  ciphergeist pixelator decode --metadata ./images/metadata.png --output decoded.pdf --password "mykey"
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # XOR commands - simple and clean
    xor_parser = subparsers.add_parser("xor", help="XOR encryption utilities")

    # Method 1: ciphergeist xor "text" "key" or ciphergeist xor "text" guess
    xor_parser.add_argument("text", nargs="?", help="Text to encrypt or ciphertext to decrypt")
    xor_parser.add_argument("key_or_guess", nargs="?", help="String key for encryption or 'guess' for decryption")

    # Method 2: ciphergeist xor --guess "ciphertext"
    xor_parser.add_argument("--guess", "-g", metavar="CIPHERTEXT", help="Guess key for the given ciphertext")
    xor_parser.add_argument("--quick", "-q", action="store_true", help="Use quick guessing algorithm")

    # Pixelator commands
    pixel_parser = subparsers.add_parser("pixelator", help="Document-to-image encoding")
    pixel_subparsers = pixel_parser.add_subparsers(dest="pixel_command", help="Pixelator operations")

    # Pixelator encode
    encode_parser = pixel_subparsers.add_parser("encode", help="Encode document to images")
    encode_parser.add_argument("--input", "-i", required=True, help="Input document path")
    encode_parser.add_argument("--output", "-o", help="Output directory (default: ./output)")
    encode_parser.add_argument("--password", "-p", help="XOR encryption key (optional)")

    # Pixelator decode
    decode_parser = pixel_subparsers.add_parser("decode", help="Decode images to document")
    decode_parser.add_argument("--metadata", "-m", required=True, help="Metadata image path")
    decode_parser.add_argument("--output", "-o", required=True, help="Output document path")
    decode_parser.add_argument("--images-dir", "-d", help="Directory containing chunk images")
    decode_parser.add_argument("--password", "-p", help="XOR decryption key (must match encoding key)")

    return parser


def _handle_xor_command(args: argparse.Namespace) -> None:
    """Handle XOR command logic."""
    # Method 2: --guess flag
    if args.guess:
        cmd_xor_guess(args.guess, args.quick)
    # Method 1: positional arguments
    elif args.text and args.key_or_guess:
        if args.key_or_guess.lower() in ["guess", "auto", "g"]:
            # This is a guess request
            cmd_xor_guess(args.text, args.quick)
        else:
            # This is encryption with string key
            cmd_xor_encrypt_with_key(args.text, args.key_or_guess)
    else:
        print("Error: Please provide arguments in one of these formats:")
        print('  ciphergeist xor "Hello World" "mykey"')
        print('  ciphergeist xor "ciphertext" guess')
        print('  ciphergeist xor --guess "ciphertext"')


def _handle_pixelator_command(args: argparse.Namespace) -> None:
    """Handle Pixelator command logic."""
    if not args.pixel_command:
        print("Error: Pixelator command required (encode/decode)")
        return

    if args.pixel_command == "encode":
        asyncio.run(cmd_pixelator_encode(args))
    elif args.pixel_command == "decode":
        asyncio.run(cmd_pixelator_decode(args))


def main() -> None:
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == "xor":
            _handle_xor_command(args)
        elif args.command == "pixelator":
            _handle_pixelator_command(args)

    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
