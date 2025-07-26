"""
CipherGeist - Cryptographic utilities and riddles.

A collection of cryptographic tools, encoders, and frequency analysis utilities.
"""

__version__ = "0.0.1"

# Export main classes and functions for easy access
from .encoders.pixelator import ChunkInfo, EncodingResult, Pixelator
from .encrypters.xorxer import (
    Guess,
    fixed_xor,
    guess_single_key_xor,
    quick_guess_single_byte_xor,
    single_byte_xor,
)

__all__ = [
    "ChunkInfo",
    "EncodingResult",
    "Guess",
    "Pixelator",
    "fixed_xor",
    "guess_single_key_xor",
    "quick_guess_single_byte_xor",
    "single_byte_xor",
]
