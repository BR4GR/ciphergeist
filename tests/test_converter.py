import sys
from pathlib import Path

import pytest

from ciphergeist.converter import convert_hex_to_base64

# Add the parent directory to path so we can import the module
sys.path.append(str(Path(__file__).parent.parent))


def test_convert_hex_to_base64_normal_case():
    """Test conversion works with standard input."""
    hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert convert_hex_to_base64(hex_input) == expected


def test_convert_hex_to_base64_empty_string():
    """Test conversion works with empty string."""
    assert convert_hex_to_base64("") == ""


def test_convert_hex_to_base64_invalid_input():
    """Test conversion raises appropriate error with invalid hex."""
    with pytest.raises(ValueError):
        convert_hex_to_base64("ZZ")
