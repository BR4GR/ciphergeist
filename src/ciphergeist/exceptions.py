"""Custom exceptions for CipherGeist."""


class CipherGeistError(Exception):
    """Base exception for CipherGeist."""

    pass


class EncryptionError(CipherGeistError):
    """Raised when encryption operations fail."""

    pass


class DecryptionError(CipherGeistError):
    """Raised when decryption operations fail."""

    pass


class EncodingError(CipherGeistError):
    """Raised when encoding operations fail."""

    pass


class DecodingError(CipherGeistError):
    """Raised when decoding operations fail."""

    pass


class InvalidKeyError(CipherGeistError):
    """Raised when an invalid encryption key is provided."""

    pass


class CorruptedDataError(CipherGeistError):
    """Raised when data integrity checks fail."""

    pass
