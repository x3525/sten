"""Custom exceptions."""


class StenError(Exception):
    """Base class for all Sten exceptions."""


class CryptoErrorGroup(StenError):
    """A combination of multiple crypto exceptions."""
