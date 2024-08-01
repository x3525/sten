"""General utilities."""

import os


def nonalphabet(chars: str, alphabet: str) -> str:
    """Get the first non-alphabet character from the given `chars`, if any."""
    for char in chars:
        if char not in alphabet:
            return char
    return ''


def splitext(path: str) -> tuple[str, str]:
    """Split the pathname `path` into a pair."""
    tail = os.path.split(path)[1]

    sep, extension = tail.rpartition('.')[1:]

    extension = (sep + extension) if sep else sep

    filename = path.removesuffix(extension)

    return filename, extension
