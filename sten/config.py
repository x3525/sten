"""Configuration module."""

import json
from contextlib import suppress


class Json:
    """JSON class."""

    def __init__(self, path: str) -> None:
        self.path = path

    def load(self) -> dict[str, bool]:
        """Deserialize a JSON document to a Python object."""
        try:
            with open(self.path, encoding='utf-8') as file:
                return json.load(file)
        except (OSError, json.JSONDecodeError):
            return {}

    def dump(self, obj: dict[str, bool]) -> None:
        """Serialize `obj` as a JSON formatted stream to a file-like object."""
        with suppress(OSError), open(self.path, 'w', encoding='utf-8') as file:
            json.dump(obj, file, separators=(',', ':'))
