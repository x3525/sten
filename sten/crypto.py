"""Ciphers."""

import enum
import operator
import re
import string
from abc import ABC, abstractmethod
from typing import Any, Literal

from sten.data import Action

ALPHABET = string.printable


class T(enum.Enum):
    """Custom type hints."""

    JOB = Literal['+', '-']
    VALIDATE_CMD_CODE = Literal['%d', '%i', '%P', '%s', '%S', '%v', '%V', '%W']


class Cipher(ABC):
    """Abstract base class for cipher classes."""

    name: str
    code: tuple[T.VALIDATE_CMD_CODE, T.VALIDATE_CMD_CODE]

    def __init__(self, key: Any, txt: str = '') -> None:
        self._key = key
        self._txt = txt

    @property
    def key(self) -> Any:
        """Cipher key."""
        return self._key

    @key.setter
    def key(self, key: Any) -> None:
        self._key = key

    @property
    def txt(self) -> str:
        """Plain/cipher text."""
        return self._txt

    @txt.setter
    def txt(self, txt: str) -> None:
        self._txt = txt

    @staticmethod
    @abstractmethod
    def validate(action: str, data: str) -> bool:
        """Validate command."""

    @abstractmethod
    def encrypt(self) -> str:
        """Encrypt."""

    @abstractmethod
    def decrypt(self) -> str:
        """Decrypt."""


class NaC(Cipher):
    """Not a cipher."""

    name = ''
    code = ('%d', '%S')

    @staticmethod
    def validate(action: str, data: str) -> bool:
        return False

    def encrypt(self) -> str:
        return self.txt

    def decrypt(self) -> str:
        return self.txt


class Caesar(Cipher):
    """Caesar cipher."""

    name = 'Caesar'
    code = ('%d', '%S')

    def __init__(self, key: str, txt: str = '') -> None:
        super().__init__(int(key), txt)

    @staticmethod
    def validate(action: str, data: str) -> bool:
        return (action == Action.DELETE) or data.isdigit()

    def encrypt(self) -> str:
        return self._do('+')

    def decrypt(self) -> str:
        return self._do('-')

    def _do(self, job: T.JOB) -> str:
        """Encrypt/decrypt."""
        jobs = {
            '+': operator.add,
            '-': operator.sub,
        }

        txt = ''

        for char in self.txt:
            it = ALPHABET.index(char)
            ik = self.key

            txt += ALPHABET[jobs[job](it, ik) % len(ALPHABET)]

        return txt


class Scytale(Cipher):
    """Scytale cipher."""

    name = 'Scytale'
    code = ('%d', '%P')

    def __init__(self, key: str, txt: str = '') -> None:
        super().__init__(int(key), txt)

    @staticmethod
    def validate(action: str, data: str) -> bool:
        return (action == Action.DELETE) or bool(re.match(r'^[1-9]\d*$', data))

    def encrypt(self) -> str:
        return ''.join(self.txt[i::self.key] for i in range(self.key))

    def decrypt(self) -> str:
        full, mod = divmod(len(self.txt), self.key)

        rows = full + (mod > 0)

        middle = rows * mod

        txt = []

        for row in range(full):
            txt.append(self.txt[row:middle:rows])
            txt.append(self.txt[(middle + row)::full])

        txt.append(self.txt[full:middle:rows])

        return ''.join(txt)


class Vigenere(Cipher):
    """Vigenère cipher."""

    name = 'Vigenère'
    code = ('%d', '%S')

    def __init__(self, key: str, txt: str = '') -> None:
        super().__init__(key, txt)

    @staticmethod
    def validate(action: str, data: str) -> bool:
        return (action == Action.DELETE) or (data in ALPHABET)

    def encrypt(self) -> str:
        return self._do('+')

    def decrypt(self) -> str:
        return self._do('-')

    def _do(self, job: T.JOB) -> str:
        """Encrypt/decrypt."""
        jobs = {
            '+': operator.add,
            '-': operator.sub,
        }

        key = iter((self.key * len(self.txt))[:len(self.txt)])

        txt = ''

        for char in self.txt:
            it = ALPHABET.index(char)
            ik = ALPHABET.index(next(key))

            txt += ALPHABET[jobs[job](it, ik) % len(ALPHABET)]

        return txt


ciphers = {
    NaC.name: NaC,
    Caesar.name: Caesar,
    Scytale.name: Scytale,
    Vigenere.name: Vigenere,
}  # type: dict[str, type[Cipher]]
