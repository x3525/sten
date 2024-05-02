"""Ciphers."""

import enum
import math
import operator
import re
import string
from abc import ABC, abstractmethod
from itertools import product
from typing import Any, Literal

import numpy as np
from numpy.typing import NDArray

from sten.data import Action
from sten.error import CryptoErrorGroup

ALPHABET = string.printable
ALPHABET_LENGTH = len(ALPHABET)


class T(enum.Enum):
    """Custom type hints."""

    ARR_ND_I = NDArray[np.int32]
    JOB = Literal['+', '-']
    ORD = Literal['i', 'j']
    VCMD_CODE = Literal['%d', '%i', '%P', '%s', '%S', '%v', '%V', '%W']


class Cipher(ABC):
    """Abstract base class for cipher classes."""

    name: str
    code: tuple[T.VCMD_CODE, T.VCMD_CODE]

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


class NotACipher(Cipher):
    """Not a cipher."""

    name = ''
    code = ('%d', '%S')

    def __init__(self, key: str, txt: str = '') -> None:
        super().__init__(key, txt)

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

        if (self.key % ALPHABET_LENGTH) == 0:
            raise CryptoErrorGroup('Key error. Shift value is equal to 0.')

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
            i_txt = ALPHABET.index(char)
            i_key = self.key

            txt += ALPHABET[jobs[job](i_txt, i_key) % ALPHABET_LENGTH]

        return txt


class Hill(Cipher):
    """Hill cipher."""

    name = 'Hill'
    code = ('%d', '%S')

    def __init__(self, key: str, txt: str = '') -> None:
        super().__init__(key, txt)

        row = math.ceil(math.sqrt(len(key)))

        self.key = self._fill(key, shape=(row, row), order='i')

        determinant = round(np.linalg.det(self.key))

        if determinant == 0:
            raise CryptoErrorGroup('Key matrix is not invertible.')
        if math.gcd(determinant, ALPHABET_LENGTH) != 1:
            raise CryptoErrorGroup(
                'Key determinant and alphabet length are not co-prime.'
            )

        self._row = row

        self._adj = np.linalg.inv(self.key) * determinant

        self._inv = pow(determinant, -1, ALPHABET_LENGTH)

    @staticmethod
    def validate(action: str, data: str) -> bool:
        return (action == Action.DELETE) or (data in ALPHABET)

    def encrypt(self) -> str:
        return self._do(self.key)

    def decrypt(self) -> str:
        return self._do(np.array(np.around(self._adj * self._inv)))

    @staticmethod
    def _fill(values: str, shape: tuple[int, int], order: T.ORD) -> T.ARR_ND_I:
        """Create a new matrix and fill it."""
        orders = {
            'i': lambda *given: given,
            'j': lambda *given: given[::-1],
        }

        matrix = np.zeros(shape=shape, dtype=int)

        row, col = orders[order](*shape)

        extra, idx = 0, 0

        for i, j in product(range(row), range(col)):
            if idx == len(values):
                matrix[orders[order](i, j)] = extra
                extra += 1
                continue

            matrix[orders[order](i, j)] = ALPHABET.index(values[idx])
            idx += 1

        return matrix

    def _do(self, matrix: NDArray) -> str:
        """Encrypt/decrypt."""
        col = math.ceil(len(self.txt) / self._row)

        vectors = self._fill(self.txt, shape=(self._row, col), order='j')

        multiplied = np.matmul(matrix.astype(int), vectors)
        transposed = np.transpose(multiplied)

        return ''.join(
            ALPHABET[i] for i in (np.concatenate(transposed) % ALPHABET_LENGTH)
        )


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
            i_txt = ALPHABET.index(char)
            i_key = ALPHABET.index(next(key))

            txt += ALPHABET[jobs[job](i_txt, i_key) % ALPHABET_LENGTH]

        return txt


ciphers = {
    NotACipher.name: NotACipher,
    Caesar.name: Caesar,
    Hill.name: Hill,
    Scytale.name: Scytale,
    Vigenere.name: Vigenere,
}  # type: dict[str, type[Cipher]]
