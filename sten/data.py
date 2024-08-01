"""Various data."""

import enum
import os


class StrEnum(str, enum.Enum):
    """Base class for string enumeration classes."""

    def __str__(self) -> str:
        return self.value


class Action(StrEnum):
    """Validate command actions.

    https://www.tcl.tk/man/tcl/TkCmd/entry.html#M16
    """

    FOCUS = '-1'
    DELETE = '0'
    INSERT = '1'


class Bd(StrEnum):
    """Border width enumeration."""

    NONE = '0'
    THIN = '2'
    WIDE = '5'


class Color(StrEnum):
    """Color enumeration."""

    BLACK = '#000000'
    BLUE = '#0000FF'
    BUTTON = '#F0F0F0'
    GREEN = '#00FF00'
    RED = '#FF0000'
    WHITE = '#FFFFFF'


class FilePath(StrEnum):
    """File path enumeration."""

    CONFIG = os.path.join(os.path.expanduser('~'), '.sten.json')


class Hotkey(StrEnum):
    """Menu item accelerator enumeration."""

    COPY = 'Ctrl+C'
    CUT = 'Ctrl+X'
    DECODE = 'Ctrl+D'
    ENCODE = 'Ctrl+E'
    OPEN_FILE = 'Ctrl+N'  # Stay away from Ctrl+O accelerator!
    PASTE = 'Ctrl+V'
    PREFERENCES = 'Ctrl+P'
    REDO = 'Ctrl+Y'
    SELECT_ALL = 'Ctrl+A'
    UNDO = 'Ctrl+Z'


class Url(StrEnum):
    """URL enumeration."""

    RSS = 'https://pypi.org/rss/project/project-sten/releases.xml'
    WEBSITE = 'https://github.com/x3525/sten'


class VEvent(StrEnum):
    """Virtual event enumeration."""

    COPY = '<<Copy>>'
    CUT = '<<Cut>>'
    DECODE = '<<_Decode_>>'
    ENCODE = '<<_Encode_>>'
    OPEN_FILE = '<<_OpenFile_>>'
    PASTE = '<<Paste>>'
    PREFERENCES = '<<_Preferences_>>'
    REDO = '<<Redo>>'
    SELECT_ALL = '<<SelectAll>>'
    UNDO = '<<Undo>>'
