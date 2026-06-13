"""This file contains constants."""

##############
# Extensions #
##############
PICTURE_EXTENSIONS = (
    '.bmp',
    '.png',
)
PICTURE_EXTENSIONS_PRETTY = '|'.join(PICTURE_EXTENSIONS)

#########
# Modes #
#########
PICTURE_MODES = (
    'RGB',
    'RGBA',
)
PICTURE_MODES_PRETTY = '|'.join(PICTURE_MODES)

############
# Paddings #
############
IX = 10
IY = 10
PX = (5, 5)
PY = (5, 5)

#############
# Sequences #
#############
SEQUENCE_COPY = ('<Control-Key-c>', '<Control-Lock-Key-C>')
SEQUENCE_CUT = ('<Control-Key-x>', '<Control-Lock-Key-X>')
SEQUENCE_DECODE = ('<Control-Key-d>', '<Control-Lock-Key-D>')
SEQUENCE_ENCODE = ('<Control-Key-e>', '<Control-Lock-Key-E>')
SEQUENCE_OPEN_FILE = ('<Control-Key-n>', '<Control-Lock-Key-N>')
SEQUENCE_PASTE = ('<Control-Key-v>', '<Control-Lock-Key-V>')
SEQUENCE_PREFERENCES = ('<Control-Key-p>', '<Control-Lock-Key-P>')
SEQUENCE_REDO = ('<Control-Key-y>', '<Control-Lock-Key-Y>')
SEQUENCE_SELECT_ALL = ('<Control-Key-a>', '<Control-Lock-Key-A>')
SEQUENCE_UNDO = ('<Control-Key-z>', '<Control-Lock-Key-Z>')

#################
# Miscellaneous #
#################
B, RGB = 8, 3

SUFFIX = '$3rh@tC3l!k'

MIN_PIXELS = B + (B * len(SUFFIX))

ENTRY_SHOW_CHAR = '*'
