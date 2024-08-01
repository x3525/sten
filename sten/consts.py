"""This file contains constants."""

##############
# Extensions #
##############
EXTENSIONS_PICTURE = (
    '.bmp',
    '.png',
)
EXTENSIONS_PICTURE_PRETTY = '|'.join(ext for ext in EXTENSIONS_PICTURE)

#########
# Modes #
#########
MODES_PICTURE = (
    'RGB',
    'RGBA',
)
MODES_PICTURE_PRETTY = '|'.join(mode for mode in MODES_PICTURE)

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
RGB = 3

B = 8

DELIMITER = '$t3nb7$3rh@tC3l!k'

MINIMUM_PIXEL = B + (B * len(DELIMITER))

ENTRY_SHOW_CHAR = '*'
