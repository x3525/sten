"""Sten — LSB-based image steganography tool."""

import collections
import ctypes
import dataclasses
import math
import os
import random
import string
import sys
import tkinter as tk
import tkinter.filedialog as fd
import tkinter.messagebox as mb
import traceback
import urllib.error
import urllib.request
import warnings
import webbrowser
from contextlib import suppress
from itertools import compress, product
from tkinter import ttk
from tkinter.font import Font
from tkinter.scrolledtext import ScrolledText
from typing import NoReturn, Optional

import defusedxml.ElementTree as ET  # type: ignore
import numpy as np
from PIL import Image, UnidentifiedImageError
from numpy.typing import NDArray

from sten.__version__ import __version__
from sten.config import Json
from sten.consts import *
from sten.crypto import ALPHABET, Hill, ciphers
from sten.data import Bd, Color, FilePath, Hotkey, Url, VEvent
from sten.error import CryptoErrorGroup
from sten.icons import *
from sten.utils import nonalphabet, splitext


@dataclasses.dataclass
class Glob:
    """Global "control" variables for the internal module."""

    bandlsb: tuple[tuple[int, int], ...]
    limit: int


@dataclasses.dataclass
class Picture:
    """Image properties of a previously opened picture file."""

    pixel: int
    imagedata: NDArray
    dimensions: tuple[int, int]
    mode: str

    filename: str
    extension: str

    properties: tuple[str, ...]


def openasfile(event: tk.Event) -> Optional[str]:
    """Open a picture file."""
    retry = True
    while retry:
        file = fd.askopenfilename(
            filetypes=[('Picture Files', EXTENSIONS_PICTURE)],
            initialdir='~',
            title='Open File',
        )

        if not file:
            break

        filename, extension = splitext(file)

        if extension.casefold() not in EXTENSIONS_PICTURE:
            retry = mb.askretrycancel(
                message=f'Not a valid file extension: {extension}',
                detail=f'Valid file extensions: {EXTENSIONS_PICTURE_PRETTY}',
            )
            continue

        try:
            with Image.open(file) as picture:
                pixel = math.prod(picture.size)
                imagedata = list(picture.getdata())
                dimensions = picture.size
                mode = picture.mode
        except (
                OSError,
                UnidentifiedImageError,
                Image.DecompressionBombError, Image.DecompressionBombWarning,
        ) as err:
            retry = mb.askretrycancel(message=str(err))
            continue

        if mode not in MODES_PICTURE:
            retry = mb.askretrycancel(
                message=f'File mode is not supported: {mode}',
                detail=f'Supported file modes: {MODES_PICTURE_PRETTY}',
            )
            continue

        if pixel < MINIMUM_PIXEL:
            retry = mb.askretrycancel(
                message=f'Need minimum {MINIMUM_PIXEL} pixels.',
                detail=f'Provided: {pixel} pixels',
            )
            continue

        # Important! After all error checks are passed, set attributes here!
        Picture.pixel = pixel
        Picture.imagedata = np.array(imagedata)
        Picture.dimensions = (width, height) = dimensions
        Picture.mode = mode

        Picture.filename = os.path.basename(filename)
        Picture.extension = extension

        capacity = (Picture.pixel * RGB) - len(DELIMITER)

        Picture.properties = (
            f'Capacity: {capacity} characters',
            f'Width: {width} pixels',
            f'Height: {height} pixels',
            f'Bit depth: {B * len(Picture.mode)} ({Picture.mode})',
        )

        Var_opened.set(file)
        Var_output.set('')

        B_show['state'] = tk.DISABLED

        return None

    return 'break'  # No more event processing for virtual event "OPEN_FILE"


def showfile() -> None:
    """Show a previously created stego-object."""
    with suppress(AttributeError, OSError):
        os.startfile(Var_output.get(), operation='open')  # nosec


def encode(event: tk.Event) -> None:
    """Create a stego-object."""
    name, key = X_ciphers.get(), E_key.get()

    if (not key) and name:
        return

    message = tabs['message'].get('1.0', tk.END)[:-1]

    if not message:
        return

    if char := nonalphabet(message, ALPHABET):
        mb.showerror(
            message='Message contains a non-alphabet character.',
            detail=f'Character: {char}',
        )
        return

    try:
        cipher = ciphers[name](key, message)
    except CryptoErrorGroup as err:
        mb.showerror(message=str(err))
        return

    message = cipher.encrypt()

    # Check the character limit, for Hill cipher :/
    if (cipher.name == Hill.name) and (len(message) > Glob.limit):
        mb.showerror(
            message='Cipher text length exceeds the character limit.',
            detail=f'Limit: {Glob.limit}',
        )
        return

    if DELIMITER in message:
        if not mb.askokcancel(
                message='Some data will be lost!',
                detail='MESSAGE WILL CONTAIN THE DELIMITER',
                icon=mb.WARNING,
        ):
            return

    output = fd.asksaveasfilename(
        confirmoverwrite=True,
        defaultextension=Picture.extension,
        filetypes=[('Picture Files', EXTENSIONS_PICTURE)],
        initialfile=f'{Picture.filename}-encoded',
        title='Save As',
    )

    if not output:
        return

    _, extension = splitext(output)

    if extension.casefold() not in EXTENSIONS_PICTURE:
        mb.showerror(
            message=f'Not a valid file extension: {extension}',
            detail=f'Valid file extensions: {EXTENSIONS_PICTURE_PRETTY}',
        )
        return

    message += DELIMITER

    image = Picture.imagedata.copy()

    # Characters -> Bits
    bits = ''.join(format(ord(c), f'0{B}b') for c in message)

    bits_length = len(bits)

    pixels = list(range(Picture.pixel))

    if seed := E_prng.get():
        random.seed(seed)
        random.shuffle(pixels)

    i = 0

    for pix, (band, lsb) in product(pixels, Glob.bandlsb):
        if i >= bits_length:
            break

        val = format(image[pix][band], f'0{B}b')

        pack = val[:B - lsb] + (_ := bits[i:i + lsb]) + val[B - lsb + len(_):]

        # Bits -> File
        image[pix][band] = int(pack, 2)

        i += lsb

    shape = Picture.imagedata.shape[1]
    array = image.reshape((*Picture.dimensions[::-1], shape)).astype(np.uint8)

    try:
        Image.fromarray(array).save(output)
    except OSError as err:
        mb.showerror(message=str(err))
        return

    Var_output.set(output)

    B_show['state'] = tk.NORMAL

    mb.showinfo(message='File is encoded!')


def decode(event: tk.Event) -> None:
    """Extract a hidden message from a stego-object."""
    name, key = X_ciphers.get(), E_key.get()

    if (not key) and name:
        return

    try:
        cipher = ciphers[name](key)
    except CryptoErrorGroup as err:
        mb.showerror(message=str(err))
        return

    pixels = list(range(Picture.pixel))

    if seed := E_prng.get():
        random.seed(seed)
        random.shuffle(pixels)

    for bandlsb in possibilities if cnf['BruteLSB'].get() else (Glob.bandlsb,):
        bits, message = '', ''

        for pix, (band, lsb) in product(pixels, bandlsb):
            if message.endswith(DELIMITER):
                break  # No need to go any further

            # File -> Bits
            bits += format(Picture.imagedata[pix][band], f'0{B}b')[-lsb:]

            if len(bits) >= B:
                # Bits -> Characters
                message += chr(int(bits[:B], 2))
                bits = bits[B:]

        if message.endswith(DELIMITER):
            break
    else:
        mb.showwarning(message='No hidden message found.')
        return

    if nonalphabet(message, ALPHABET):
        mb.showerror(
            message='Message contains a non-alphabet character.',
            detail='ARE YOU SURE THIS MESSAGE WAS CREATED USING STEN?',
        )
        return

    message = message.removesuffix(DELIMITER)

    cipher.txt = message
    message = cipher.decrypt()

    tabs['decoded']['state'] = tk.NORMAL
    tabs['decoded'].delete('1.0', tk.END)
    tabs['decoded'].insert('1.0', message)
    tabs['decoded']['state'] = tk.DISABLED

    N_stego.select(tabs['decoded'])

    Var_output.set('')

    B_show['state'] = tk.DISABLED

    mb.showinfo(message='File is decoded!')


def preferences(event: tk.Event) -> None:
    """Show preferences."""
    toplevel = tk.Toplevel(root)

    toplevel.grab_set()  # Direct all events to this Toplevel

    toplevel.pack_propagate(True)

    toplevel.wm_attributes('-topmost', 1)

    toplevel.wm_title('Preferences')

    toplevel.wm_resizable(False, False)

    root.eval(f'tk::PlaceWindow {toplevel} center')

    tk.Checkbutton(
        toplevel,
        anchor=tk.W,
        text='Confirm before exiting the program',
        variable=cnf['ConfirmExit'],
    ).pack_configure(expand=True, fill=tk.BOTH, side=tk.TOP)
    tk.Checkbutton(
        toplevel,
        anchor=tk.W,
        text='Use brute force technique to decode',
        variable=cnf['BruteLSB'],
    ).pack_configure(expand=True, fill=tk.BOTH, side=tk.TOP)


def properties() -> None:
    """Show image properties."""
    mb.showinfo(message='\n'.join(getattr(Picture, 'properties', [])))


def close() -> None:
    """Save preferences and destroy the main window."""
    if cnf['ConfirmExit'].get():
        if not mb.askokcancel(message='Are you sure you want to exit?'):
            return

    jason.dump({key: variable.get() for key, variable in cnf.items()})

    root.quit()  # Widgets can be accessed later


def manipulate(v_event: str) -> None:
    """Use a manipulation by triggering the given virtual event."""
    widget = root.focus_get()

    if not widget:
        return

    widget.event_generate(v_event)


def focusset(event: tk.Event) -> None:
    """Direct input focus to the widget."""
    event.widget.focus_set()


def popup(event: tk.Event) -> None:
    """Show context menu."""
    try:
        M_edit.tk_popup(event.x_root, event.y_root)
    finally:
        M_edit.grab_release()


def always() -> None:
    """Toggle "Always on Top" state."""
    topmost = root.wm_attributes()[root.wm_attributes().index('-topmost') + 1]
    root.wm_attributes('-topmost', 1 - topmost)


def transparent() -> None:
    """Toggle "Transparent" state."""
    alpha = root.wm_attributes()[root.wm_attributes().index('-alpha') + 1]
    root.wm_attributes('-alpha', 1.5 - alpha)


def check_for_updates() -> None:
    """Check for program updates."""
    try:
        with urllib.request.urlopen(Url.RSS, timeout=9) as feed:  # nosec
            latest = ET.fromstring(feed.read()).findtext('channel/item/title')
    except urllib.error.URLError as err:
        mb.showerror(message=str(err))
    else:
        mb.showinfo(message=('Outdated.', 'All good!')[__version__ == latest])


def activate(event: tk.Event) -> None:
    """When a file is opened, this method binds widgets to "F5" once."""
    root.bind(VEvent.OPEN_FILE, openasfile)
    root.bind(VEvent.OPEN_FILE, refresh, add='+')

    M_edit.entryconfigure(MENU_ITEM_INDEX_UNDO, state=tk.NORMAL)
    M_edit.entryconfigure(MENU_ITEM_INDEX_REDO, state=tk.NORMAL)
    M_edit.entryconfigure(MENU_ITEM_INDEX_CUT, state=tk.NORMAL)
    M_edit.entryconfigure(MENU_ITEM_INDEX_COPY, state=tk.NORMAL)
    M_edit.entryconfigure(MENU_ITEM_INDEX_PASTE, state=tk.NORMAL)
    M_edit.entryconfigure(MENU_ITEM_INDEX_SELECT_ALL, state=tk.NORMAL)

    root.bind(VEvent.UNDO, refresh)
    root.bind(VEvent.REDO, refresh)
    root.bind(VEvent.CUT, refresh)
    root.bind(VEvent.PASTE, refresh)

    E_prng['state'] = tk.NORMAL

    X_ciphers['state'] = 'readonly'
    X_ciphers.bind('<<ComboboxSelected>>', refresh)

    E_key['state'] = tk.NORMAL
    E_key.bind('<KeyRelease>', refresh)

    N_stego.tab(tabs['message'], state=tk.NORMAL)
    N_stego.tab(tabs['decoded'], state=tk.NORMAL)

    N_stego.select(tabs['message'])

    tabs['message']['state'] = tk.NORMAL
    tabs['message']['bg'] = Color.WHITE
    tabs['message'].bind('<ButtonPress-3>', focusset)
    tabs['message'].bind('<ButtonRelease-3>', popup)
    tabs['message'].bind('<KeyRelease>', refresh)

    for scl in scales:
        scl['state'] = tk.NORMAL
        scl.bind('<ButtonRelease-1>', refresh)  # Left mouse button release
        scl.bind('<ButtonRelease-2>', refresh)  # Middle mouse button release
        scl.bind('<ButtonRelease-3>', refresh)  # Right mouse button release
        scl.bind('<B1-Motion>', refresh)
        scl.bind('<B2-Motion>', refresh)
        scl.bind('<B3-Motion>', refresh)


def refresh(event: tk.Event) -> None:
    """The ultimate refresh function, aka F5."""
    widget = event.widget

    ciphername = X_ciphers.get()

    if widget is not X_ciphers:
        pass
    else:
        E_key.delete('0', tk.END)
        E_key['vcmd'] = namevcmd[ciphername]  # Update validate command

    message = tabs['message'].get('1.0', tk.END)[:-1]

    key = E_key.get()

    # Activate/deactivate encode/decode features
    if (not key) and ciphername:
        root.unbind(VEvent.ENCODE)
        root.unbind(VEvent.DECODE)
        M_file.entryconfigure(MENU_ITEM_INDEX_ENCODE, state=tk.DISABLED)
        M_file.entryconfigure(MENU_ITEM_INDEX_DECODE, state=tk.DISABLED)
        B_encode['state'] = tk.DISABLED
        B_decode['state'] = tk.DISABLED
    else:
        root.bind(VEvent.DECODE, decode)
        M_file.entryconfigure(MENU_ITEM_INDEX_DECODE, state=tk.NORMAL)
        B_decode['state'] = tk.NORMAL
        if message:
            root.bind(VEvent.ENCODE, encode)
            M_file.entryconfigure(MENU_ITEM_INDEX_ENCODE, state=tk.NORMAL)
            B_encode['state'] = tk.NORMAL
        else:
            root.unbind(VEvent.ENCODE)
            M_file.entryconfigure(MENU_ITEM_INDEX_ENCODE, state=tk.DISABLED)
            B_encode['state'] = tk.DISABLED

    bandlsb = {
        band: lsb
        for band, scl in enumerate(scales) if (lsb := int(scl.get())) != 0
    }

    if widget not in scales:
        pass
    else:
        if len(bandlsb) != 0:
            # LSB warning?
            widget['fg'] = Color.BLACK if (widget.get() < 4) else Color.RED
        # Fix LSB
        else:
            widget['fg'] = Color.BLACK
            widget.set(1)
            bandlsb = {scales.index(widget): 1}

    limit = ((Picture.pixel * sum(bandlsb.values())) // B) - len(DELIMITER)

    if len(message) > limit:
        # Delete excess message
        tabs['message'].delete('1.0', tk.END)
        tabs['message'].insert('1.0', message[:limit])

    used = len(tabs['message'].get('1.0', tk.END)[:-1])

    left = limit - used

    F_book['text'] = information.substitute(used=used, left=left, limit=limit)

    if event.char in ['']:
        pass
    else:
        if (widget is tabs['message']) or (left == 0):
            # Scroll such that the character at "INSERT" index is visible
            tabs['message'].see(tabs['message'].index(tk.INSERT))

    Glob.bandlsb = tuple(bandlsb.items())

    Glob.limit = limit


def schedule(ms: int) -> None:
    """Periodic file existence check."""
    output = Var_output.get()

    B_show['state'] = tk.NORMAL if os.path.exists(output) else tk.DISABLED

    root.after(ms, schedule, ms)


###################
# /!\ Logging /!\ #
###################
def exception(*msg) -> NoReturn:
    """Report callback exception."""
    if msg[0] is not KeyboardInterrupt:
        mb.showerror(message=''.join(traceback.format_exception(*msg)))
    os._exit(-1)


sys.excepthook = exception

#######################
# Windows OS Specific #
#######################
with suppress(AttributeError):
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('sten.3525')

################
# /|\ Root /|\ #
################
root = tk.Tk()

root.report_callback_exception = exception

root.pack_propagate(True)

root.wm_protocol('WM_DELETE_WINDOW', close)

root.wm_iconphoto(True, tk.PhotoImage(data=IMAGE_DATA_STEN))

root.wm_title('Sten')

SCREEN_W = root.winfo_screenwidth()
SCREEN_H = root.winfo_screenheight()

WINDOW_W = 1000
WINDOW_H = 550
WINDOW_W = SCREEN_W if (SCREEN_W < WINDOW_W) else WINDOW_W
WINDOW_H = SCREEN_H if (SCREEN_H < WINDOW_H) else WINDOW_H

CENTER_X = (SCREEN_W // 2) - (WINDOW_W // 2)
CENTER_Y = (SCREEN_H // 2) - (WINDOW_H // 2)

root.wm_resizable(True, True)

WINDOW_W_MIN = WINDOW_W // 2
WINDOW_H_MIN = WINDOW_H

root.wm_minsize(WINDOW_W_MIN, WINDOW_H_MIN)

geometry = string.Template('${w}x${h}-${x}-${y}')

GEOMETRY = geometry.substitute(w=WINDOW_W, h=WINDOW_H, x=CENTER_X, y=CENTER_Y)

root.wm_geometry(GEOMETRY)

font = Font(family='Consolas', size=9, weight='normal')

root.option_add('*Font', font)

style = ttk.Style()

style.configure('.', font=font)  # Ttk widgets only!

#################
# Configuration #
#################
jason = Json(FilePath.CONFIG)

cnf = collections.defaultdict(
    lambda: tk.BooleanVar(value=False),
    {str(k): tk.BooleanVar(value=bool(v)) for k, v in jason.load().items()}
)

########
# Menu #
########
menu = tk.Menu(root, tearoff=False)

root.configure(menu=menu)

##############
# Menu: File #
##############
M_file = tk.Menu(menu, tearoff=False)

menu.add_cascade(label='File', menu=M_file, state=tk.NORMAL, underline=0)

IMAGE_OPEN_FILE = tk.PhotoImage(data=IMAGE_DATA_OPEN_FILE)
IMAGE_SHOW_FILE = tk.PhotoImage(data=IMAGE_DATA_SHOW_FILE)
IMAGE_ENCODE = tk.PhotoImage(data=IMAGE_DATA_ENCODE)
IMAGE_DECODE = tk.PhotoImage(data=IMAGE_DATA_DECODE)
IMAGE_PREFERENCES = tk.PhotoImage(data=IMAGE_DATA_PREFERENCES)

root.event_add(VEvent.OPEN_FILE, *SEQUENCE_OPEN_FILE)
root.event_add(VEvent.ENCODE, *SEQUENCE_ENCODE)
root.event_add(VEvent.DECODE, *SEQUENCE_DECODE)
root.event_add(VEvent.PREFERENCES, *SEQUENCE_PREFERENCES)

M_file.add_command(
    accelerator=Hotkey.OPEN_FILE,
    command=lambda: root.event_generate(VEvent.OPEN_FILE),
    compound=tk.LEFT,
    image=IMAGE_OPEN_FILE,
    label='Open File',
    state=tk.NORMAL,
    underline=3,
)

root.bind(VEvent.OPEN_FILE, openasfile)
root.bind(VEvent.OPEN_FILE, activate, add='+')
root.bind(VEvent.OPEN_FILE, refresh, add='+')

M_file.add_separator()

M_file.add_command(
    accelerator=Hotkey.ENCODE,
    command=lambda: root.event_generate(VEvent.ENCODE),
    compound=tk.LEFT,
    image=IMAGE_ENCODE,
    label=(MENU_ITEM_INDEX_ENCODE := 'Encode'),
    state=tk.DISABLED,
    underline=0,
)

M_file.add_command(
    accelerator=Hotkey.DECODE,
    command=lambda: root.event_generate(VEvent.DECODE),
    compound=tk.LEFT,
    image=IMAGE_DECODE,
    label=(MENU_ITEM_INDEX_DECODE := 'Decode'),
    state=tk.DISABLED,
    underline=0,
)

M_file.add_separator()

M_file.add_command(
    accelerator=Hotkey.PREFERENCES,
    command=lambda: root.event_generate(VEvent.PREFERENCES),
    compound=tk.LEFT,
    image=IMAGE_PREFERENCES,
    label='Preferences',
    state=tk.NORMAL,
    underline=0,
)

root.bind(VEvent.PREFERENCES, preferences)

M_file.add_command(
    command=properties,
    label='Image Properties',
    state=tk.NORMAL,
    underline=7,
)

M_file.add_separator()

M_file.add_command(
    command=close,
    label='Exit',
    state=tk.NORMAL,
    underline=1,
)

##############
# Menu: Edit #
##############
M_edit = tk.Menu(menu, tearoff=False)

menu.add_cascade(label='Edit', menu=M_edit, state=tk.NORMAL, underline=0)

IMAGE_UNDO = tk.PhotoImage(data=IMAGE_DATA_UNDO)
IMAGE_REDO = tk.PhotoImage(data=IMAGE_DATA_REDO)
IMAGE_CUT = tk.PhotoImage(data=IMAGE_DATA_CUT)
IMAGE_COPY = tk.PhotoImage(data=IMAGE_DATA_COPY)
IMAGE_PASTE = tk.PhotoImage(data=IMAGE_DATA_PASTE)
IMAGE_SELECT_ALL = tk.PhotoImage(data=IMAGE_DATA_SELECT_ALL)

# Delete all defaults...
root.event_delete(VEvent.UNDO)
root.event_delete(VEvent.REDO)
root.event_delete(VEvent.CUT)
root.event_delete(VEvent.COPY)
root.event_delete(VEvent.PASTE)
root.event_delete(VEvent.SELECT_ALL)

# ...then add new ones
root.event_add(VEvent.UNDO, *SEQUENCE_UNDO)
root.event_add(VEvent.REDO, *SEQUENCE_REDO)
root.event_add(VEvent.CUT, *SEQUENCE_CUT)
root.event_add(VEvent.COPY, *SEQUENCE_COPY)
root.event_add(VEvent.PASTE, *SEQUENCE_PASTE)
root.event_add(VEvent.SELECT_ALL, *SEQUENCE_SELECT_ALL)

M_edit.add_command(
    accelerator=Hotkey.UNDO,
    command=lambda: manipulate(VEvent.UNDO),
    compound=tk.LEFT,
    image=IMAGE_UNDO,
    label=(MENU_ITEM_INDEX_UNDO := 'Undo'),
    state=tk.DISABLED,
    underline=0,
)

M_edit.add_command(
    accelerator=Hotkey.REDO,
    command=lambda: manipulate(VEvent.REDO),
    compound=tk.LEFT,
    image=IMAGE_REDO,
    label=(MENU_ITEM_INDEX_REDO := 'Redo'),
    state=tk.DISABLED,
    underline=0,
)

M_edit.add_separator()

M_edit.add_command(
    accelerator=Hotkey.CUT,
    command=lambda: manipulate(VEvent.CUT),
    compound=tk.LEFT,
    image=IMAGE_CUT,
    label=(MENU_ITEM_INDEX_CUT := 'Cut'),
    state=tk.DISABLED,
    underline=2,
)

M_edit.add_command(
    accelerator=Hotkey.COPY,
    command=lambda: manipulate(VEvent.COPY),
    compound=tk.LEFT,
    image=IMAGE_COPY,
    label=(MENU_ITEM_INDEX_COPY := 'Copy'),
    state=tk.DISABLED,
    underline=0,
)

M_edit.add_command(
    accelerator=Hotkey.PASTE,
    command=lambda: manipulate(VEvent.PASTE),
    compound=tk.LEFT,
    image=IMAGE_PASTE,
    label=(MENU_ITEM_INDEX_PASTE := 'Paste'),
    state=tk.DISABLED,
    underline=0,
)

M_edit.add_separator()

M_edit.add_command(
    accelerator=Hotkey.SELECT_ALL,
    command=lambda: manipulate(VEvent.SELECT_ALL),
    compound=tk.LEFT,
    image=IMAGE_SELECT_ALL,
    label=(MENU_ITEM_INDEX_SELECT_ALL := 'Select All'),
    state=tk.DISABLED,
    underline=7,
)

################
# Menu: Window #
################
M_window = tk.Menu(menu, tearoff=False)

menu.add_cascade(label='Window', menu=M_window, state=tk.NORMAL, underline=0)

IMAGE_RESET = tk.PhotoImage(data=IMAGE_DATA_RESET)

M_window.add_checkbutton(
    command=always,
    label='Always on Top',
    state=tk.NORMAL,
    underline=7,
)

M_window.add_checkbutton(
    command=transparent,
    label='Transparent',
    state=tk.NORMAL,
    underline=0,
)

M_window.add_separator()

M_window.add_command(
    command=lambda: root.wm_geometry(GEOMETRY),
    compound=tk.LEFT,
    image=IMAGE_RESET,
    label='Reset',
    state=tk.NORMAL,
    underline=0,
)

##############
# Menu: Help #
##############
M_help = tk.Menu(menu, tearoff=False)

menu.add_cascade(label='Help', menu=M_help, state=tk.NORMAL, underline=0)

IMAGE_WEB_SITE = tk.PhotoImage(data=IMAGE_DATA_WEB_SITE)
IMAGE_ABOUT = tk.PhotoImage(data=IMAGE_DATA_ABOUT)

M_help.add_command(
    command=check_for_updates,
    label='Check for Updates',
    state=tk.NORMAL,
    underline=10,
)

M_help.add_separator()

M_help.add_command(
    command=lambda: webbrowser.open(Url.WEBSITE, new=2),
    compound=tk.LEFT,
    image=IMAGE_WEB_SITE,
    label='Website',
    state=tk.NORMAL,
    underline=0,
)

M_help.add_command(
    command=lambda: mb.showinfo(message=__version__),
    compound=tk.LEFT,
    image=IMAGE_ABOUT,
    label='About',
    state=tk.NORMAL,
    underline=0,
)

#########
# Frame #
#########
frame = tk.Frame(
    root,
    bd=Bd.NONE,
    bg=Color.BLACK,
    relief=tk.FLAT,
)

frame.grid_propagate(True)

frame.grid_rowconfigure(index=0, weight=0)
frame.grid_rowconfigure(index=1, weight=0)
frame.grid_rowconfigure(index=2, weight=0)
frame.grid_rowconfigure(index=3, weight=1)
frame.grid_columnconfigure(index=0, weight=0)
frame.grid_columnconfigure(index=1, weight=1)

frame.pack_configure(
    expand=True, fill=tk.BOTH, side=tk.TOP
)

################
# Frame: Stego #
################
F_stego = tk.Frame(
    frame,
    bd=Bd.THIN,
    bg=Color.BLACK,
    relief=tk.RIDGE,
)

F_stego.pack_propagate(True)

F_stego.grid_configure(
    row=0, column=0, padx=PX, pady=PY, sticky=tk.NSEW
)

#################
# Encode Button #
#################
B_encode = tk.Button(
    F_stego,
    activebackground=Color.WHITE,
    anchor=tk.CENTER,
    bd=Bd.WIDE,
    bg=Color.WHITE,
    command=lambda: root.event_generate(VEvent.ENCODE),
    compound=tk.LEFT,
    fg=Color.BLACK,
    image=IMAGE_ENCODE,
    relief=tk.FLAT,
    state=tk.DISABLED,
    takefocus=True,
    text='Encode',
)

B_encode.pack_configure(
    expand=True, fill=tk.BOTH, padx=PX, pady=PY, side=tk.LEFT
)

#################
# Decode Button #
#################
B_decode = tk.Button(
    F_stego,
    activebackground=Color.WHITE,
    anchor=tk.CENTER,
    bd=Bd.WIDE,
    bg=Color.WHITE,
    command=lambda: root.event_generate(VEvent.DECODE),
    compound=tk.LEFT,
    fg=Color.BLACK,
    image=IMAGE_DECODE,
    relief=tk.FLAT,
    state=tk.DISABLED,
    takefocus=True,
    text='Decode',
)

B_decode.pack_configure(
    expand=True, fill=tk.BOTH, padx=PX, pady=PY, side=tk.LEFT
)

###############
# Frame: Info #
###############
F_info = tk.Frame(
    frame,
    bd=Bd.THIN,
    bg=Color.BLACK,
    relief=tk.RIDGE,
)

F_info.grid_propagate(True)

F_info.grid_rowconfigure(index=0, weight=1)
F_info.grid_rowconfigure(index=1, weight=1)
F_info.grid_columnconfigure(index=0, weight=0)
F_info.grid_columnconfigure(index=1, weight=1)
F_info.grid_columnconfigure(index=2, weight=0)

F_info.grid_configure(
    row=0, column=1, padx=PX, pady=PY, sticky=tk.NSEW
)

#######################
# Opened File Section #
#######################
tk.Label(
    F_info,
    anchor=tk.CENTER,
    bd=Bd.NONE,
    bg=Color.BLACK,
    fg=Color.WHITE,
    relief=tk.FLAT,
    state=tk.NORMAL,
    takefocus=False,
    text='Opened',
).grid_configure(row=0, column=0, padx=PX, pady=PY, sticky=tk.NSEW)

tk.Entry(
    F_info,
    bd=Bd.NONE,
    fg=Color.BLACK,
    readonlybackground=Color.BUTTON,
    relief=tk.FLAT,
    state='readonly',
    takefocus=False,
    textvariable=(Var_opened := tk.StringVar()),
).grid_configure(row=0, column=1, ipady=IY, padx=PX, pady=PY, sticky=tk.NSEW)

B_open = tk.Button(
    F_info,
    activebackground=Color.WHITE,
    anchor=tk.CENTER,
    bd=Bd.WIDE,
    bg=Color.WHITE,
    command=lambda: root.event_generate(VEvent.OPEN_FILE),
    compound=tk.LEFT,
    fg=Color.BLACK,
    image=IMAGE_OPEN_FILE,
    relief=tk.FLAT,
    state=tk.NORMAL,
    takefocus=True,
)

B_open.grid_configure(
    row=0, column=2, ipadx=IX, padx=PX, pady=PY, sticky=tk.NSEW
)

#######################
# Output File Section #
#######################
tk.Label(
    F_info,
    anchor=tk.CENTER,
    bd=Bd.NONE,
    bg=Color.BLACK,
    fg=Color.WHITE,
    relief=tk.FLAT,
    state=tk.NORMAL,
    takefocus=False,
    text='Output',
).grid_configure(row=1, column=0, padx=PX, pady=PY, sticky=tk.NSEW)

tk.Entry(
    F_info,
    bd=Bd.NONE,
    fg=Color.BLACK,
    readonlybackground=Color.BUTTON,
    relief=tk.FLAT,
    state='readonly',
    takefocus=False,
    textvariable=(Var_output := tk.StringVar()),
).grid_configure(row=1, column=1, ipady=IY, padx=PX, pady=PY, sticky=tk.NSEW)

B_show = tk.Button(
    F_info,
    activebackground=Color.WHITE,
    anchor=tk.CENTER,
    bd=Bd.WIDE,
    bg=Color.WHITE,
    command=showfile,
    compound=tk.LEFT,
    fg=Color.BLACK,
    image=IMAGE_SHOW_FILE,
    relief=tk.FLAT,
    state=tk.DISABLED,
    takefocus=True,
)

B_show.grid_configure(
    row=1, column=2, ipadx=IX, padx=PX, pady=PY, sticky=tk.NSEW
)

###############
# Frame: PRNG #
###############
F_prng = tk.LabelFrame(
    frame,
    bd=Bd.THIN,
    bg=Color.BLACK,
    fg=Color.WHITE,
    labelanchor=tk.S,
    relief=tk.RIDGE,
    text='PRNG',
)

F_prng.pack_propagate(True)

F_prng.grid_configure(
    row=1, column=0, padx=PX, pady=PY, sticky=tk.NSEW
)

###################
# PRNG Seed Entry #
###################
E_prng = tk.Entry(
    F_prng,
    bd=Bd.NONE,
    bg=Color.WHITE,
    disabledbackground=Color.BUTTON,
    fg=Color.BLACK,
    relief=tk.FLAT,
    show=ENTRY_SHOW_CHAR,
    state=tk.DISABLED,
    takefocus=True,
)

E_prng.bind(VEvent.PASTE, lambda e: 'break')

E_prng.pack_configure(
    expand=True, fill=tk.BOTH, ipady=IY, padx=PX, pady=PY, side=tk.TOP
)

#################
# Frame: Crypto #
#################
F_crypto = tk.LabelFrame(
    frame,
    bd=Bd.THIN,
    bg=Color.BLACK,
    fg=Color.WHITE,
    labelanchor=tk.S,
    relief=tk.RIDGE,
    text='Encryption',
)

F_crypto.pack_propagate(True)

F_crypto.grid_configure(
    row=2, column=0, padx=PX, pady=PY, sticky=tk.NSEW
)

####################
# Ciphers Combobox #
####################
X_ciphers = ttk.Combobox(
    F_crypto,
    background=Color.WHITE,
    foreground=Color.BLACK,
    state=tk.DISABLED,
    takefocus=True,
    values=tuple(ciphers),
)

X_ciphers.current(1)

X_ciphers.pack_configure(
    expand=True, fill=tk.BOTH, ipady=IY, padx=PX, pady=PY, side=tk.TOP
)

####################
# Cipher Key Entry #
####################
namevcmd = {
    name: (root.register(cipher.validate), *cipher.code)
    for name, cipher in ciphers.items()
}

E_key = tk.Entry(
    F_crypto,
    bd=Bd.NONE,
    bg=Color.WHITE,
    disabledbackground=Color.BUTTON,
    fg=Color.BLACK,
    relief=tk.FLAT,
    show=ENTRY_SHOW_CHAR,
    state=tk.DISABLED,
    takefocus=True,
    validate='key',
    vcmd=namevcmd[X_ciphers.get()],
)

E_key.bind(VEvent.PASTE, lambda e: 'break')

E_key.pack_configure(
    expand=True, fill=tk.BOTH, ipady=IY, padx=PX, pady=PY, side=tk.TOP
)

##############
# Frame: LSB #
##############
F_lsb = tk.LabelFrame(
    frame,
    bd=Bd.THIN,
    bg=Color.BLACK,
    fg=Color.WHITE,
    labelanchor=tk.S,
    relief=tk.RIDGE,
    text='LSB',
)

F_lsb.pack_propagate(True)

F_lsb.grid_configure(
    row=3, column=0, padx=PX, pady=PY, sticky=tk.NSEW
)

##############
# LSB Scales #
##############
scales = [
    tk.Scale(F_lsb, fg=Color.BLACK, from_=B, to=0, troughcolor=color)
    for color in (Color.RED, Color.GREEN, Color.BLUE)
]

possibilities = [
    tuple(compress(enumerate(t), t)) for t in product(range(B + 1), repeat=RGB)
]

for scale in scales:
    scale.set(1)  # Do not change the position of this line!
    scale.configure(
        bd=Bd.THIN,
        relief=tk.FLAT,
        sliderlength=50,
        sliderrelief=tk.RAISED,
        state=tk.DISABLED,
        takefocus=True,
    )
    scale.pack_configure(
        expand=True, fill=tk.BOTH, padx=PX, pady=PY, side=tk.LEFT
    )

###################
# Frame: Notebook #
###################
mapping = {'used': 0, 'left': 0, 'limit': 0}

information = string.Template('${used}+${left}=${limit}')

F_book = tk.LabelFrame(
    frame,
    bd=Bd.THIN,
    bg=Color.BLACK,
    fg=Color.WHITE,
    labelanchor=tk.SE,
    relief=tk.RIDGE,
    text=information.substitute(mapping),
)

F_book.pack_propagate(True)

F_book.grid_configure(
    row=1, column=1, rowspan=3, padx=PX, pady=PY, sticky=tk.NSEW
)

##################
# Stego Notebook #
##################
tabs = {}

N_stego = ttk.Notebook(
    F_book,
    takefocus=True,
)

N_stego.pack_configure(
    expand=True, fill=tk.BOTH, padx=PX, pady=PY, side=tk.TOP
)

for title in ['message', 'decoded']:
    tab = ScrolledText(
        N_stego,
        bd=Bd.NONE,
        bg=Color.BUTTON,
        fg=Color.BLACK,
        relief=tk.FLAT,
        state=tk.DISABLED,
        tabs=1,
        takefocus=False,
        undo=True,
        wrap='char',
    )
    tab.pack_configure(
        expand=True, fill=tk.BOTH, padx=PX, pady=PY, side=tk.TOP
    )
    N_stego.add(
        tab,
        state=tk.DISABLED,
        sticky=tk.NSEW,
        text=title.capitalize(),
    )
    tabs.update({title: tab})


def start() -> None:
    """Start the program."""
    root.mainloop()


def main() -> None:
    """Entry point."""
    warnings.simplefilter('error', Image.DecompressionBombWarning)

    schedule(250)

    start()


if __name__ == '__main__':
    main()
