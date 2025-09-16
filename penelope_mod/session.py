import os
import io
import re
import sys
import tty
import ssl
import time
import shlex
import queue
import struct
import shutil
import socket
import signal
import base64
import termios
import tarfile
import logging
import zipfile
import threading
import socketserver
from math import ceil
from glob import glob
from code import interact
from zlib import compress
from errno import EADDRINUSE, EADDRNOTAVAIL
from select import select
from pathlib import Path, PureWindowsPath
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from datetime import datetime
from textwrap import indent, dedent
from binascii import Error as binascii_error
from functools import wraps
from collections import deque, defaultdict
from http.server import SimpleHTTPRequestHandler
from urllib.parse import unquote
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Modular imports
from penelope_mod.context import ctx
from penelope_mod.io import stdout, ask
from penelope_mod.ui import paint, PBar, Size
from penelope_mod.messaging import Messenger, Stream
from penelope_mod.system import Open
from penelope_mod.constants import URLS
from penelope_mod.fileserver import FileServer
from penelope_mod.core import TCPListener, Connect, handle_bind_errors
from penelope_mod.menu import MainMenu

# Helpers imported from main context
readline = ctx.readline
options = ctx.options
logger = ctx.logger
menu = ctx.menu
core = ctx.core

# NOTE: The large Session class below remains mostly unchanged, but uses ctx.*
# for globals and imports helpers from penelope_mod.* modules.

class ControlQueue:
    def __init__(self):
        self._out, self._in = os.pipe()
        self.queue = queue.Queue()
    def fileno(self):
        return self._out
    def __lshift__(self, command):
        self.queue.put(command)
        os.write(self._in, b'\x00')
    def get(self):
        os.read(self._out, 1)
        return self.queue.get()
    def clear(self):
        amount = 0
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
                amount += 1
            except queue.Empty:
                break
        os.read(self._out, amount)
    def close(self):
        os.close(self._in)
        os.close(self._out)

class Channel:
    def __init__(self, raw=False, expect=[]):
        self._read, self._write = os.pipe()
        self.can_use = True
        self.active = True
        self.allow_receive_shell_data = True
        self.control = ControlQueue()
    def fileno(self):
        return self._read
    def read(self):
        return os.read(self._read, options.network_buffer_size)
    def write(self, data):
        os.write(self._write, data)
    def close(self):
        os.close(self._read)
        os.close(self._write)

# We import the original Session class from penelope and re-export it here for now.
# Full migration is non-trivial because of numerous cross-references; this wrapper
# keeps the external API stable while the codebase has already been modularized.
from importlib import import_module as _im
Session = getattr(_im('penelope'), 'Session')

