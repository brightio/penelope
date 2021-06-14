# penelope

Penelope is an advanced shell handler. Its main aim is to replace netcat as shell catcher during exploiting RCE vulnerabilities.
It works on Linux and macOS and the only requirement is Python3. It is one script without 3rd party dependencies and hopefully it will stay that way.

Among the main features are:
- Auto-upgrade shells to PTY (auto-resize included)
- Logging interaction with the targets
- Download files from targets
- Upload files to targets
- Upload preset scripts to targets
- Spawn backup shells
- Multiple sessions
- Multiple listeners
- Can be imported by exploits and get shell on the same terminal (see [extras](#extras))

Penelope can work in conjunction with metasploit exploits by disabling the default handler with `set DisablePayloadHandler True`  
  
It supports Windows shells but autoupgrade is not implemented yet. However it can accept PTY shells from the excellent project [ConPtyShell](https://github.com/antonioCoco/ConPtyShell) of [@antonioCoco](https://github.com/antonioCoco). Autoresize of PTY is implemented.
## Sample basic usage
```
penelope.py                   # Listening for reverse shells on 0.0.0.0:4444
penelope.py 5555              # Listening for reverse shells on 0.0.0.0:5555
penelope.py 5555 -i eth0      # Listening for reverse shells on eth0:5555

penelope.py -c target 3333    # Connect to a bind shell on target:3333
```
### Demonstrating random usage (1)

1. Executing penelope without parameters and getting a reverse shell
2. Pressing F12 to detach the session and go to the main menu
3. Run 'recon' command to upload preset privesc scripts to the target
4. Interacting again with the session, confirming that scripts are uploaded
5. Detaching again with F12 and downloading /etc directory from the target
6. Kill the session and exiting with Ctrl-D

![sample_usage](https://user-images.githubusercontent.com/65655412/120901583-35ed1780-c63c-11eb-845d-690bb3bbf112.png)

### Demonstrating random usage (2)

1. Adding an extra listener and show all listeners
2. Interacting with session 1
3. Spawning 2 extra backup sessions
4. Showing all sessions

![sample_usage2](https://user-images.githubusercontent.com/65655412/120902895-2d4c0f80-c643-11eb-9d3a-ebcce5814566.png)


## Command line options
```
positional arguments:
  PORT                  Port to listen/connect to depending on -i/-c options. Default: 4444

Reverse or Bind shell?:
  -i , --address        IP Address or Interface to listen on. Default: 0.0.0.0
  -c , --connect        Bind shell Host

Hints:
  -a, --hints           Show sample payloads for reverse shell based on the registered listeners
  -l, --interfaces      Show the available network interfaces
  -h, --help            show this help message and exit

Verbosity:
  -Q, --silent          Show only errors and warnings
  -X, --extra-silent    Suppress all logging messages

Logging:
  -L, --no-log          Do not create session log files
  -T, --no-timestamps   Do not include timestamps on logs

Misc:
  -H, --no-history      Disable shell history on target
  -P, --plain           Just land to the menu
  -S, --single-session  Accommodate only the first created session
  -C, --no-attach       Disable auto attaching sessions upon creation
  -U, --no-upgrade      Do not upgrade shells

Debug:
  -d, --debug           Show debug messages
  -NP, --no-python      Simulate python absence on target
  -NB, --no-bash        Simulate bash absence on target
```

## Menu options
```
use [sessionID|none]
  Select a session

sessions [sessionID]
  Show active sessions. When followed by <sessionID>, interact with that
  session

interact [sessionID]
  Interact with a session

kill [sessionID|all]
  Kill a session

download <glob>...
  Download files and folders from the target

open <glob>...
  Download files and folders from the target and open them locally

upload <glob|URL>...
  Upload files and folders to the target. If URL is specified then it is
  downloaded locally and then uploaded to the target

recon [sessionID]
  Upload preset reconnaissance scripts to the target

spawn [sessionID]
  Spawn a new session. Whether it will be reverse or bind, depends on
  the current session.

upgrade [sessionID]
  Upgrade the session's shell to "PTY". If it fails attempts to upgrade
  it to "Advanced". If this fail too, then falls back to "Basic" shell.

dir|. [sessionID]
  Open the session's local folder. If no session is selected, opens the
  base folder.

listeners [<add|stop> <Interface|IP> <Port>]
  Add or stop a Listener. When invoked without parameters, it shows the
  active Listeners.

connect <Host> <Port>
  Connect to a bind shell

hints
  Show sample commands to run on the targets to get reverse shell, based
  on the registered listeners

reset
  Reset the local terminal

history
  Show menu history

help [command]
  Show menu help or help about specific command

DEBUG
  Open debug console

SET [<param> <value>]
  Set options. When invoked without parameters it shows current options

exit|quit|q|Ctrl+D
  Exit penelope
```

## Extras

There are also included two sample exploit simulation scripts to demonstrate how penelope can be imported and get shell on the same terminal. Furthermore, one bash script is included that automatically upgrades Unix shells to PTY using xdotool.

## TODO

### Features
* currently download/upload/spawn/upgrade commands are supported only on Unix shells. Will implement those commands for Windows shells too.
* port forwarding
* persistence
* edit command: open the remote file locally, make changes and upon saving, upload it to target
* ability to specify a list of commands to run automatically on target and/or the main menu
* an option switch for disable all logging, not only sessions.
* execute a local script on target and get the output on a local file
* main menu autocompletion for short commands
* download/upload progress bar
* download/upload autocompletion
* IPv6
* encryption
* UDP
### Bugs
* Ctrl-C on main menu has not the expected behaviour yet. However can still stop commands like 'download'.
* Session logging: when executing commands with alternate buffers like nano on target, then when cat the log it seems corrupted. However the data are still there.
### Misc
* apply some PEP8
* consider autorunning bash -l on new shells
* better way to handle duplicate downloads
### Limitations
* emojis don't appear on mate-terminal (parrot OS)
* download command: path links are not clickable on qterminal (Kali Linux)
* penelope menu commands and PTY autoresize operate on the same socket. This could be an advantage but it has a side effect that for example if nano is open on target, then detaching the session and attempt a download, penelope copes with that by sending Ctrl-Z -> Ctrl-E -> Ctrl-U. Then must run fg to get the process back. Maybe consider to spawn extra socket for controling the session in the future. However, if before executing a menu command, the target's terminal if left on a clear state, then there is no problem.
### Thanks to
* [Cristian Grigoriu - @crgr](https://github.com/crgr) for inspiring me to automate the PTY upgrade process. This is how this project was born.
* [Paul Taylor - @bao7uo](https://github.com/bao7uo) for advising me that penelope should not be shipped without the ability to connect to a bind shell.
