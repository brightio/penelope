# penelope

Penelope is an advanced shell handler. Its main aim is to replace netcat as shell catcher during exploiting RCE vulnerabilities.
It works on Linux and macOS and the only requirement is Python >= 3.6. It is a single script, it needs no installation or any 3rd party dependency and hopefully it will stay that way.

Among the main features are:
- Auto-upgrade shells to PTY (auto-resize included)
- Logging interaction with the targets
- Download files from targets
- Upload files to targets
- Upload preset scripts to targets
- Spawn shells on multiple tabs and/or hosts
- Maintain X amount of active shells per host no matter what
- Multiple sessions
- Multiple listeners
- Can be imported by python3 exploits and get shell on the same terminal (see [Extras](#Extras))

Penelope can work in conjunction with metasploit exploits by disabling the default handler with `set DisablePayloadHandler True`

It supports Windows shells but autoupgrade is not implemented yet. However it can accept PTY shells from the excellent project [ConPtyShell](https://github.com/antonioCoco/ConPtyShell) of [@antonioCoco](https://github.com/antonioCoco). Autoresize of PTY is implemented.

## Usage
### Sample Typical Usage
```
./penelope.py                   # Listening for reverse shells on 0.0.0.0:4444
./penelope.py 5555              # Listening for reverse shells on 0.0.0.0:5555
./penelope.py 5555 -i eth0      # Listening for reverse shells on eth0:5555
./penelope.py -c target 3333    # Connect to a bind shell on target:3333
```

### Demonstrating Random Usage

As shown in the below video, within only a few seconds we have easily:
1. A fully functional auto-resizable PTY shell
2. One more such shell in another tab
3. Logging every interaction with the target
4. Uploaded the latest versions of LinPEAS and linux-smart-enumeration
5. Downloaded the whole /etc directory
6. For every shell that may be killed for some reason, automatically a new one is spawned. This gives us a kind of persistence with the target

https://user-images.githubusercontent.com/65655412/151394465-9eb4937d-bfad-45df-b058-3b74164be517.mp4

### Penelope Main Menu Commands
Some Notes:
- *By default you need to press F12 to detach the PTY shell and go to the Main Menu. If the upgrade was not possible the you ended up with a basic shell, you can detach it with Ctrl+C. This also prevents the accidental killing of the shell.*
- *The menu supports TAB completion and also short commands. For example instead of "interact 1" you can just type "i 1".*
- *The batch command by default uploads predefined privilege escalation scripts. You can modify this behaviour by using a configuration file (See extras/penelope.conf). This file can be speficied with -r in the command line or be placed in ~/.penelope/penelope.conf*

![help](https://user-images.githubusercontent.com/65655412/150849045-110d4bf6-a86d-4b77-a290-075abeee62d4.png)

### Command Line Options
```
positional arguments:
  ports                 Ports to listen/connect to, depending on -i/-c options. Default: 4444

Reverse or Bind shell?:
  -i , --interface      Interface or IP address to listen on. Default: 0.0.0.0
  -c , --connect        Bind shell Host

Hints:
  -a, --hints           Show sample payloads for reverse shell based on the registered Listeners
  -l, --interfaces      Show the available network interfaces
  -h, --help            show this help message and exit

Verbosity:
  -Q, --silent          Be a bit less verbose
  -d, --debug           Show debug messages

Logging:
  -L, --no-log          Do not create session log files
  -T, --no-timestamps   Do not include timestamps on logs

Misc:
  -r , --configfile     Configuration file location
  -m , --maintain       Maintain NUM total shells per target
  -H, --no-history      Disable shell history on target
  -P, --plain           Just land to the main menu
  -S, --single-session  Accommodate only the first created session
  -C, --no-attach       Disable auto attaching sessions upon creation
  -U, --no-upgrade      Do not upgrade shells

Debug:
  -NP, --no-python      Simulate python absence on target
  -NB, --no-bash        Simulate bash absence on target
  -v, --version         Show Penelope version
```

## Extras
There are also included two sample exploit simulation scripts in the extras folder to demonstrate how penelope can be imported and get shell on the same terminal. The illustration below shows how Penelope is imported in a python3 exploit for the Quick machine of Hack The Box.

![exploit](https://user-images.githubusercontent.com/65655412/151350244-3d0b4e60-04a6-494b-8eab-2498cfb8b809.gif)

Furthermore, one bash script is included which automatically upgrades Unix shells to PTY using the xdotool.

![tty](https://user-images.githubusercontent.com/65655412/151353020-8585e352-2037-41f1-94d6-4fd7d1cb7943.gif)

## Contribution
If you want to contribute to this project please report bugs, unexpected program behaviours and/or new ideas.

## TODO

### Features
* ability to execute a local script on target and get the output on a local file
* remote and local port forwarding
* persistence
* edit command: open the remote file locally, make changes and upon saving, upload it to the target
* currently download/upload/spawn/upgrade commands are supported only on Unix shells. Will implement those commands for Windows shells too.
* spawn meterpreter sessions
* an option switch for disable all logging, not only sessions.
* main menu autocompletion for short commands
* download/upload progress bar
* download/upload autocompletion
* IPv6
* encryption
* UDP support

### Known Issues
* Ctrl-C on main menu has not the expected behavior yet. However can still stop commands like 'download'.
* Session logging: when executing commands on the target that feature alternate buffers like nano and they are abnormally terminated, then when 'catting' the logfile it seems corrupted. However the data are still there. Also for example when resetting the remote terminal, these escape sequences are reflected in the logs. I will need to filter specific escape sequences so as to ensure that when 'catting' the logfile, a smooth log is presented.

### Limitations
* For the emojis to be shown correctly, the fonts-noto-color-emoji package should be installed. It is installed by default on many distros but not on parrot OS. May consider removing emojis altogether.
* When downloading files via the download menu command, clickable links with the downloaded files are presented. However the links are not clickable on the qterminal (Kali Linux).
* penelope menu commands and PTY autoresize operate on the same socket. This could be an advantage but it has a side effect that for example if nano is open on target, then detaching the session and attempt a download, penelope copes with that by sending Ctrl-Z -> Ctrl-E -> Ctrl-U. Then must run fg to get the process back. Maybe consider to spawn extra socket for controling the session in the future. However, if before executing a menu command, the target's terminal if left on a clear state, then there is no problem.

## Thanks to
* [Cristian Grigoriu - @crgr](https://github.com/crgr) for inspiring me to automate the PTY upgrade process. This is how this project was born.
* [Paul Taylor - @bao7uo](https://github.com/bao7uo) for advising me that penelope should not be shipped without the ability to connect to a bind shell.
* [Longlone - @WAY29](https://github.com/WAY29) for indicating the need for compatibility with previous versions of Python (3.6)
* [Carlos Polop - @carlospolop](https://github.com/carlospolop) for the idea to spawn shells on listeners on fellow systems
