# penelope
Penelope is a shell handler designed to be easy to use and intended to replace netcat when exploiting RCE vulnerabilities. It is compatible with Linux and macOS and requires Python 3.6 or higher. It is a standalone script that does not require any installation or external dependencies, and it is intended to remain this way.

Among the main features are:
- Auto-upgrade shells to PTY (realtime resize included)
- Logging interaction with the targets
- Download files/folders from targets
- Upload local/remote files/folders to targets
- Run scripts on targets and get output on a local file in real time.
- Spawn shells on multiple tabs and/or hosts
- Maintain X amount of active shells per host no matter what
- Multiple sessions
- Multiple listeners
- Can be imported by python3 exploits and get shell on the same terminal (see [Extras](#Extras))

Penelope can work in conjunction with metasploit exploits by disabling the default handler with `set DisablePayloadHandler True`

Currently only Unix shells are fully supported. There is only basic support for Windows shells (netcat-like interaction + logging) and the rest of the features are under way.

## Usage
### Sample Typical Usage
```
./penelope.py                   # Listening for reverse shells on 0.0.0.0:4444
./penelope.py -a                # Listening for reverse shells on 0.0.0.0:4444 and show reverse shell payloads based on the current Listeners
./penelope.py 5555              # Listening for reverse shells on 0.0.0.0:5555
./penelope.py 5555 -i eth0      # Listening for reverse shells on eth0:5555
./penelope.py 1111 2222 3333    # Listening for reverse shells on 0.0.0.0:1111, 0.0.0.0:2222, 0.0.0.0:3333
./penelope.py -c target 3333    # Connect to a bind shell on target:3333
```

### Demonstrating Random Usage

As shown in the below video, within only a few seconds we have easily:
1. A fully functional auto-resizable PTY shell while logging every interaction with the target
2. Execute the lastest version of Linpeas on the target without touching the disk and get the output on a local file in realtime 
3. One more PTY shell in another tab
4. Uploaded the latest versions of LinPEAS and linux-smart-enumeration
5. Uploaded a local folder with custom scripts
6. Uploaded an exploit-db exploit directly from URL
7. Downloaded and opened locally a remote file
8. Downloaded the remote /etc directory
9. For every shell that may be killed for some reason, automatically a new one is spawned. This gives us a kind of persistence with the target

https://user-images.githubusercontent.com/65655412/208298446-fe2f11f6-d8bc-4e85-9f19-94e66593102b.mp4

### Main Menu Commands
Some Notes:
- By default you need to press `F12` to detach the PTY shell and go to the Main Menu. If the upgrade was not possible the you ended up with a basic shell, you can detach it with `Ctrl+C`. This also prevents the accidental killing of the shell.
- The Main Menu supports TAB completion and also short commands. For example instead of `interact 1` you can just type `i 1`.
- You can add more scripts and modify default behaviours by using a configuration file (See extras/penelope.conf). This file can be speficied with -r in the command line or can be placed in ~/.penelope/penelope.conf

![Main Menu](https://user-images.githubusercontent.com/65655412/196921489-5d446ff2-1fe9-4789-b6af-11a8ddf81fe7.png)

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

Session Logging:
  -L, --no-log          Do not create session log files
  -T, --no-timestamps   Do not include timestamps in session logs

Misc:
  -r , --configfile     Configuration file location
  -m , --maintain       Maintain NUM total shells per target
  -H, --no-history      Disable shell history on target
  -P, --plain           Just land to the main menu
  -S, --single-session  Accommodate only the first created session
  -C, --no-attach       Disable auto attaching sessions upon creation
  -U, --no-upgrade      Do not upgrade shells

Debug:
  -N , --no-bins        Simulate binary absence on target (comma separated list)
  -v, --version         Show Penelope version

```

## Extras
There are also included two sample exploit simulation scripts in the extras folder to demonstrate how penelope can be imported and get shell on the same terminal. The illustration below shows how Penelope is imported in a python3 exploit for the Quick machine of Hack The Box.

![exploit](https://user-images.githubusercontent.com/65655412/151350244-3d0b4e60-04a6-494b-8eab-2498cfb8b809.gif)

Furthermore, a bash script is included which automatically upgrades Unix shells to PTY using the xdotool.

![tty](https://user-images.githubusercontent.com/65655412/151353020-8585e352-2037-41f1-94d6-4fd7d1cb7943.gif)


## Contribution
If you want to contribute to this project please report bugs, unexpected program behaviours and/or new ideas.

## TODO

### Features
* remote and local port forwarding
* socks & http proxy
* persistence modules
* edit command: open the remote file locally, make changes and upon saving, upload it to the target
* currently download/upload/spawn/upgrade commands are supported only on Unix shells. Will implement those commands for Windows shells too.
* spawn meterpreter sessions
* an option switch for disable all logging, not only sessions.
* main menu autocompletion for short commands
* download/upload autocompletion
* IPv6 support
* encryption
* UDP support

### Known Issues
* Main menu: Ctrl-C on main menu has not the expected behavior yet.
* Session logging: when executing commands on the target that feature alternate buffers like nano and they are abnormally terminated, then when 'catting' the logfile it seems corrupted. However the data are still there. Also for example when resetting the remote terminal, these escape sequences are reflected in the logs. I will need to filter specific escape sequences so as to ensure that when 'catting' the logfile, a smooth log is presented.

### Limitations
* For the emojis to be shown correctly, the fonts-noto-color-emoji package should be installed. It is installed by default on many distros but not on parrot OS. May consider removing emojis altogether.
* When downloading files via the download menu command, clickable links with the downloaded files are presented. However the links are not clickable on the qterminal (Kali Linux).

## Trivia
Penelope was the wife of Odysseus and she is known for her fidelity for him by waiting years. Since a characteristic of reverse shell handlers is waiting, this tool is named after her.

## Thanks to
* [Cristian Grigoriu - @crgr](https://github.com/crgr) for inspiring me to automate the PTY upgrade process. This is how this project was born.
* [Paul Taylor - @bao7uo](https://github.com/bao7uo) for the idea to support bind shells.
* [Longlone - @WAY29](https://github.com/WAY29) for indicating the need for compatibility with previous versions of Python (3.6).
* [Carlos Polop - @carlospolop](https://github.com/carlospolop) for the idea to spawn shells on listeners on other systems.
* [@darrenmartyn](https://github.com/darrenmartyn) for indicating an alternative method to upgrade the shell to PTY using the script command.
* [@robertstrom](https://github.com/robertstrom) and [@RamadhanAmizudin](https://github.com/RamadhanAmizudin) for bug reporting.
