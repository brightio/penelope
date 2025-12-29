<div align="center">
  <img src="https://github.com/user-attachments/assets/0d369fba-480e-4e27-a117-8845dbd4b58e" alt="Logo" width="200"/>
</div>

<img src="https://img.shields.io/badge/Version-0.15.0-blueviolet"/><br>
![BlackHat Arsenal](https://img.shields.io/badge/BlackHat-Arsenal-black)
![EU](https://img.shields.io/badge/EU%202024-blue)
![USA](https://img.shields.io/badge/USA%202025-red)
![MEA](https://img.shields.io/badge/MEA%202025-green)

Penelope is a powerful shell handler built as a modern netcat replacement for RCE exploitation, aiming to simplify, accelerate, and optimize post-exploitation workflows.

## Table of Contents
- 📥 [Install](#install)
- ⚙️ [Features](#features)
  - 🖥️ [Session Features](#session-features)
  - 🌍 [Global Features](#global-features)
  - 🧩 [Modules](#modules)
- 💻 [Usage](#usage)
  - ▶️ [Sample Typical Usage](#sample-typical-usage)
  - 🎬 [Demonstrating Random Usage](#demonstrating-random-usage)
  - 🖲️ [Main Menu Commands](#main-menu-commands)
  - ⚡ [Command Line Options](#command-line-options)
- 📝 [TODO](#todo)
- ❓ [FAQ](#faq)
- 🙌 [Thanks to the early birds](#thanks-to-the-early-birds)

## Install

Penelope can be run on all Unix-based systems (Linux, macOS, FreeBSD etc) and requires **Python 3.6+**

It requires no installation as it uses only Python’s standard library - just download and execute the script:
```bash
wget https://raw.githubusercontent.com/brightio/penelope/refs/heads/main/penelope.py && python3 penelope.py
```
For a more streamlined setup, it can be installed using pipx:
```bash
pipx install git+https://github.com/brightio/penelope
```
## Features
### Session Features
|Description|Unix with Python>=2.3| Unix without Python>=2.3|Windows|
|-----------|:-------------------:|:-----------------------:|:-----:|
|Auto-upgrade shell|PTY|PTY(*)|readline|
|Real-time terminal resize|✅|✅|❌|
|Logging shell activity|✅|✅|✅|
|Download remote files/folders|✅|✅|✅|
|Upload local/HTTP files/folders|✅|✅|✅|
|In-memory local/HTTP script execution with real-time output downloading|✅|❌|❌|
|Local port forwarding|✅|❌|❌|
|Spawn shells on multiple tabs and/or hosts|✅|✅|❌|
|Maintain X amount of active shells per host no matter what|✅|✅|❌|

(*) opens a second TCP connection

### Global Features
- Streamline interaction with the targets via modules
- Multiple sessions
- Multiple listeners
- Serve files/folders via HTTP (-s switch)
- Can be imported by python3 exploits and get shell on the same terminal (see [extras](https://github.com/brightio/penelope/tree/main/extras))
- Can work in conjunction with metasploit exploits by disabling the default handler with `set DisablePayloadHandler True`

### Modules

<img width="2341" height="946" alt="image" src="https://github.com/user-attachments/assets/c3779ca1-d2b3-49b5-b853-544a71e71611" />

#### Meterpreter module demonstration

![meterpreter](https://github.com/user-attachments/assets/b9cda69c-e25c-41e1-abe2-ce18ba13c4ed)

## Usage
### Sample Typical Usage
```
penelope                          # Listening for reverse shells on 0.0.0.0:4444
penelope -p 5555                  # Listening for reverse shells on 0.0.0.0:5555
penelope -p 4444,5555             # Listening for reverse shells on 0.0.0.0:4444 and 0.0.0.0:5555
penelope -i eth0 -p 5555          # Listening for reverse shells on eth0:5555
penelope -a                       # Listening for reverse shells on 0.0.0.0:4444 and show sample reverse shell payloads

penelope -c target -p 3333        # Connect to a bind shell on target:3333

penelope ssh user@target          # Get a reverse shell from target on local port 4444
penelope -p 5555 ssh user@target  # Get a reverse shell from target on local port 5555
penelope -i eth0 -p 5555 -- ssh -l user -p 2222 target  # Get a reverse shell from target on eth0, local port 5555 (use -- if ssh needs switches)

penelope -s <File/Folder>         # Share a file or folder via HTTP
```
![Penelope](https://github.com/user-attachments/assets/b8e5cd84-60a5-4d79-b041-68bee901ab19)

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

https://github.com/brightio/penelope/assets/65655412/7295da32-28e2-4c92-971f-09423eeff178

### Main Menu Commands
Some Notes:
- By default you need to press `F12` to detach the PTY shell and go to the Main Menu. If the upgrade was not possible the you ended up with a basic shell, you can detach it with `Ctrl+C`. This also prevents the accidental killing of the shell.
- The Main Menu supports TAB completion and also short commands. For example instead of `interact 1` you can just type `i 1`.

![Main Menu](https://github.com/user-attachments/assets/b3f568bc-5e66-4e6f-9510-3e61a3518e82)

### Command Line Options
```
positional arguments:
  args                          Arguments for -s/--serve and SSH reverse shell modes

options:
  -p PORTS, --ports PORTS       Ports (comma separated) to listen/connect/serve, depending on -i/-c/-s options
                                (Default: 4444/5555/8000)

Reverse or Bind shell?:
  -i , --interface              Local interface/IP to listen. (Default: 0.0.0.0)
  -c , --connect                Bind shell Host

Hints:
  -a, --payloads                Show sample reverse shell payloads for active Listeners
  -l, --interfaces              List available network interfaces
  -h, --help                    show this help message and exit

Session Logging:
  -L, --no-log                  Disable session log files
  -T, --no-timestamps           Disable timestamps in logs
  -CT, --no-colored-timestamps  Disable colored timestamps in logs

Misc:
  -m , --maintain               Keep N sessions per target
  -M, --menu                    Start in the Main Menu.
  -S, --single-session          Accommodate only the first created session
  -C, --no-attach               Do not auto-attach on new sessions
  -U, --no-upgrade              Disable shell auto-upgrade
  -O, --oscp-safe               Enable OSCP-safe mode

File server:
  -s, --serve                   Run HTTP file server mode
  -prefix , --url-prefix        URL path prefix

Debug:
  -N , --no-bins                Simulate missing binaries on target (comma-separated)
  -v, --version                 Print version and exit
  -d, --debug                   Enable debug output
  -dd, --dev-mode               Enable developer mode
  -cu, --check-urls             Check hardcoded URLs health and exit
```

## TODO

### Features
* Windows PTY auto-upgrade
* encryption
* download/upload autocompletion
* remote port forwarding
* socks & http proxy
* team server
* HTTPs and DNS agents

### Known Issues
* Session logging: when executing commands on the target that feature alternate buffers like nano and they are abnormally terminated, then when 'catting' the logfile it seems corrupted. However the data are still there. Also for example when resetting the remote terminal, these escape sequences are reflected in the logs. I will need to filter specific escape sequences so as to ensure that when 'catting' the logfile, a smooth log is presented.

## FAQ

### ► Is Penelope allowed in OSCP exam?
Yes. Penelope is allowed because its core features do not perform automatic exploitation.
However, caution is required when using certain modules:
* The meterpreter module should be used only on a single target, as permitted by OSCP rules.
* The traitor module uploads Traitor, which performs automatic privilege escalation.

So as long as you know what you’re doing, there should be no issues. If you want to avoid mistakes, you can use the `-O / --oscp-safe` switch.

### ► How can I return from the remote shell to the Main Menu?
It depends on the type of shell upgrade in use:
* PTY: press `F12`
* Readline: send EOF (`Ctrl-D`)
* Raw: send SIGINT (`Ctrl-C`)

In any case, the correct key is always displayed when you attach to a session. For example:

<img width="597" height="56" alt="463710291-51ee6370-7952-4db1-a0fd-31572278fa8e" src="https://github.com/user-attachments/assets/36b53c73-48cb-4ba7-a36a-ea92d1ea8f9b" />

### ► How can I customize Penelope (change default options, create custom modules, etc.)?
See [peneloperc](https://github.com/brightio/penelope/blob/main/extras/peneloperc)

### ► How can I contribute?
Your contributions are invaluable! If you’d like to help, please report bugs, unexpected behaviors, or share new ideas. You can also submit pull requests but avoid making commits from IDEs that enforce PEP8 and unintentionally restructure the entire codebase.

### ► How come the name?
Penelope was the wife of Odysseus and she is known for her fidelity for him by waiting years. Since a characteristic of reverse shell handlers is waiting, this tool is named after her.

## Thanks to the early birds
* [Cristian Grigoriu - @crgr](https://github.com/crgr) for inspiring me to automate the PTY upgrade process. This is how this project was born.
* [Paul Taylor - @bao7uo](https://github.com/bao7uo) for the idea to support bind shells.
* [Longlone - @WAY29](https://github.com/WAY29) for indicating the need for compatibility with previous versions of Python (3.6).
* [Carlos Polop - @carlospolop](https://github.com/carlospolop) for the idea to spawn shells on listeners on other systems.
* [@darrenmartyn](https://github.com/darrenmartyn) for indicating an alternative method to upgrade the shell to PTY using the script command.
* [@bamuwe](https://github.com/bamuwe) for the idea to get reverse shells via SSH.
* [@strikoder](https://github.com/strikoder) for numerous enhancement ideas.
* [@root-tanishq](https://github.com/root-tanishq), [@robertstrom](https://github.com/robertstrom), [@terryf82](https://github.com/terryf82), [@RamadhanAmizudin](https://github.com/RamadhanAmizudin), [@furkan-enes-polatoglu](https://github.com/furkan-enes-polatoglu), [@DerekFost](https://github.com/DerekFost), [@Mag1cByt3s](https://github.com/Mag1cByt3s), [@nightingalephillip](https://github.com/nightingalephillip), [@grisuno](https://github.com/grisuno), [@thinkslynk](https://github.com/thinkslynk), [@stavoxnetworks](https://github.com/stavoxnetworks), [@thomas-br](https://github.com/thomas-br), [@joshoram80](https://github.com/joshoram80), [@TheAalCh3m1st](https://github.com/TheAalCh3m1st), [@r3pek](https://github.com/r3pek), [@bamuwe](https://github.com/bamuwe), [@six-two](https://github.com/six-two), [@x9xhack](https://github.com/x9xhack), [@dummys](https://github.com/dummys), [@pocpayload](https://github.com/pocpayload), [@anti79](https://github.com/anti79), [@strikoder](https://github.com/strikoder) for bug reporting.
* Special thanks to [@Y3llowDuck](https://github.com/Y3llowDuck) for spreading the word!
