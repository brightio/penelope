<div align="center">
  <img src="https://github.com/user-attachments/assets/0d369fba-480e-4e27-a117-8845dbd4b58e" alt="Logo" width="200"/>
</div>

<img src="https://img.shields.io/badge/Version-0.20.3-6D4AFF"/><br>
![Black Hat Arsenal](https://img.shields.io/badge/Presented%20at-Black%20Hat%20Arsenal-111827)
![EU](https://img.shields.io/badge/EU%202024-2563EB)
![USA](https://img.shields.io/badge/USA%202025-B91C1C)
![MEA](https://img.shields.io/badge/MEA%202025-15803D)<br>
![Kali Linux](https://img.shields.io/badge/Packaged%20in-Kali%20Linux-557C94)

Penelope is a modern shell handler for penetration testers and CTF players. It provides a more capable alternative to basic netcat listeners, adding automatic PTY upgrades, session management, logging, file transfers and helper modules.

## Table of Contents
- 📥 [Installation](#installation)
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

## Installation

Penelope runs on Unix-like systems, including Linux, macOS and FreeBSD, and requires **Python 3.6+**.

### Kali Linux
Penelope is available in Kali Linux:
```bash
sudo apt update
sudo apt install penelope
```

### Standalone execution
Penelope is implemented entirely with Python’s standard library, allowing it to run as a standalone script without any external dependencies:
```bash
wget -q https://raw.githubusercontent.com/brightio/penelope/refs/heads/main/penelope.py && python3 penelope.py
```

### pipx
To install the latest upstream version directly from GitHub:
```bash
pipx install git+https://github.com/brightio/penelope
```
For a versioned and more stable release path, Penelope is also available on PyPI:
```bash
pipx install penelope-shell-handler
```

## Features
### Session Features
|Description|Unix with Python>=2.3| Unix without Python>=2.3|Windows|
|-----------|:-------------------:|:-----------------------:|:-----:|
|Auto-upgrade shell|PTY|PTY(*)|readline(**)|
|Real-time terminal resize|✅|✅|❌|
|Logging shell activity|✅|✅|✅|
|Download remote files/folders|✅|✅|✅|
|Upload local/HTTP files/folders|✅|✅|✅|
|In-memory local/HTTP script execution with real-time output downloading|✅|❌|❌|
|Local port forwarding|✅|❌|❌|
|Spawn shells on multiple tabs and/or hosts|✅|✅|❌|
|Maintain X amount of active shells per host no matter what|✅|✅|❌|

(*) opens a second TCP connection

(**) Can be manually upgraded with the `upgrade` command

### Global Features
- Streamline interaction with the targets via modules
- Multiple sessions
- Multiple listeners
- Serve files/folders via HTTP (-s switch)
- Can be imported by python3 exploits and get shell on the same terminal (see [extras/exploit_examples](https://github.com/brightio/penelope/tree/main/extras/exploit_examples))
- Can work in conjunction with Metasploit exploits by disabling the default handler with `set DisablePayloadHandler True`

### Modules

![modules](https://github.com/user-attachments/assets/e1428a62-727b-4f2e-bb9e-b225e49409e1)

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

As shown in the video below, within only a few seconds we can:
1. Get a fully functional auto-resizable PTY shell while logging every interaction with the target
2. Execute the latest version of LinPEAS on the target without touching the disk and save the output to a local file in real time
3. Open one more PTY shell in another tab
4. Upload the latest versions of LinPEAS and linux-smart-enumeration
5. Upload a local folder with custom scripts
6. Upload an exploit-db exploit directly from URL
7. Download and open a remote file locally
8. Download the remote /etc directory
9. Automatically spawn a new shell if an existing shell dies, helping keep access available during unstable shell sessions

https://github.com/brightio/penelope/assets/65655412/7295da32-28e2-4c92-971f-09423eeff178

### Main Menu Commands
Some Notes:
- By default you need to press `F12` to detach the PTY shell and go to the Main Menu. If the upgrade was not possible and you ended up with a basic shell, you can detach it with `Ctrl+C`. This also prevents the accidental killing of the shell.
- The Main Menu supports TAB completion and also short commands. For example instead of `interact 1` you can just type `i 1`.

![Main Menu](https://github.com/user-attachments/assets/a0ba2925-ea7a-4c09-9ed0-8063a7d21b65)

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
  -j , --jump                   Reverse shell jump endpoints

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
* encryption
* remote port forwarding
* socks & http proxy
* team server
* HTTPs and DNS agents

### Known Issues
* Session logging: commands that use alternate buffers, such as nano, may leave escape sequences in the log if they terminate abnormally. The data is still preserved, but viewing the logfile with tools like `cat` may look corrupted. Filtering these escape sequences is planned to make log output smoother.

## FAQ

### ► Is Penelope allowed in the OSCP exam?

Penelope’s core shell-handling features do not perform automatic exploitation, which makes them suitable for OSCP-style usage. However, exam rules can change, so always verify the current official OffSec rules before using any tool during an exam.

Some modules require extra caution:

* The meterpreter module should only be used in a way that complies with the current exam rules.
* The traitor module uploads Traitor, which performs automatic privilege escalation.

If you want to avoid accidental rule violations, use the `-O / --oscp-safe` switch.

### ► How can I return from the remote shell to the Main Menu?
It depends on the type of shell upgrade in use:
* PTY: press `F12`
* Readline: send EOF (`Ctrl-D`)
* Raw: send SIGINT (`Ctrl-C`)

In any case, the correct key is always displayed when you attach to a session. For example:

![F12](https://github.com/user-attachments/assets/87da0eec-0d78-4f1b-8e82-f3ebe9cacf5e)

### ► How can I customize Penelope (change default options, create custom modules, etc.)?
See [peneloperc](https://github.com/brightio/penelope/blob/main/extras/peneloperc)

### ► Why aren’t my current working directory and/or user respected when I use menu commands like download/upload?
This usually means you opened a new interactive shell, possibly under a different user. The Penelope agent only tracks the directory of the initial shell and keeps the permissions of the user from that first shell. The best workaround is to `cd /tmp` before opening a new shell, or, if you switched users, spawn a new reverse shell as the new user.

### ► How can I contribute?
Your contributions are invaluable! If you’d like to help, please report bugs, unexpected behaviors, or share new ideas. You can also submit pull requests but avoid making commits from IDEs that enforce PEP8 and unintentionally restructure the entire codebase.

### ► Where does the name come from?
Penelope was the wife of Odysseus and is known for her loyalty and patience while waiting for him to return. The tool is named after her because it was built to be a faithful and stable shell handler for workflows that go beyond a basic listener.

## Thanks to the early birds
* [Cristian Grigoriu - @crgr](https://github.com/crgr) for inspiring me to automate the PTY upgrade process. This is how this project was born.
* [Paul Taylor - @bao7uo](https://github.com/bao7uo) for the idea to support bind shells.
* [Longlone - @WAY29](https://github.com/WAY29) for indicating the need for compatibility with previous versions of Python (3.6).
* [Carlos Polop - @carlospolop](https://github.com/carlospolop) for the idea to spawn shells on listeners on other systems.
* [@darrenmartyn](https://github.com/darrenmartyn) for indicating an alternative method to upgrade the shell to PTY using the script command.
* [@bamuwe](https://github.com/bamuwe) for the idea to get reverse shells via SSH.
* [@strikoder](https://github.com/strikoder) for numerous enhancement ideas.
* [@root-tanishq](https://github.com/root-tanishq), [@robertstrom](https://github.com/robertstrom), [@terryf82](https://github.com/terryf82), [@RamadhanAmizudin](https://github.com/RamadhanAmizudin), [@furkan-enes-polatoglu](https://github.com/furkan-enes-polatoglu), [@DerekFost](https://github.com/DerekFost), [@Mag1cByt3s](https://github.com/Mag1cByt3s), [@nightingalephillip](https://github.com/nightingalephillip), [@grisuno](https://github.com/grisuno), [@thinkslynk](https://github.com/thinkslynk), [@stavoxnetworks](https://github.com/stavoxnetworks), [@thomas-br](https://github.com/thomas-br), [@joshoram80](https://github.com/joshoram80), [@TheAalCh3m1st](https://github.com/TheAalCh3m1st), [@r3pek](https://github.com/r3pek), [@bamuwe](https://github.com/bamuwe), [@six-two](https://github.com/six-two), [@x9xhack](https://github.com/x9xhack), [@dummys](https://github.com/dummys), [@pocpayload](https://github.com/pocpayload), [@anti79](https://github.com/anti79), [@strikoder](https://github.com/strikoder), [@bestutsengineer](https://github.com/bestutsengineer) for bug reporting.
* Special thanks to [@Y3llowDuck](https://github.com/Y3llowDuck) for spreading the word!
