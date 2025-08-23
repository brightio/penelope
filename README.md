<div align="center">
  <img src="https://github.com/user-attachments/assets/0d369fba-480e-4e27-a117-8845dbd4b58e" alt="Logo" width="200"/>
</div>
<div align="center">
  <img src="https://raw.githubusercontent.com/toolswatch/badges/refs/heads/master/arsenal/europe/2024.svg?sanitize=true"/>
</div>
Penelope is a powerful shell handler built to simplify, accelerate, and optimize post-exploitation workflows.

- It runs on all Unix-based systems (Linux, macOS, FreeBSD etc)
- Requires **Python 3.6+**
- It is **standalone** as it uses only Python’s standard library.

![Penelope](https://github.com/user-attachments/assets/b8e5cd84-60a5-4d79-b041-68bee901ab19)

## Install

Penelope requires no installation - just download and execute the script:
```bash
wget https://raw.githubusercontent.com/brightio/penelope/refs/heads/main/penelope.py && python3 penelope.py
```
For a more streamlined setup, it can be installed using:
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
- Can be imported by python3 exploits and get shell on the same terminal (see [Extras](#Extras))

### Modules
![Modules](https://github.com/user-attachments/assets/cb2c3e36-a051-4bff-9091-25b63a584235)

#### Meterpreter module demonstration

![meterpreter](https://github.com/user-attachments/assets/b9cda69c-e25c-41e1-abe2-ce18ba13c4ed)

Penelope can work in conjunction with metasploit exploits by disabling the default handler with `set DisablePayloadHandler True`

## Usage
### Sample Typical Usage
```
penelope                          # Listening for reverse shells on 0.0.0.0:4444
penelope -a                       # Listening for reverse shells on 0.0.0.0:4444 and show reverse shell payloads based on the current Listeners
penelope -p 5555                  # Listening for reverse shells on 0.0.0.0:5555
penelope -i eth0 -p 5555          # Listening for reverse shells on eth0:5555
penelope -c target -p 3333        # Connect to a bind shell on target:3333
penelope ssh user@target          # Get a reverse shell from target on local port 4444
penelope -p 5555 ssh user@target  # Get a reverse shell from target on local port 5555
penelope -i eth0 -p 5555 -- ssh -l user -p 2222 target  # Get a reverse shell from target on eth0, local port 5555 (use -- if ssh needs switches)
penelope -s <File/Folder>         # Share a file or folder via HTTP
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

https://github.com/brightio/penelope/assets/65655412/7295da32-28e2-4c92-971f-09423eeff178

### Main Menu Commands
Some Notes:
- By default you need to press `F12` to detach the PTY shell and go to the Main Menu. If the upgrade was not possible the you ended up with a basic shell, you can detach it with `Ctrl+C`. This also prevents the accidental killing of the shell.
- The Main Menu supports TAB completion and also short commands. For example instead of `interact 1` you can just type `i 1`.

![Main Menu](https://github.com/user-attachments/assets/b3f568bc-5e66-4e6f-9510-3e61a3518e82)

### Command Line Options
```
positional arguments:
  args                          Arguments for -s/--serve and SSH reverse shell (default: None)

options:
  -p PORT, --port PORT          Port to listen/connect/serve, depending on -i/-c/-s options. Default: 4444/5555/8000 (default: None)

Reverse or Bind shell?:
  -i , --interface              Interface or IP address to listen on. Default: 0.0.0.0 (default: None)
  -c , --connect                Bind shell Host (default: None)

Hints:
  -a, --payloads                Show sample payloads for reverse shell based on the registered Listeners (default: False)
  -l, --interfaces              Show the available network interfaces (default: False)
  -h, --help                    show this help message and exit

Session Logging:
  -L, --no-log                  Do not create session log files (default: False)
  -T, --no-timestamps           Do not include timestamps in session logs (default: False)
  -CT, --no-colored-timestamps  Do not color timestamps in session logs (default: False)

Misc:
  -m , --maintain               Maintain NUM total shells per target (default: None)
  -M, --menu                    Just land to the Main Menu (default: False)
  -S, --single-session          Accommodate only the first created session (default: False)
  -C, --no-attach               Disable auto attaching sessions upon creation (default: False)
  -U, --no-upgrade              Do not upgrade shells (default: False)

File server:
  -s, --serve                   HTTP File Server mode (default: False)
  -prefix , --url-prefix        URL prefix (default: None)

Debug:
  -N , --no-bins                Simulate binary absence on target (comma separated list) (default: None)
  -v, --version                 Show Penelope version (default: False)
  -d, --debug                   Show debug messages (default: False)
  -dd, --dev-mode               Developer mode (default: False)
  -cu, --check-urls             Check health of hardcoded URLs (default: False)
```

## Contribution
Your contributions are invaluable! If you’d like to help, please report bugs, unexpected behaviors, or share new ideas. You can also submit pull requests but avoid making commits from IDEs that enforce PEP8 and unintentionally restructure the entire codebase.

## TODO

### Features
* remote port forwarding
* socks & http proxy
* persistence modules
* team server
* currently spawn/script/portfwd commands are supported only on Unix shells. Those need to be implemented for Windows shells too.
* an option switch for disable all logging, not only sessions.
* main menu autocompletion for short commands
* download/upload autocompletion
* IPv6 support
* encryption
* UDP support

### Known Issues
* Main menu: Ctrl-C on main menu has not the expected behavior yet.
* Session logging: when executing commands on the target that feature alternate buffers like nano and they are abnormally terminated, then when 'catting' the logfile it seems corrupted. However the data are still there. Also for example when resetting the remote terminal, these escape sequences are reflected in the logs. I will need to filter specific escape sequences so as to ensure that when 'catting' the logfile, a smooth log is presented.

## Trivia
Penelope was the wife of Odysseus and she is known for her fidelity for him by waiting years. Since a characteristic of reverse shell handlers is waiting, this tool is named after her.

## Thanks to the early birds
* [Cristian Grigoriu - @crgr](https://github.com/crgr) for inspiring me to automate the PTY upgrade process. This is how this project was born.
* [Paul Taylor - @bao7uo](https://github.com/bao7uo) for the idea to support bind shells.
* [Longlone - @WAY29](https://github.com/WAY29) for indicating the need for compatibility with previous versions of Python (3.6).
* [Carlos Polop - @carlospolop](https://github.com/carlospolop) for the idea to spawn shells on listeners on other systems.
* [@darrenmartyn](https://github.com/darrenmartyn) for indicating an alternative method to upgrade the shell to PTY using the script command.
* [@bamuwe](https://github.com/bamuwe) for the idea to get reverse shells via SSH.
* [@root-tanishq](https://github.com/root-tanishq), [@robertstrom](https://github.com/robertstrom), [@terryf82](https://github.com/terryf82), [@RamadhanAmizudin](https://github.com/RamadhanAmizudin), [@furkan-enes-polatoglu](https://github.com/furkan-enes-polatoglu), [@DerekFost](https://github.com/DerekFost), [@Mag1cByt3s](https://github.com/Mag1cByt3s), [@nightingalephillip](https://github.com/nightingalephillip), [@grisuno](https://github.com/grisuno), [@thinkslynk](https://github.com/thinkslynk), [@stavoxnetworks](https://github.com/stavoxnetworks), [@thomas-br](https://github.com/thomas-br), [@joshoram80](https://github.com/joshoram80), [@TheAalCh3m1st](https://github.com/TheAalCh3m1st), [@r3pek](https://github.com/r3pek), [@bamuwe](https://github.com/bamuwe), [@six-two](https://github.com/six-two), [@x9xhack](https://github.com/x9xhack), [@dummys](https://github.com/dummys), [@pocpayload](https://github.com/pocpayload), [@anti79](https://github.com/anti79) for bug reporting.
