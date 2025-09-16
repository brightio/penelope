import os
import platform
import shutil
import subprocess
from select import select
from penelope_mod.context import ctx

# Terminal detection
myOS = platform.system()
DISPLAY = 'DISPLAY' in os.environ
TERMINALS = [
    'gnome-terminal', 'mate-terminal', 'qterminal', 'terminator', 'alacritty', 'kitty', 'tilix',
    'konsole', 'xfce4-terminal', 'lxterminal', 'urxvt', 'st', 'xterm', 'eterm', 'x-terminal-emulator'
]
TERMINAL = next((term for term in TERMINALS if shutil.which(term)), None)


def Open(item, terminal=False):
    if myOS != 'Darwin' and not DISPLAY:
        ctx.logger.error("No available $DISPLAY")
        return False

    if not terminal:
        program = 'xdg-open' if myOS != 'Darwin' else 'open'
        args = [item]
    else:
        if not TERMINAL:
            ctx.logger.error("No available terminal emulator")
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
            args = [_switch, *__import__('shlex').split(item)]
        else:
            program = 'osascript'
            args = ['-e', f'tell app "Terminal" to do script "{item}"']

    if not shutil.which(program):
        ctx.logger.error(f"Cannot open window: '{program}' binary does not exist")
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
            ctx.logger.error(error.decode())
            return False
    return True


def fonts_installed():
    possible_paths = (
        "/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf",
        "/usr/share/fonts/noto/NotoColorEmoji.ttf",
        "/usr/local/share/fonts/noto/NotoColorEmoji.ttf",
        "/usr/local/share/fonts/noto-emoji/NotoColorEmoji.ttf"
    )

    for path in possible_paths:
        if os.path.isfile(path):
            return True
    if myOS == "Darwin":
        return True
    try:
        if "Noto Color Emoji" in subprocess.run(["fc-list"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout:
            return True
    except:
        pass
    return False

