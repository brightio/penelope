import os
import signal
import threading
import builtins
from penelope_mod.context import ctx


def stdout(data, record=True):
    """Write bytes to stdout and record to output buffer if needed."""
    os.write(1, data)
    if record and ctx.core is not None:
        ctx.core.output_line_buffer << data


def ask(text):
    """Prompt user with a colored question, handling Ctrl-C gracefully."""
    try:
        return builtins.input(text)
    except EOFError:
        print()
        return ''  # Return empty string instead of recursively calling ask
    except KeyboardInterrupt:
        print("^C")
        return ' '


def my_input(text="", histfile=None, histlen=None, completer=lambda text, state: None, completer_delims=None):
    if threading.current_thread().name == 'MainThread':
        signal.signal(signal.SIGINT, ctx.keyboard_interrupt)

    rl = ctx.readline
    if rl:
        rl.set_completer(completer)
        rl.set_completer_delims(completer_delims or ctx.default_readline_delims)
        rl.clear_history()
        if histfile:
            try:
                rl.read_history_file(histfile)
            except Exception as e:
                if ctx.cmdlogger:
                    ctx.cmdlogger.debug(f"Error loading history file: {e}")

    if ctx.core is not None:
        ctx.core.output_line_buffer << b"\n" + text.encode()
        ctx.core.wait_input = True

    try:
        response = builtins.input(text)

        if rl:
            if histfile:
                try:
                    rl.set_history_length(ctx.options.histlength)
                    rl.write_history_file(histfile)
                except Exception as e:
                    if ctx.cmdlogger:
                        ctx.cmdlogger.debug(f"Error writing to history file: {e}")
        return response
    finally:
        if ctx.core is not None:
            ctx.core.wait_input = False

