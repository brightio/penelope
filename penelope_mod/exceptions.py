import sys
import platform
from penelope_mod.ui import paint

def custom_excepthook(*args):
    if len(args) == 1 and hasattr(args[0], 'exc_type'):
        exc_type, exc_value, exc_traceback = args[0].exc_type, args[0].exc_value, args[0].exc_traceback
    elif len(args) == 3:
        exc_type, exc_value, exc_traceback = args
    else:
        return
    print("\n", paint('Oops...').RED, '🐞\n', paint().yellow, '─' * 80, sep='')
    sys.__excepthook__(exc_type, exc_value, exc_traceback)
    # Defer context import to avoid cycles
    from penelope_mod.context import ctx
    print('─' * 80, f"\n{paint('Penelope version:').red} {paint(ctx.version).green}")
    print(f"{paint('Python version:').red} {paint(sys.version).green}")
    print(f"{paint('System:').red} {paint(platform.version()).green}\n")

