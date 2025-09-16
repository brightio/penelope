# Simple shared context for cross-module dependencies

class _Context:
    def __init__(self):
        # Will be set by main program
        self.logger = None
        self.cmdlogger = None
        self.options = None
        self.core = None
        self.menu = None
        # Program metadata
        self.program = None
        self.version = None
        # Optional extras
        self.readline = None
        self.default_readline_delims = None
        self.keyboard_interrupt = None
        self.load_rc = None


def set_context(*, logger=None, cmdlogger=None, options=None, core=None, menu=None,
                program=None, version=None,
                readline=None, default_readline_delims=None, keyboard_interrupt=None,
                load_rc=None):
    ctx.logger = logger
    ctx.cmdlogger = cmdlogger
    ctx.options = options
    ctx.core = core
    ctx.menu = menu
    ctx.program = program
    ctx.version = version
    ctx.readline = readline
    ctx.default_readline_delims = default_readline_delims
    ctx.keyboard_interrupt = keyboard_interrupt
    ctx.load_rc = load_rc


ctx = _Context()

