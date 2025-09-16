from .base import Module
from penelope_mod.constants import URLS
from penelope_mod.context import ctx

class lse(Module):
    category = "Privilege Escalation"
    def run(session, args):
        """
        Run the latest version of linux-smart-enumeration in the background
        """
        if session.OS == 'Unix':
            session.script(URLS['lse'])
        else:
            ctx.logger.error("This module runs only on Unix shells")

