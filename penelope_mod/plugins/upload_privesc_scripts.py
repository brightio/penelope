from .base import Module
from penelope_mod.constants import URLS
from penelope_mod.ui import paint
from penelope_mod.context import ctx
from penelope_mod.io import ask, stdout

class upload_privesc_scripts(Module):
    category = "Privilege Escalation"
    def run(session, args):
        """
        Upload a set of privilege escalation scripts to the target
        """
        if session.OS == 'Unix':
            session.upload(URLS['linpeas'])
            session.upload(URLS['lse'])
            session.upload(URLS['deepce'])

        elif session.OS == 'Windows':
            session.upload(URLS['winpeas'])
            session.upload(URLS['powerup'])
            session.upload(URLS['privesccheck'])

