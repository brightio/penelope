from .base import Module
from penelope_mod.constants import URLS
from penelope_mod.context import ctx

class linux_procmemdump(Module):
    category = "Forensics"
    def run(session, args):
        """
        Dump process memory in the background (requires root)
        """
        if session.OS == 'Unix':
            if not session.system == 'Linux':
                ctx.logger.error(f"This modules runs only on Linux, not on {session.system}.")
                return False
            session.upload(URLS['linux_procmemdump'], remote_path=session.tmp)
            print(session.exec(f"ps -eo pid,cmd", value=True))
            ctx.logger.info(f"Please provide the PID of the process to be acquired:")
            PID = input("PID: ")
            session.exec(f"{session.tmp}/linux_procmemdump.sh -p {PID} -s -d {session.tmp}")
            ctx.logger.info(f"Strings of the process dump will be stored at {session.tmp}/{PID}/")
        else:
            ctx.logger.error("This module runs only on Unix shells")

