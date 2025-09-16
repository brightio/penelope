from .base import Module
from penelope_mod.constants import URLS
from penelope_mod.context import ctx
from textwrap import indent

class uac(Module):
    category = "Forensics"
    def run(session, args):
        """
        Acquire forensic data Unix systems using UAC (Unix-like Artifacts Collector) in the background
        """
        if session.OS == 'Unix':
            if not session.system == 'Linux':
                ctx.logger.error(f"This modules runs only on Linux, not on {session.system}.")
                return False
            path = session.upload(URLS['uac_linux'], remote_path=session.tmp)[0]
            result = session.exec(f"tar xf {path} -C {session.tmp} >/dev/null", value=True)
            if not result:
                ctx.logger.info(f"UAC successfully extracted on {session.tmp}")
            else:
                ctx.logger.error(f"Extraction to {session.tmp} failed:\n{indent(result, ' ' * 4 + '- ')}")
                return False
            ctx.logger.info(f"root user check is disabled. Data collection may be limited. It will WRITE the output on the remote file system.")
            cmd = f"cd {path.removesuffix('.tar.gz')}; ./uac -u -p ir_triage --output-format tar {session.tmp}"
            tf = f"/tmp/{__import__('random').randrange(10**6)}"
            with open(tf, "w") as f:
                f.write("#!/bin/sh\n")
                f.write(cmd)
            ctx.logger.info(f"UAC output will be stored at {session.tmp}/uac-%hostname%-%os%-%timestamp%")
            session.script(tf)
        # Once completed, transfer the output files to your host
        else:
            ctx.logger.error("This module runs only on Unix shells")

