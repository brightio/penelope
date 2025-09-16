import os
import socket
import socketserver
from http.server import SimpleHTTPRequestHandler
from urllib.parse import unquote

from penelope_mod.context import ctx
from penelope_mod.ui import paint, Table
from penelope_mod.network import Interfaces
from penelope_mod.core import handle_bind_errors

class FileServer:
    def __init__(self, *items, port=None, host=None, url_prefix=None, quiet=False):
        self.port = port or ctx.options.default_fileserver_port
        self.host = host or ctx.options.default_interface
        self.host = Interfaces().translate(self.host)
        self.items = items
        self.url_prefix = url_prefix + '/' if url_prefix else ''
        self.quiet = quiet
        self.filemap = {}
        for item in self.items:
            self.add(item)

    def add(self, item):
        if item == '/':
            self.filemap[f'/{self.url_prefix}[root]'] = '/'
            return '/[root]'

        item = os.path.abspath(os.path.normpath(os.path.expandvars(os.path.expanduser(item))))

        if not os.path.exists(item):
            if not self.quiet:
                ctx.logger.warning(f"'{item}' does not exist and will be ignored.")
            return None

        if item in self.filemap.values():
            for _urlpath, _item in self.filemap.items():
                if _item == item:
                    return _urlpath

        urlpath = f"/{self.url_prefix}{os.path.basename(item)}"
        while urlpath in self.filemap:
            root, ext = os.path.splitext(urlpath)
            urlpath = root + '_' + ext
        self.filemap[urlpath] = item
        return urlpath

    def remove(self, item):
        item = os.path.abspath(os.path.normpath(os.path.expandvars(os.path.expanduser(item))))
        if item in self.filemap:
            del self.filemap[f"/{os.path.basename(item)}"]
        else:
            if not self.quiet:
                ctx.logger.warning(f"{item} is not served.")

    @property
    def links(self):
        output = []
        ips = [self.host]

        if self.host == '0.0.0.0':
            ips = [ip for ip in Interfaces().list.values()]

        for ip in ips:
            output.extend(('', '🏠 http://' + str(paint(ip).cyan) + ":" + str(paint(self.port).red) + '/' + self.url_prefix))
            table = Table(joinchar=' → ')
            for urlpath, filepath in self.filemap.items():
                table += (
                    paint(f"{'📁' if os.path.isdir(filepath) else '📄'} ").green +
                    paint(f"http://{ip}:{self.port}{urlpath}").white_BLUE, filepath
                )
            output.append(str(table))
            output.append("─" * len(output[1]))

        return '\n'.join(output)

    def start(self):
        __import__('threading').Thread(target=self._start).start()

    def _start(self):
        filemap, host, port, url_prefix, quiet = self.filemap, self.host, self.port, self.url_prefix, self.quiet

        class CustomTCPServer(socketserver.TCPServer):
            allow_reuse_address = True

            def __init__(self, *args, **kwargs):
                self.client_sockets = []
                super().__init__(*args, **kwargs)

            @handle_bind_errors
            def server_bind(self, host, port):
                self.server_address = (host, int(port))
                super().server_bind()

            def process_request(self, request, client_address):
                self.client_sockets.append(request)
                super().process_request(request, client_address)

            def shutdown(self):
                for sock in self.client_sockets:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                        sock.close()
                    except:
                        pass
                super().shutdown()

        class CustomHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                try:
                    if self.path == '/' + url_prefix:
                        response = ''
                        for path in filemap.keys():
                            response += f'<li><a href="{path}">{path}</a></li>'
                        response = response.encode()
                        self.send_response(200)
                        self.send_header("Content-type", "text/html")
                        self.send_header("Content-Length", str(len(response)))
                        self.end_headers()

                        self.wfile.write(response)
                    else:
                        super().do_GET()
                except Exception as e:
                    ctx.logger.error(e)

            def translate_path(self, path):
                path = path.split('?', 1)[0]
                path = path.split('#', 1)[0]
                try:
                    path = unquote(path, errors='surrogatepass')
                except UnicodeDecodeError:
                    path = unquote(path)
                path = os.path.normpath(path)

                for urlpath, filepath in filemap.items():
                    if path == urlpath:
                        return filepath
                    elif path.startswith(urlpath):
                        relpath = path[len(urlpath):].lstrip('/')
                        return os.path.join(filepath, relpath)
                return ""

            def log_message(self, format, *args):
                if quiet:
                    return None
                message = format % args
                response = message.translate(self._control_char_table).split(' ')
                if not response[0].startswith('"'):
                    return
                if response[3][0] == '3':
                    color = 'yellow'
                elif response[3][0] in ('4', '5'):
                    color = 'red'
                else:
                    color = 'green'

                response = getattr(paint(f"{response[0]} {response[1]} {response[3]}\""), color)

                ctx.logger.info(
                    f"{paint('[').white}{paint(self.log_date_time_string()).magenta}] "
                    f"FileServer({host}:{port}) [{paint(self.address_string()).cyan}] {response}"
                )

        with CustomTCPServer((self.host, self.port), CustomHandler, bind_and_activate=False) as self.httpd:
            if not self.httpd.server_bind(self.host, self.port):
                return False
            self.httpd.server_activate()
            self.id = ctx.core.new_fileserverID
            ctx.core.fileservers[self.id] = self
            if not quiet:
                print(self.links)
            self.httpd.serve_forever()

    def stop(self):
        del ctx.core.fileservers[self.id]
        if not self.quiet:
            ctx.logger.warning(f"Shutting down Fileserver #{self.id}")
        self.httpd.shutdown()

