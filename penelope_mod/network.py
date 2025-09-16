import logging
import re
import shutil
import subprocess

class Interfaces:
    def __init__(self):
        self.interfaces = []
        
    def __str__(self):
        table = Table(joinchar=' : ')
        table.header = [paint('Interface').MAGENTA, paint('IP Address').MAGENTA]
        for name, ip in self.list.items():
            table += [paint(name).cyan, paint(ip).yellow]
        return str(table)

    def oneLine(self):
        return '(' + str(self).replace('\n', '|') + ')'

    def translate(self, interface_name):
        if interface_name in self.list:
            return self.list[interface_name]
        elif interface_name in ('any', 'all'):
            return '0.0.0.0'
        else:
            return interface_name

    @staticmethod
    def ipa(busybox=False):
        interfaces = []
        current_interface = None
        params = ['ip', 'addr']
        if busybox:
            params.insert(0, 'busybox')
        for line in subprocess.check_output(params).decode().splitlines():
            interface = re.search(r"^\d+: (.+?):", line)
            if interface:
                current_interface = interface[1]
                continue
            if current_interface:
                ip = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                if ip:
                    interfaces.append((current_interface, ip[1]))
                    current_interface = None # TODO support multiple IPs in one interface
        return interfaces

    @staticmethod
    def ifconfig():
        output = subprocess.check_output(['ifconfig']).decode()
        return re.findall(r'^(\w+).*?\n\s+inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)', output, re.MULTILINE | re.DOTALL)

    @property
    def list(self):
        logger = logging.getLogger('penelope')
        if shutil.which("ip"):
            interfaces = self.ipa()
        elif shutil.which("ifconfig"):
            interfaces = self.ifconfig()
        elif shutil.which("busybox"):
            interfaces = self.ipa(busybox=True)
        else:
            logger.error("'ip', 'ifconfig' and 'busybox' commands are not available. (Really???)")
            return dict()
        return {i[0]:i[1] for i in interfaces}

    @property
    def list_all(self):
        return [item for item in list(self.list.keys()) + list(self.list.values())]

# Late imports to avoid circular deps in standalone module usage
from .ui import Table, paint