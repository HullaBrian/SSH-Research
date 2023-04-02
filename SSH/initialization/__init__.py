from SSH.types import IP
from SSH.objects import Server
from SSH.initialization.exchange_version import exchange_version
from SSH.initialization.key_exchange import key_exchange

import socket

from loguru import logger


def connect(ip: IP):
    Connection(ip)


class Connection(object):
    def __init__(self, ip: IP):
        self.ip = ip
        self.server = Server("", 22, "")

        self._connect()

    def _connect(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((str(self.ip), 22))
            except ConnectionRefusedError:
                logger.error(f"Could not connect to {self.ip}: Connection Refused!")
                return

            self.server.ssh_version = exchange_version(s).decode("utf-8").removesuffix("\r\n")
            logger.debug(f"Server SSH version '{self.server.ssh_version}'")
