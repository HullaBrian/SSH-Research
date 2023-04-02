from SSH import __app_name__, __version__

import socket

from loguru import logger


def exchange_version(sock: socket) -> bytes:
    data = f"{__app_name__} v{__version__}\r\n".encode("utf-8")
    logger.debug(f"Sending data '{data}'")
    sock.sendall(data)
    return sock.recv(1024)
