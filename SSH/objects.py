from dataclasses import dataclass


@dataclass()
class Server:
    ip: str
    port: int
    ssh_version: str
