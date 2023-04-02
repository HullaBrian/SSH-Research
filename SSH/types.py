from dataclasses import dataclass


@dataclass()
class IP:
    o1: str
    o2: str
    o3: str
    o4: str

    def __str__(self):
        return self.o1 + "." + self.o2 + "." + self.o3 + "." + self.o4
