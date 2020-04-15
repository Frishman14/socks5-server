import abc
from typing import Any, Tuple, List


class AbstractPacketParser(metaclass=abc.ABCMeta):
    def __init__(self, raw_packet):
        self.raw_packet: bytes = raw_packet

    @abc.abstractmethod
    def header(self) -> Tuple[Any]:
        pass

    @abc.abstractmethod
    def credentials(self) -> List[Any]:
        pass
