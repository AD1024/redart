from dataclasses import dataclass
import enum

class TimestampScale(enum.IntEnum):
    SECOND = enum.auto()
    MILLISECOND = enum.auto()
    MICROSECOND = enum.auto()

@dataclass
class RedartConfig:
    timescale: TimestampScale

_redart_config: RedartConfig = None

def get_config():
    if _redart_config is None:
        raise ValueError("Redart has not been initialized yet")
    return _redart_config