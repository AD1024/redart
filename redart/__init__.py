from . import config, data, simulator


def init(timescale: config.TimestampScale = config.TimestampScale.MILLISECOND,
         ignore_syn: bool = False,
         logging_level: str = None):
    import os
    if logging_level is None and "REDART_LOG_LEVEL" in os.environ:
        logging_level = os.environ["REDART_LOG_LEVEL"]
    config._redart_config = config.RedartConfig(
        timescale, ignore_syn, logging_level)


def current_config():
    return config.get_config()


def set_timescale(timescale: config.TimestampScale):
    config._redart_config.timescale = timescale
