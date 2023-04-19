from . import config, data, simulator


def init(timescale: config.TimestampScale):
    config._redart_config = config.RedartConfig(timescale)


def current_config():
    return config.get_config()


def set_timescale(timescale: config.TimestampScale):
    config._redart_config.timescale = timescale
