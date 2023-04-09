import logging
import os


class LogFormatter(logging.Formatter):
    # https://stackoverflow.com/questions/384076/how-can-i-color-python-logging-output
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def _logging_level(default='WARN'):
    '''
        REDART_LOG_LEVEL: The logging level for redart, possible values
            - DEBUG
            - INFO
            - WARN
            - ERROR
            - CRITICAL
    '''
    redart_logging_level = os.environ.get('REDART_LOG_LEVEL', default)
    return {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARN': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }.get(redart_logging_level, logging.WARNING)


def get_logger(name, *, default_level='WARN'):
    logger = logging.getLogger(name)
    level = _logging_level(default_level)
    logger.setLevel(level)
    formatter = LogFormatter()
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger
