"""
Set colored logger.

This module should only be imported in the main function.

.. code-block:: py

    name = 'your_app_name'
    debugging = True

    try:
        from coloredlog import setColoredLogger

        setColoredLogger(name, debugging)
    except ImportError:
        pass

    logger = logging.getLogger(name)
    logger.debug('debug message!')
"""

from copy import copy
from enum import IntEnum
import logging


__all__ = ['setColoredLogger']


class Color(IntEnum):
    """
    The background is set with 40 plus the number of the color, and the
    foreground with 30.
    """
    __slots__ = ()

    BLACK = 0
    RED = 1
    GREEN = 2
    YELLOW = 3
    BLUE = 4
    MAGENTA = 5
    CYAN = 6
    WHITE = 7


def colored(s: str, color: int, bold=False):
    if not color:
        return s
    COLOR_SEQ = '\033[1;'
    BOLD_SEQ = '\033[1m'
    RESET_SEQ = '\033[0m'
    return f'{BOLD_SEQ if bold else ""}{COLOR_SEQ}{30 + color}m{s}{RESET_SEQ}'


class ColoredFormatter(logging.Formatter):
    __slots__ = ()

    COLORS = {
        'WARNING': Color.YELLOW,
        'INFO': Color.WHITE,
        'DEBUG': Color.BLUE,
        'CRITICAL': Color.YELLOW,
        'ERROR': Color.RED
    }

    def format(self, record: logging.LogRecord):
        """
        Format the record using the underlying formatter, but display the
        level name in color.

        The function does not change the original record.
        """
        record = copy(record)
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = colored(levelname, self.COLORS[levelname])
        return super().format(record)


def setColoredLogger(logger: str | logging.Logger, verbose=False):
    """
    Set console output for logger of giver namespace.

    :param ns: Logger, or namespace of the logger.
    :param verbose: Whether to set logger level to debug.
    """
    try:
        from colorama import just_fix_windows_console

        just_fix_windows_console()
    except ImportError:
        pass

    if isinstance(logger, str):
        logger = logging.getLogger(logger)
    if verbose:
        logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setFormatter(ColoredFormatter(
        # log by time
        # '%(asctime)s - %(levelname)s: %(message)s'
        # gtk style
        # '(%(filename)s:%(process)d): %(funcName)s-%(levelname)s **: %(message)s'
        '(%(filename)s %(funcName)s+%(lineno)d): %(levelname)s **: %(message)s'))
    logger.addHandler(ch)
