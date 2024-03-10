"""
Set colored logger.

This module should only be imported in the main function.

.. code-block:: py

    try:
        from coloredlog import setColoredLogger
    except ImportError:
        setColoredLogger = lambda *args, **kwargs: None

    name = 'your_app_name'
    debugging = True
    setColoredLogger(name, debugging)

    logger = logging.getLogger(name)
    logger.debug('debug message!')
"""

from copy import copy
import logging


# The background is set with 40 plus the number of the color, and the foreground
# with 30
BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

# These are the sequences need to get colored output
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;{}m"
BOLD_SEQ = "\033[1m"
COLORS = {
    'WARNING': YELLOW,
    'INFO': WHITE,
    'DEBUG': BLUE,
    'CRITICAL': YELLOW,
    'ERROR': RED
}


class ColoredFormatter(logging.Formatter):
    def format(self, record):
        """
        Format the record using the underlying formatter, but display the
        level name in color.

        The function does not change the original record.
        """
        record = copy(record)
        levelname = record.levelname
        if levelname in COLORS:
            record.levelname = ''.join((
                COLOR_SEQ.format(30 + COLORS[levelname]), levelname, RESET_SEQ))
        return super().format(record)


def setColoredLogger(logger : str | logging.Logger, verbose=False):
    """
    Set console output for logger of giver namespace.

    :param ns: Logger, or namespace of the logger.
    :param verbose: Whether to set logger level to debug.
    """
    if isinstance(logger, str):
        logger = logging.getLogger(logger)
    if verbose:
        logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setFormatter(ColoredFormatter(
        # log by time
        # '%(asctime)s - %(levelname)s: %(message)s'))
        # gtk style
        # '(%(filename)s:%(process)d): %(funcName)s-%(levelname)s **: %(message)s'))
        '(%(filename)s %(funcName)s+%(lineno)d): %(levelname)s **: %(message)s'))
    logger.addHandler(ch)
