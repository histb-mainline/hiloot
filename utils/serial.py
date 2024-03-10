import asyncio
import logging
import sys
from typing import TYPE_CHECKING, Callable, Literal, overload

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer, SupportsWrite


__all__ = ['SerialLogger', 'SerialMux']


_logger = logging.getLogger(__name__)

try:
    from .coloredlog import setColoredLogger

    setColoredLogger(_logger)
except ImportError:
    pass


class SerialLogger:
    """Serial port logging stream."""
    buf: 'SupportsWrite[str]'
    "underlying logging stream"
    prefix: str
    "prefix when starting a new line"
    newline: bool
    "`True` if last byte is a newline"
    raw: bool
    "log all messages as raw bytes, useful for debugging but really flooding"

    __slots__ = tuple(__annotations__)

    def __init__(self, buf: 'SupportsWrite[str]' = sys.stderr):
        self.buf = buf
        self.prefix = '-> '
        self.newline = True
        self.raw = False

    def _write_bytes(self, s: bytes):
        if not self.newline:
            # last message must be a str
            self.buf.write('%\n')
        self.buf.write(self.prefix)
        self.buf.write(repr(s))

        self.newline = True
        self.buf.write('\n')

    def _write_str(self, s: bytes):
        for i, m in enumerate(s.splitlines()):
            if i:
                self.buf.write('\n')
            if i or self.newline:
                self.buf.write(self.prefix)
            self.buf.write(m.decode(errors='ignore'))

        self.newline = s[-1] == 0xa
        if self.newline:
            self.buf.write('\n')

    def write(self, s: bytes):
        if not s:
            return 0

        if not self.raw and s[0] < 0x80:
            self._write_str(s)
        else:
            # do not log single ACK to prevent flooding
            if not self.raw and s == b'\xaa':
                return 1
            self._write_bytes(s)

        return len(s)


class SerialMux:
    r"""
    Serial port multiplexer.

    Printable messages end with newline (`b'\n'`). Binary messages end with
    `b'\xaa'`.

    However, since serial lines are not reliable transmission, the delimiters
    themselves could also be lost, thus we need to recheck the type of message
    after the restart length.

    This class does not handle timeouts; use :func:`asyncio.timeout`.
    """
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    logger: 'SupportsWrite[bytes] | None'

    delimiter: int
    "delimiter for the boundary of a frame"
    restart: int | None
    """
    restart length, should be larger than the length of the longest possible
    frame
    """
    retry: float | None
    "seconds before starting retransmission"

    _buffer: bytearray
    _binary: bool

    __slots__ = tuple(__annotations__)

    def __init__(
            self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, /,
            logger: 'SupportsWrite[bytes] | None' = None, delimiter=0xaa,
            restart: int | None = 17):
        self.reader = reader
        self.writer = writer
        self.logger = logger
        self.delimiter = delimiter
        self.restart = restart
        self.retry = .25

        self._buffer = bytearray()
        self._binary = False

    def at_eof(self):
        return self.reader.at_eof()

    def clear(self):
        self._buffer.clear()
        self._binary = False

    def _read(self):
        """Immediately extract inner buffer."""
        if not self._buffer:
            return b'', False

        ret = bytes(self._buffer), self._binary
        self.clear()

        if self.logger:
            self.logger.write(ret[0])
        return ret

    async def read(self, nowait=False) -> tuple[bytes, bool]:
        """
        Get a reply.

        If a printable message is being process, it is always returned at the
        end of newline, or at the beginning of the first unprintable char
        (`>= 0x80`).

        If a binary message is being process, it is always returned at the
        end of :attr:`SerialMux.delimiter`, or no longer than
        :attr:`SerialMux.restart`. User should check whether it is a valid
        reply.

        :return: Reply, and whether it is binary (non-printable).
        """
        if self.reader.at_eof():
            raise EOFError

        while True:
            if nowait and not self.reader._buffer:  # type: ignore
                break

            if self.reader.at_eof():
                break

            # StreamReader.read() does not emit real read() call; it simply
            # extracts from its buffer
            s = await self.reader.read(1)
            if not s:
                # EOF read
                break
            c = s[0]

            if c >= 0x80:
                if self._buffer and not self._binary:
                    # binary message starts without newline
                    ret = self._read()
                    self._buffer.append(c)
                    self._binary = True
                    return ret
                self._binary = True

            self._buffer.append(c)

            if self._binary:
                if c == self.delimiter:
                    break
                if self.restart is not None and \
                        len(self._buffer) >= self.restart:
                    break
            else:
                # if printable, ignore restart setting and read everything
                if c == 0xa:
                    break
        return self._read()

    @overload
    async def wait(
        self,
        target: bytes | bytearray | memoryview | Callable[[bytes], bool],
        superfluous: None = None) -> Literal[True]: ...

    @overload
    async def wait(
        self,
        target: bytes | bytearray | memoryview | Callable[[bytes], bool],
        superfluous: int) -> bool: ...

    async def wait(
            self,
            target: bytes | bytearray | memoryview | Callable[[bytes], bool],
            superfluous: int | None = None):
        """
        Wait for specified message in serial port.

        :param target: target message
        :param superfluous: number of allowed superfluous messages before
            ``target``
        :return: `True` if message was found, `False` if message flooding.
        """
        ret = False
        i = 0
        while True:
            msg, binary = await self.read()
            if target(msg) if callable(target) else msg == target:
                ret = True
                break

            if superfluous is not None and i >= superfluous:
                break
            i += 1
        return ret

    async def communicate(
            self, request: 'ReadableBuffer',
            want: Callable[[bytes], bool] | None = None):
        """Send frame and wait for reply."""
        # discard everything in reader
        while (await self.read(True))[0]:
            pass
        self._read()

        i = 0
        while True:
            self.writer.write(memoryview(request))
            # await self.writer.drain()

            try:
                async with asyncio.timeout(self.retry):
                    while True:
                        reply, binary = await self.read()
                        if want is None or want(reply):
                            return reply
            except asyncio.TimeoutError:
                pass

            i += 1
            _logger.warning(f'retransmitting {i}...')
