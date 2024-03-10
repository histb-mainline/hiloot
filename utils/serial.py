from enum import IntEnum
import serial
import sys

from typing import *
from utils.typing_ext import Buffer


__all__ = ['TerminalLogger', 'readser', 'waitser', 'queryser']


class TerminalLogger:
    "Log serial port output to console."

    def __init__(self, out: TextIO=sys.stderr):
        self.line_cont = False
        self.out = out

    def __call__(self, msg: bytes):
        self.out.flush()
        self.out.buffer.flush()
        if msg[0] < 0x80:
            if not self.line_cont:
                self.out.buffer.write(b'-> ')
            self.out.buffer.write(msg)
            self.out.buffer.flush()
            self.line_cont = msg[-1] != b'\n'[0]
        else:
            self.out.write('-> ')
            self.out.write(repr(msg))
            self.out.write('\n')
            self.out.flush()
            self.line_cont = False


class ReplyState(IntEnum):
    OK = 0xaa
    "no error found"
    CKSUM_MISMATCHED = 0x55
    "checksum mismatched"


def readser(
        ser: serial.Serial,
        logger: Callable[[bytes], Any] | None=None) -> tuple[bytes, bool]:
    """
    Read string or frame from a serial port.

    If a string is received, it is eqivalent to ser.readline().
    """
    msg = ser.read(1)
    if not msg:
        return msg, False

    frame_got = msg[0] >= 0x80
    if not frame_got:
        if msg != b'\n':
            msg += ser.readline()
    else:
        # we just read as much as possible when frame is received
        buf = bytearray(msg)
        while True:
            if msg == b'\xaa' or msg == b'\x55':
                break
            msg = ser.read(1)
            if not msg:
                break
            buf.extend(msg)
        msg = bytes(buf)

    if logger:
        logger(msg)
    return msg, frame_got


def waitser(
        ser: serial.Serial, msg: bytes,
        logger: Callable[[bytes], Any] | None=None, /, timeout=-1):
    """
    Wait for specified message in serial port.

    :param timeout: timeout for read operations (<0: no timeout)
    :returns: %True if device is powered on, %False if message flooding.
    """
    poll_max = timeout / ser.timeout if timeout >= 0 and ser.timeout else -1

    ret = False
    superfluous_i = 0
    poll_i = 0
    while True:
        msg = readser(ser, logger)[0]
        if msg == b'Bootrom start\r\n':
            ret = True
            break

        if msg:
            if superfluous_i >= 50:
                break
            superfluous_i += 1

        if 0 <= poll_max <= poll_i:
            break
        poll_i += 1

    return ret


def queryser(
        ser: serial.Serial, request: Buffer,
        logger: Callable[[bytes], Any] | None=None, /, timeout=1., resend=3):
    """
    Send frame and wait for frame reply.

    :param timeout: timeout for read operations (<0: no timeout)
    :param resend: number of times to resend a frame (<0: no limit)
    :returns: non-empty reply frame data (with ACK)
    :raises RuntimeError: If reply state is not OK.
    :raises TimeoutError: If no frame received.
    """
    if not request:
        return memoryview(b'')

    poll_max = timeout / ser.timeout if timeout >= 0 and ser.timeout else -1

    frame_got = False
    retry_i = 0
    while True:
        ser.write(request)
        ser.flush()

        poll_i = 0
        while True:
            reply, frame_got = readser(ser, logger)
            if frame_got:
                state = reply[-1]
                if state != ReplyState.OK:
                    raise RuntimeError(f'invalid reply state {state:#04x}')
                break

            if 0 <= poll_max <= poll_i:
                break
            poll_i += 1

        if frame_got:
            break

        if 0  <= resend <= retry_i:
            break
        retry_i += 1

    if not frame_got:
        raise TimeoutError('timeout or too many serial messages')

    return memoryview(reply)[:-1]
