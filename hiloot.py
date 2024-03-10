#!/usr/bin/env python3

import binascii
from enum import IntEnum
from dataclasses import astuple, dataclass
import logging
import struct
import time
import serial
import serial.tools.list_ports
import sys

from typing import Any, Callable, ClassVar, SupportsBytes

from utils.serial import *
from utils.typing_ext import *
import bootimg


logger = logging.getLogger(__name__)


def printerr(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class Payloadx2I:
    __slots__ = ()

    STRUCT: ClassVar[struct.Struct] = struct.Struct('>B2I')

    def __bytes__(self):
        t = astuple(self)  # type: ignore
        return self.STRUCT.pack(1, t[0], t[1])

    @classmethod
    def from_bytes(cls, data: bytes):
        _, arg1, arg2 = cls.STRUCT.unpack(data)
        return cls(arg1, arg2)


@dataclass(frozen=True)
class TypeRequest(Payloadx2I):
    """The payload of request Type frame."""

    use_onboard_fastboot: bool
    "(notBareBurn)"
    to_ddr: bool
    "%True if flash type is DDR (ddrOrFlash)"


@dataclass(frozen=True)
class HeadRequest(Payloadx2I):
    """The payload of Head frame."""

    size: int
    "data size"
    addr: int
    "load address"


@dataclass(frozen=True)
class ChipID:
    """The payload of reply Type frame."""

    sysid: int
    chipid: int
    ca: bool
    tee: bool
    multiform: bool

    STRUCT: ClassVar[struct.Struct] = struct.Struct('>B2I')

    def __str__(self):
        f: list[str] = []
        if self.ca:
            f.append('ca')
        if self.tee:
            f.append('tee')
        if self.multiform:
            f.append('multiform')
        flags = f', {" ".join(f)}' if f else ''
        return (
            f'Hi{self.sysid >> 16:X}v{self.sysid & 0xffff:X}, '
            f'chip {self.chipid:X}{flags} '
            f'(0x{bytes(self).hex()})'
        )

    def __bytes__(self):
        flags = 0
        if self.ca:
            flags |= 1
        if self.tee:
            flags |= 2
        if self.multiform:
            flags |= 4
        return self.STRUCT.pack(flags, self.chipid, self.sysid)

    @classmethod
    def from_bytes(cls, data: ByteLike):
        r"""
        Parse bytes into ChipID.

        >>> ChipID.from_bytes(b'\x08\x00\x00\x00\x037\x98\x03\x00').chipid
        3
        """
        flags, chipid, sysid = cls.STRUCT.unpack(bytes(data))
        ca = bool(flags & 1)
        tee = bool(flags & 2)
        multiform = bool(flags & 4)
        return cls(sysid, chipid, ca, tee, multiform)


class FrameType(IntEnum):
    TYPE = 0xbd
    "get board info"
    HEAD = 0xfe
    "set up load address and data length"
    DATA = 0xda
    "send data"
    TAIL = 0xed
    "finish sending data"
    BOARD = 0xce
    "get board variant"


@dataclass(frozen=True)
class Frame:
    """HiSi variant of XMODEM."""

    type: int
    "%FrameType"
    seq: int
    """
    auto-incremented sequence number when sending files (FrameType.HEAD,
    FrameType.DATA, FrameType.TAIL), otherwise set to 0
    """
    payload: Buffer

    STRUCT: ClassVar[struct.Struct] = struct.Struct('>3B')

    def __bytes__(self):
        r"""
        Pack a request frame.

        >>> bytes(Frame(0xbd, 0, b'\x01\x00\x00\x00\x00\x00\x00\x00\x01'))
        b'\xbd\x00\xff\x01\x00\x00\x00\x00\x00\x00\x00\x01p^'
        """
        buf = self.STRUCT.pack(self.type, self.seq & 0xff, ~self.seq & 0xff)
        buf += bytes(self.payload)
        return buf + binascii.crc_hqx(buf, 0).to_bytes(2, 'big')

    @classmethod
    def from_bytes(cls, buf: Buffer):
        r"""
        Parse reply frame.

        >>> Frame.parse(b'\xbd\x00\x00\x08\x00\x00\x00\x037\x98\x03\x00\xd8z')
        (189, 0, b'\x08\x00\x00\x00\x037\x98\x03\x00')
        """
        view = memoryview(buf)

        chsum = int.from_bytes(view[-2:], 'big')
        if chsum != binascii.crc_hqx(view[:-2], 0):
            raise ValueError('invalid checksum')

        type_: int
        seq: int
        type_, seq, _ = cls.STRUCT.unpack(view[:3])

        return cls(type_, seq, view[3:-2])


class DeviceError(Exception):
    pass


class Device:
    """Send or receive data from HiSi device."""

    def __init__(self, ser: serial.Serial, timeout=1., ser_output=False):
        self.ser = ser
        "serial port to the device"
        self.ser_logger: Callable[[bytes], Any] | None = \
            TerminalLogger() if ser_output else None
        "logger for serial output"

        self.timeout = timeout
        "timeout for frame reading (<0: no timeout)"
        self.resend = 3
        "number of times to resend a frame (<0: no limit)"

    def connect(self, timeout=-1):
        """
        Wait for the device to be power on.

        :returns: %True if device is powered on, %False if message flooding.
        """
        return waitser(
            self.ser, b'Bootrom start\r\n', self.ser_logger, timeout=timeout)

    def communicate(self, request: Buffer):
        """Send frame and wait for frame reply."""
        return queryser(
            self.ser, request, self.ser_logger, timeout=self.timeout,
            resend=self.resend)

    def query(self, type: int, seq: int, payload: ByteLike, reply_with: int):
        reply = self.communicate(bytes(Frame(type, seq, bytes(payload))))
        if not reply:
            raise RuntimeError('no reply')
        frame = Frame.from_bytes(reply)
        if frame.type != reply_with:
            raise RuntimeError(f'invalid reply type {frame.type:#04x}')
        return frame

    def send(self, type: int, seq: int, payload: ByteLike):
        reply = self.communicate(bytes(Frame(type, seq, bytes(payload))))
        if reply:
            raise RuntimeError('unexpected reply')

    def get_chip(self):
        """Get the SoC ID."""
        return ChipID.from_bytes(bytes(self.query(
            FrameType.TYPE, 0, TypeRequest(False, True), FrameType.TYPE
        ).payload))

    def get_board(self):
        """Get the board reg file index."""
        return int.from_bytes(memoryview(self.query(
            FrameType.BOARD, 0, b'\1' + b'\0' * 8, FrameType.BOARD
        ).payload)[:4], 'little')

    def load(
            self, addr: int, size: int, data: Buffer, name: str='data',
            print_user: Callable[[str], Any]=printerr):
        """Send %data to device memory %addr."""
        if not size:
            return

        print_user(f'Send {name} to {addr:#x}, length {size:#x}...')
        self.send(FrameType.HEAD, 0, HeadRequest(size, addr))

        view = memoryview(data)
        n = (size + 1023) // 1024
        for i in range(n):
            print_user(f'{i + 1:2d}/{n:2d}...')
            src = 1024 * i
            chunk = view[src:src + 1024] if src + 1024 <= size else \
                    view[src:size]  # + b'\x00' * (src + 1024 - size)
            self.send(FrameType.DATA, i + 1, chunk)

        self.send(FrameType.TAIL, n + 1, b'')
        print_user(f'Done sending {name}.')

    def load_region(
            self, param: bootimg.Memcpy, name: str='data',
            print_user: Callable[[str], Any]=printerr):
        return self.load(param.addr, param.size, param.data, name, print_user)

    def boot(
            self, image: bytes, print_user: Callable[[str], Any]=printerr,
            timeout=-1):
        """Boot HiSi device via serial port."""
        print_user('Please power cycle your device.\nWait device (re)booting...')
        if not self.connect(timeout):
            raise DeviceError('serial message flooding')
        print_user('Device is powered on')

        chip = self.get_chip()
        print_user('Board info: %s' % chip)
        params = bootimg.BootParam.parse(chip.chipid, image)

        reg_i = self.get_board()
        print_user('Board use reg #%d' % reg_i)
        if reg_i >= len(params.regs):
            raise RuntimeError('board reg #%d not found in bootimg' % reg_i)

        self.load_region(params.head, 'head data', print_user)

        self.load_region(params.aux, 'auxiliary code', print_user)

        if params.aux_enc_flag == bootimg.OTPID.NORMAL:
            if chip.ca:
                time.sleep(.5)
            self.load_region(
                bootimg.Memcpy.cut(params.boot.end, 0x2a00, image),
                'extra area', print_user)
        elif params.aux_enc_flag == bootimg.OTPID.SB and params.extra_size:
            time.sleep(1)
            self.load_region(
                bootimg.Memcpy.cut(
                    params.boot.end + params.extra_size * reg_i,
                    params.extra_size, image),
                'extra area', print_user)

        self.load_region(params.regs[reg_i], 'reg', print_user)

        self.load(0, len(image), image, 'bootimg', print_user)

        if chip.chipid in (2, 3) and chip.ca and params.multi_param and params.asc:
            asc_data = memoryview(params.asc.data)
            self.load(
                params.asc.addr, 0x400, asc_data[:0x400],
                'ACPU start code (1)', print_user)
            self.load(
                params.asc.addr, params.asc.size - 0x400, asc_data[0x400:],
                'ACPU start code (2)', print_user)


def main():
    import argparse

    try:
        from utils.coloredlog import setColoredLogger
    except ImportError:
        setColoredLogger = lambda *args, **kwargs: None

    parser = argparse.ArgumentParser(
        description='Boot LibBootrom-supported HiStb devices via serial port.')
    parser.add_argument(
        '-p', '--port', metavar='PATH', dest='serial_path',
        help='serial port to use (default: auto detect)')
    parser.add_argument(
        '--rate', metavar='RATE', dest='bandurate', default=115200, type=int,
        help='serial bandurate (default: 115200)')
    parser.add_argument(
        '--timeout', metavar='TIME', default=1., type=float,
        help='serial communication timeout in second (default: 1)')
    parser.add_argument(
        '-d', '--debug', action='store_true',
        help='debug')
    parser.add_argument(
        'bootimg', metavar='fastboot.bin', type=argparse.FileType('rb'),
        help='fastboot.bin to use')

    args = parser.parse_args()

    logger = logging.getLogger(__name__)
    setColoredLogger(logger, args.debug)

    if args.serial_path:
        serial_path = args.serial_path
    else:
        sers = [
            info for info in serial.tools.list_ports.comports()
            if info.subsystem == 'usb-serial'
        ]
        if len(sers) == 0:
            printerr('Error: No serial ports detected, use "-p PATH" to specify the path manually')
            return 253
        elif len(sers) > 1:
            msgs = ['Error: Multiple serial ports found, use "-p PATH" to specify one to use:']
            for ser in sers:
                msgs.append(f'  {ser.name}: {ser.device_path}')
            printerr('\n'.join(msgs))
            return 253
        serial_path = sers[0].device
        printerr('Auto-select USB serial port: %s' % serial_path)

    try:
        ser = serial.Serial(
            serial_path, args.bandurate, timeout=args.timeout / 4)
        logger.info('Use serial port %s @ %d', ser.name, args.bandurate)
        dev = Device(ser, args.timeout, args.debug)
        dev.boot(args.bootimg.read(), printerr)
    except (DeviceError, NotImplementedError) as e:
        printerr('Error: %s' % e)
        return 1
    except serial.SerialException as e:
        printerr('Error: Serial port error, %s' % e)
        return 254
    except KeyboardInterrupt:
        printerr('\nError: Keyboard interrupt')
        return 255

    printerr('Bootstrap end.\n=========================================')

    while True:
        readser(dev.ser, dev.ser_logger)

    return 0


if __name__ == '__main__':
    exit(main())
