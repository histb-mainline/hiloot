#!/usr/bin/env python3

from enum import IntEnum
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer


__all__ = ['Memcpy', 'KeyRights', 'OTPID', 'BootParamError', 'BootParam']


def uint32(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset:offset + 4], 'little')


class Memcpy(NamedTuple):
    addr: int
    "destination address"
    size: int
    "data size"
    data: 'ReadableBuffer'
    "data"

    def __bool__(self):
        """
        Test if the region contains data (all bytes are NOT the same).

        Note this is different from `bool(self.size)`.
        """
        if not self.size:
            return False
        view = memoryview(self.data)
        b = view[0]
        return any(x != b for x in view)

    def __bytes__(self):
        return bytes(self.data)

    def __len__(self):
        return self.size

    def __repr__(self):
        return '{1}(addr={0.addr:#x}, size={0.size:#x}, data={0.data!r})' \
            .format(self, type(self).__name__)

    def __getitem__(self, s: slice):
        view = memoryview(self.data)[s]
        return type(self)(self.addr + (s.start or 0), len(view), view)

    @property
    def end(self):
        return self.addr + self.size

    @classmethod
    def cut(cls, addr: int, size: int, data: 'ReadableBuffer', offset=0):
        view = memoryview(data)
        if size < 0 or addr < 0 or addr + size > len(view):
            raise ValueError
        return cls(addr + offset, size, view[addr:addr + size])

    @classmethod
    def cuts(cls, addr: int, size: int, data: 'ReadableBuffer', offset=0):
        view = memoryview(data)
        if size < 0 or addr < 0 or addr + size > len(view):
            raise ValueError
        return [
            cls(i + offset, size, view[i:i + size])
            for i in range(addr, len(view), size)]


class KeyRights(IntEnum):
    __slots__ = ()

    TYPE_1 = 0x3c78962d


class FlashBootEnc(IntEnum):
    __slots__ = ()

    TYPE_1 = 0x3c7896e1


class OTPID(IntEnum):
    __slots__ = ()

    NORMAL = 0x2a13c812
    SB = 0x83855248


class BootParamError(Exception):
    __slots__ = ()


class BootParam(NamedTuple):
    head: Memcpy
    aux: Memcpy
    asc: Memcpy
    unchecked: Memcpy
    boot: Memcpy
    regs: list[Memcpy]

    # do not use enum types here, since we may encounter unknown values

    # we don't know the exact meaning of these parameters, and these names are
    # simply wild guesses
    extra_size: int = 0
    key_rights: int = 0
    flash_boot_enc_flag: int = 0
    aux_enc_flag: int = 0
    ":class:`OTPID`"
    multi_param: bool = False
    boot_store_addr: int = 0

    offset: int = 0
    "advance length in source file"

    def __repr__(self):
        return (
            '{1}(head={0.head!r}, aux={0.aux!r}, asc={0.asc!r}, '
            'unchecked={0.unchecked!r}, boot={0.boot!r}, regs={0.regs!r}, '
            'extra_size={0.extra_size:#x}, key_rights={0.key_rights:#x}, '
            'flash_boot_enc_flag={0.flash_boot_enc_flag:#x}, '
            'aux_enc_flag={0.aux_enc_flag:#x}, multi_param={0.multi_param!r}, '
            'boot_store_addr={0.boot_store_addr:#x}, offset={0.offset:#x})'
            .format(self, type(self).__name__))

    def __iter__(self):
        yield 'head', self.head
        yield 'aux', self.aux
        yield 'asc', self.asc
        yield 'unchecked', self.unchecked
        yield 'boot', self.boot
        for reg in self.regs:
            yield 'reg', reg

    def last_pos(self):
        """Return the last position of the boot image where contents are."""
        return max((region.end for _, region in self if region), default=0)

    @classmethod
    def parse_v1(cls, image: 'ReadableBuffer'):
        view = memoryview(image)

        aux_addr = uint32(view, 0x214)
        if aux_addr != 0x3000:
            raise BootParamError(
                f'v1 aux addr should be 0x3000, got {aux_addr:#x}')

        key_rights = uint32(view, 0x210)
        flash_boot_enc_flag = uint32(view, 0x40c)
        aux_enc_flag = uint32(view, 0x40c)
        multi_param = bool(uint32(view, 0x2fe0))
        boot_store_addr = uint32(view, 0x2fec)
        extra_size = 0
        if aux_enc_flag == OTPID.SB:
            extra_size = uint32(view, 0x410)
            if extra_size > 0x2a00:
                raise BootParamError(
                    f'invalid v1 extra area size {extra_size:#x}')

        head = Memcpy.cut(0, 0x3000, view)
        aux = Memcpy.cut(head.end, uint32(view, 0x218), view)
        asc = Memcpy.cut(aux.end, 0, view)
        unchecked = Memcpy.cut(asc.end, 0x1000, view)
        boot = Memcpy.cut(
            unchecked.end, uint32(view, 0x408) - unchecked.size, view)
        regs = Memcpy.cuts(
            uint32(view, 0x2fe4), uint32(view, 0x2fe8), view)

        return cls(
            head, aux, asc, unchecked, boot, regs, extra_size,
            key_rights, flash_boot_enc_flag, aux_enc_flag, multi_param,
            boot_store_addr)

    @classmethod
    def parse_v2(cls, image: 'ReadableBuffer'):
        offset = 0x10000
        view = memoryview(image)[offset:]

        key_rights = uint32(view, 0x210)
        flash_boot_enc_flag = uint32(view, 0x40c)
        aux_enc_flag = uint32(view, 0x2fc8)
        multi_param = bool(uint32(view, 0x2fe0))
        boot_store_addr = uint32(view, 0x2fec)

        head = Memcpy.cut(0, 0x3000, view, offset)
        aux = Memcpy.cut(head.end, uint32(view, 0x214), view, offset)
        asc = Memcpy.cut(aux.end, uint32(view, 0x218), view, offset)
        unchecked = Memcpy.cut(asc.end, 0x1000, view, offset)
        boot = Memcpy.cut(
            unchecked.end, uint32(view, 0x2fe4) - unchecked.end, view, offset)
        regs = Memcpy.cuts(boot.end, uint32(view, 0x2fe8), view, offset)

        return cls(
            head, aux, asc, unchecked, boot, regs, 0,
            key_rights, flash_boot_enc_flag, aux_enc_flag, multi_param,
            boot_store_addr)

    @classmethod
    def parse_v3(cls, image: 'ReadableBuffer'):
        view = memoryview(image)

        key_rights = uint32(view, 0x210)
        flash_boot_enc_flag = uint32(view, 0x40c)
        aux_enc_flag = uint32(view, 0x428)
        multi_param = True
        boot_store_addr = uint32(view, 0x2fec)

        head = Memcpy.cut(0, 0x3000, view)
        aux = Memcpy.cut(head.end, uint32(view, 0x214), view)
        asc = Memcpy.cut(aux.end, uint32(view, 0x218), view)
        unchecked = Memcpy.cut(asc.end, 0x1000, view)
        boot = Memcpy.cut(
            unchecked.end, uint32(view, 0x408) - unchecked.size, view)
        regs = Memcpy.cuts(boot.end, uint32(view, 0x42c), view)

        return cls(
            head, aux, asc, unchecked, boot, regs, 0,
            key_rights, flash_boot_enc_flag, aux_enc_flag, multi_param,
            boot_store_addr)

    @classmethod
    def parse_v4(cls, image: 'ReadableBuffer'):
        view = memoryview(image)

        key_rights = uint32(view, 0x210)
        offset = 0 if key_rights == KeyRights.TYPE_1 else 0x10000
        view = view[offset:]

        flash_boot_enc_flag = uint32(view, 0x40c)
        aux_enc_flag = uint32(view, 0x428)
        multi_param = True
        boot_store_addr = uint32(view, 0x2fec)

        head = Memcpy.cut(0, 0x3000, view, offset)
        aux = Memcpy.cut(head.end, uint32(view, 0x214), view, offset)
        asc = Memcpy.cut(aux.end, uint32(view, 0x218), view, offset)
        unchecked = Memcpy.cut(asc.end, 0x1000, view, offset)
        boot = Memcpy.cut(
            unchecked.end, uint32(view, 0x408) - unchecked.size, view, offset)
        regs = Memcpy.cuts(boot.end, uint32(view, 0x42c), view, offset)

        return cls(
            head, aux, asc, unchecked, boot, regs, 0,
            key_rights, flash_boot_enc_flag, aux_enc_flag, multi_param,
            boot_store_addr)

    @classmethod
    def parse(cls, version: int, image: 'ReadableBuffer'):
        if version == 1:
            return cls.parse_v1(image)
        elif version == 2:
            return cls.parse_v2(image)
        elif version == 3:
            return cls.parse_v3(image)
        elif version == 4:
            return cls.parse_v4(image)
        else:
            raise BootParamError(f'boot param version {version} unknown')


def main():
    import argparse
    import os
    import sys

    def dir_path(s):
        if not os.path.isdir(s):
            raise NotADirectoryError(s)
        return s

    parser = argparse.ArgumentParser(
        description='Parse, split, or shrink fastboot.bin.')
    parser.add_argument(
        '--dd', action='store_true',
        help="generate 'dd' commands")
    parser.add_argument(
        '-s', '--split', metavar='DIR', type=dir_path,
        help='output dir of split files (empty regions are skipped)')
    parser.add_argument(
        '-o', '--output', metavar='PATH', type=argparse.FileType('wb'),
        help='output path of shrinked file')
    parser.add_argument(
        'bootimg', metavar='fastboot.bin', type=argparse.FileType('rb'),
        help='fastboot.bin to use')
    parser.add_argument(
        'version', type=int, help='boot param version')

    args = parser.parse_args()

    image = args.bootimg.read()
    try:
        params = BootParam.parse(args.version, image)
    except BootParamError as e:
        print(f'Error when parsing input file: {e}', file=sys.stderr)
        return 1

    if not args.dd:
        def print_memcpy(name: str, region: Memcpy, offset=0):
            if not region:
                return
            print(
                f'{name}: {offset + region.addr:#8x}, '
                f'{offset + region.end:#8x}  ({region.size:#7x})')

        print(
            'Extra size          : {0.extra_size:#x}\n'
            'Key rights          : {0.key_rights:#x}\n'
            'Flash boot enc flag : {0.flash_boot_enc_flag:#x}\n'
            'Aux enc flag        : {0.aux_enc_flag:#x}\n'
            'Support multi param : {0.multi_param!r}\n'
            'Boot store addr     : {0.boot_store_addr:#010x}'.format(params))
        print_memcpy('Head            ', params.head, params.offset)
        print_memcpy('Auxiliary code  ', params.aux, params.offset)
        print_memcpy('ACPU start code ', params.asc, params.offset)
        print_memcpy('Unchecked area  ', params.unchecked, params.offset)
        print_memcpy('Bootloader      ', params.boot, params.offset)
        for i, reg in enumerate(params.regs):
            print_memcpy(f'Reg param {i}', reg, params.offset)

    if args.split or args.dd:
        for name, region in params:
            if not region:
                continue
            filename = f'{name}@{region.addr:x}.bin'
            if args.split:
                with open(os.path.join(args.split, filename), 'wb') as f:
                    f.write(region.data)
            if args.dd:
                print(
                    '{cmd} if={src} of={dst} skip={addr} count={size}\n'
                    '{cmd} conv=notrunc if={dst} of={src} seek={addr} count={size}\n'
                    .format(
                        cmd='dd iflag=skip_bytes,count_bytes',
                        src=args.bootimg.name, dst=filename,
                        addr=region.addr, size=region.size))

    file_end = params.last_pos()

    if not args.output:
        if file_end < len(image):
            print(
                '\nThis file can be shrinked to {0:#x} ({0}) bytes '
                'from {1:#x} ({1}) bytes.'.format(file_end, len(image)))
    else:
        args.output.write(image[:file_end])
        if file_end < len(image):
            print(
                '\nFile shrinked to {0:#x} ({0}) bytes from {1:#x} ({1}) bytes.'
                .format(file_end, len(image)))
        else:
            print('\nFile is {0:#x} ({0}) bytes intact.'.format(len(image)))

    return 0


if __name__ == '__main__':
    exit(main())
