#!/usr/bin/env python3

from enum import IntEnum
from typing import NamedTuple

from utils.typing_ext import *


def uint32(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset:offset + 4], 'little')


class Memcpy(NamedTuple):
    addr: int
    size: int
    data: Buffer

    @property
    def end(self):
        return self.addr + self.size

    def __bytes__(self):
        return bytes(self.data)

    def __repr__(self):
        return f'{type(self).__name__}(addr={self.addr:#x}, size={self.size:#x}, data={self.data!r})'

    @classmethod
    def cut(cls, addr: int, size: int, data: Buffer):
        return cls(addr, size, memoryview(data)[addr:addr + size])

    @classmethod
    def cuts(cls, addr: int, size: int, data: Buffer):
        view = memoryview(data)
        return [
            cls(addr + i * size, size, view[addr + i * size:addr + (i + 1) * size])
            for i in range((len(view) - addr) // size)
        ]


class BootEnc(IntEnum):
    NO_ENC = 0x3c78962d


class OTPID(IntEnum):
    NORMAL = 0x2a13c812
    SB = 0x83855248


class BootParam(NamedTuple):
    head: Memcpy
    aux: Memcpy
    asc: Memcpy | None
    boot: Memcpy
    regs: list[Memcpy]
    extra_size: int = 0

    boot_enc_flag: int = 0
    aux_enc_flag: int = 0
    "%OTPID"
    multi_param: bool = False
    boot_store_addr: int = 0

    @classmethod
    def from_image_v1(cls, image: bytes):
        boot_enc_flag = uint32(image, 0x210)
        aux_enc_flag = uint32(image, 0x40c)
        multi_param = uint32(image, 0x2fe0) != 0
        boot_store_addr = uint32(image, 0x2fec)

        assert uint32(image, 0x214) == 0x3000

        head = Memcpy.cut(0, 0x3000, image)
        aux = Memcpy.cut(head.end, uint32(image, 0x218), image)
        boot = Memcpy.cut(aux.end, uint32(image, 0x408), image)
        regs = Memcpy.cuts(
            uint32(image, 0x2fe4), uint32(image, 0x2fe8), image)
        if aux_enc_flag == OTPID.SB:
            extra_size = uint32(image, 0x410)
            if extra_size > 0x2a00:
                raise ValueError(f'invalid v1 extra area size {extra_size:#x}')

        return cls(
            head, aux, None, boot, regs, extra_size,
            boot_enc_flag, aux_enc_flag, multi_param, boot_store_addr
        )

        #if (ca or sysid == 0x19060810) and not multi_param:
        #    raise ValueError('invalid v1 multi_param')
        #tee = sysid == 0x19060810

    @classmethod
    def from_image_v2(cls, image: bytes):
        image = memoryview(image)[0x10000:]

        boot_enc_flag = uint32(image, 0x210)
        aux_enc_flag = uint32(image, 0x40c)
        multi_param = uint32(image, 0x2fe0) != 0
        boot_store_addr = uint32(image, 0x2fec)

        head = Memcpy.cut(0, 0x3000, image)
        aux = Memcpy.cut(head.end, uint32(image, 0x214), image)
        asc = Memcpy.cut(aux.end, uint32(image, 0x218), image)
        boot = Memcpy.cut(asc.end, uint32(image, 0x2fe4) - asc.end, image)
        regs = Memcpy.cuts(boot.end, uint32(image, 0x2fe8), image)

        return cls(
            head, aux, boot, boot, regs, 0,
            boot_enc_flag, aux_enc_flag, multi_param, boot_store_addr
        )

    @classmethod
    def from_image_v3(cls, image: bytes):
        boot_enc_flag = uint32(image, 0x10210)
        aux_enc_flag = uint32(image, 0x428)
        multi_param = True
        boot_store_addr = uint32(image, 0x2fec)

        head = Memcpy.cut(0, 0x3000, image)
        aux = Memcpy.cut(head.end, uint32(image, 0x214), image)
        asc = Memcpy.cut(aux.end, uint32(image, 0x218), image)
        boot = Memcpy.cut(asc.end, uint32(image, 0x408), image)
        regs = Memcpy.cuts(boot.end, uint32(image, 0x42c), image)

        return cls(
            head, aux, boot, boot, regs, 0,
            boot_enc_flag, aux_enc_flag, multi_param, boot_store_addr
        )

    @classmethod
    def from_image_v4(cls, image: bytes):
        boot_enc_flag = uint32(image, 0x210)
        if boot_enc_flag != BootEnc.NO_ENC:
            image = memoryview(image)[0x10000:]

        aux_enc_flag = uint32(image, 0x428)
        multi_param = True
        boot_store_addr = uint32(image, 0x2fec)

        head = Memcpy.cut(0, 0x3000, image)
        aux = Memcpy.cut(head.end, uint32(image, 0x214), image)
        asc = Memcpy.cut(aux.end, uint32(image, 0x218), image)
        boot = Memcpy.cut(asc.end, uint32(image, 0x408), image)
        regs = Memcpy.cuts(boot.end, uint32(image, 0x42c), image)

        return cls(
            head, aux, boot, boot, regs, 0,
            boot_enc_flag, aux_enc_flag, multi_param, boot_store_addr
        )

    @classmethod
    def parse(cls, version: int, image: bytes):
        if version == 1:
            return cls.from_image_v1(image)
        elif version == 2:
            return cls.from_image_v2(image)
        elif version == 3:
            return cls.from_image_v3(image)
        elif version == 4:
            return cls.from_image_v4(image)
        else:
            raise NotImplementedError('boot param version not supported')


def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description='Parse fastboot.bin.')
    parser.add_argument(
        'version', type=int,
        help='boot param version')
    parser.add_argument(
        'bootimg', metavar='fastboot.bin', type=argparse.FileType('rb'),
        help='fastboot.bin to use')

    args = parser.parse_args()

    image = BootParam.parse(args.version, args.bootimg.read())
    if not image:
        print('Boot param version not supported', file=sys.stderr)
        return 1

    print(image)

    return 0


if __name__ == '__main__':
    exit(main())
