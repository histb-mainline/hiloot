#!/usr/bin/env python3

from collections import OrderedDict
from datetime import datetime
from enum import IntEnum
from io import BufferedReader, BytesIO
from typing import TYPE_CHECKING, BinaryIO, Mapping, NamedTuple
import warnings

if TYPE_CHECKING:
    from _typeshed import SupportsRead


__all__ = ['Register', 'RegModuleType', 'RegModule', 'RegBinFormat', 'RegBin']


def mustread(buf: 'SupportsRead[bytes]', size=1):
    if not size:
        return b''

    data = buf.read(size)
    if len(data) < size:
        raise ValueError('not enough data')
    return data


def readuntil(buf: 'SupportsRead[bytes]', delimiter=0, including=False):
    ret = bytearray()
    while True:
        data = mustread(buf)
        if data[0] == delimiter:
            if including:
                ret.append(data[0])
            break
        ret.append(data[0])
    return bytes(ret)


def mustwithin(buf: BinaryIO, size: int):
    if not size:
        return

    start = buf.tell()
    while True:
        yield
        run = buf.tell() - start
        if run > size:
            raise ValueError('buffer overrun')
        elif run == size:
            break


def writememn(buf: BinaryIO, b: bytes, n: int):
    ret = buf.write(b[:n])
    if ret < n:
        buf.write(b'\0' * (n - ret))
    return n


def writestrn(buf: BinaryIO, s: str, n: int):
    writememn(buf, s.encode(), n - 1)
    buf.write(b'\0')
    return n


def to_enum(s: str | None, default: int = 0):
    if s is None:
        return default
    s = s.lower()
    if s in ['true', 't', 'yes', 'y', '1']:
        return 1
    elif s in ['false', 'f', 'no', 'n', '0']:
        return 0
    else:
        try:
            return int(s, 0)
        except ValueError:
            raise ValueError(f'"{s}" cannot be interrepreted as enum value')


def to_bool(s: str | None, default: bool = False):
    if s is None:
        return default
    return bool(to_enum(s))


class Register(NamedTuple):
    addr: int
    "register address"
    value: int
    "value written to or read from register (0 - 0xffffffff)"
    mask: int
    "mask for register value"
    delay: int
    "delay before operation in us"
    readonly: bool = False
    "perform read operation instead of modify"

    def __repr__(self):
        return (
            '{1}(addr={0.addr:#x}, value={0.value:#x}, mask={0.mask:#x}, '
            'delay={0.delay!r}, readonly={0.readonly!r})'.format(
                self, type(self).__name__))

    @property
    def shift(self):
        return ((self.mask ^ (self.mask - 1)) >> 1).bit_length()

    @property
    def _count(self):
        return self.mask.bit_count()

    @property
    def sftcnt(self):
        if not self.mask:
            raise ValueError('mask cannot be zero')
        if self.mask > 0xffffffff:
            raise ValueError('mask is too large')
        shift = self.shift
        count = self._count
        if (1 << count) - 1 != self.mask >> shift:
            raise ValueError('mask is not a consecutive sequence of bit 1')
        return shift, count

    @property
    def count(self):
        return self.sftcnt[1]

    def to_ini(self):
        ret = [
            f'{self.addr:#010x}',
            f'{self.value:10}' if self.value < 10 else f'{self.value:#10x}',
            f'{self.mask:#10x}' if self.mask != 0xffffffff else f'{"-":>10}',
            f'{self.delay:4}', f'r' if self.readonly else 'w']
        if not self.readonly:
            ret.pop()
            if not self.delay:
                ret.pop()
                if self.mask == 0xffffffff:
                    ret.pop()
        return '  '.join(ret)

    def addr_len_cfg(self, base: int):
        diff = self.addr - base
        if diff < 0 or diff > 0xffff:
            return 4
        elif diff <= 0xff:
            return 1
        else:
            return 2

    def delay_len_v120(self):
        return (self.delay.bit_length() + 7) >> 3

    def value_len_cfg(self):
        mask = self.value
        if self.mask != 0xffffffff:
            mask |= self.mask
        if mask <= 0xff:
            return 1
        elif mask <= 0xffff:
            return 2
        else:
            return 4

    def value_len_v120(self):
        return ((self.value >> self.shift).bit_length() + 7) >> 3

    def delay_len_cfg(self):
        return 2 * ((self.delay + 249) // 250)

    def len_reg(self):
        return 0x10

    def len_cfg(self, base: int):
        value_len = self.value_len_cfg()
        ret = 1 + self.addr_len_cfg(base) + value_len + self.delay_len_cfg()
        if self.mask != 0xffffffff:
            ret += value_len
        return ret

    def len_v120(self):
        return 3 + self.value_len_v120() + self.delay_len_v120()

    def dump_reg(self, stream: BinaryIO, flags: int):
        shift, count = self.sftcnt
        attrs = shift << 11 & 0xf800 | (count - 1) << 3 & 0xf8 | \
            flags << 1 & 0x6 | 1
        if self.readonly:
            attrs <<= 16

        ret = 0
        ret += stream.write(self.addr.to_bytes(4, 'little'))
        ret += stream.write((self.value >> shift).to_bytes(4, 'little'))
        ret += stream.write(self.delay.to_bytes(4, 'little'))
        ret += stream.write(attrs.to_bytes(4, 'little'))
        return ret

    def dump_cfg(self, stream: BinaryIO, base: int):
        if self.mask != 0xffffffff:
            op = 4 if self.readonly else 3
        else:
            op = 2 if self.readonly else 0
        value_len = self.value_len_cfg()
        addr_len = self.addr_len_cfg(base)
        op |= (value_len.bit_length() - 1) << 4
        op |= (addr_len.bit_length() - 1) << 6

        ret = 0
        ret += stream.write(op.to_bytes())
        ret += stream.write((
            self.addr - base if addr_len < 4 else self.addr
        ).to_bytes(addr_len, 'big'))
        ret += stream.write(
            (self.value & (1 << (8 * value_len)) - 1
             ).to_bytes(value_len, 'big'))
        if self.mask != 0xffffffff:
            ret += stream.write(
                (self.mask & (1 << (8 * value_len)) - 1
                 ).to_bytes(value_len, 'big'))
        if self.delay:
            div, mod = divmod(self.delay, 250)
            ret += stream.write(b'\1\xfa' * div)
            if mod:
                ret += stream.write(b'\1')
                ret += stream.write(mod.to_bytes())
        return ret

    def dump_v120(self, stream: BinaryIO):
        shift, count = self.sftcnt

        ret = 0
        ret += stream.write(bytes([
            self.addr & 0xff, self.value_len_v120() << 5 | shift,
            self.delay_len_v120() << 5 | (count - 1)]))
        ret += stream.write(
            (self.value >> shift).to_bytes(self.value_len_v120(), 'big'))
        ret += stream.write(self.delay.to_bytes(self.delay_len_v120(), 'big'))
        return ret

    @classmethod
    def from_ini(cls, obj: str):
        toks = [i for i in obj.split(' ') if i]
        if len(toks) < 1:
            raise ValueError('empty register definition')
        if len(toks) < 2:
            raise ValueError(f'value not specified for register {toks[0]}')

        addr_s = toks[0]
        value_s = toks[1]
        mask_s = toks[2] if len(toks) > 2 else '-'
        delay_s = toks[3] if len(toks) > 3 else '0'
        readonly_s = toks[4] if len(toks) > 4 else ''

        try:
            addr = int(addr_s, 0)
            value = int(value_s, 0)
            mask = 0xffffffff if mask_s == '-' else int(mask_s, 0)
            delay = int(delay_s, 0)
        except ValueError as e:
            raise ValueError(f'non-numeric arguments in register {toks[0]}')
        readonly = readonly_s == 'r'

        return cls(addr, value, mask, delay, readonly)

    @staticmethod
    def has_more_reg(buf: BufferedReader):
        return bool(int.from_bytes(buf.peek(4)[:4]))

    @staticmethod
    def has_more_cfg(buf: BufferedReader):
        return True

    @staticmethod
    def has_more_v120(buf: BufferedReader):
        return bool(int.from_bytes(buf.peek(4)[:4]))

    @classmethod
    def load_reg(cls, buf: BufferedReader):
        data = mustread(buf, 0x10)
        addr = int.from_bytes(data[0x0:0x4], 'little')
        value_sft = int.from_bytes(data[0x4:0x8], 'little')
        delay = int.from_bytes(data[0x8:0xc], 'little')
        attrs = int.from_bytes(data[0xc:0x10], 'little')
        if not attrs:
            warnings.warn(f'no operation specified for {addr:#010x}')

        readonly = not bool(attrs & 0xffff)
        if readonly:
            attrs >>= 16

        shift = (attrs & 0xf800) >> 11
        count_m1 = (attrs & 0xf8) >> 3
        flags = (attrs & 0x6) >> 1  # 1: wakeup, 2: boot

        return cls(
            addr, value_sft << shift, ((2 << count_m1) - 1) << shift, delay,
            readonly), flags

    @classmethod
    def load_cfg(cls, buf: BufferedReader, base: int):
        attrs = mustread(buf)[0]
        op = attrs & 0xf
        if op not in [0, 2, 3, 4]:
            raise ValueError(f'invalid operation {op:#x}')
        addr_len = 1 << ((attrs & 0xc0) >> 6)
        value_len = 1 << ((attrs & 0x30) >> 4)

        addr = int.from_bytes(mustread(buf, addr_len), 'big')
        if addr_len < 4:
            addr += base
        value = int.from_bytes(mustread(buf, value_len), 'big')
        mask = 0xffffffff if op < 3 else int.from_bytes(
            mustread(buf, value_len), 'big')

        return cls(addr, value, mask, 0, op == 2 or op == 4), None

    @classmethod
    def load_v120(cls, buf: BufferedReader, base: int):
        data = mustread(buf, 3)
        addr = base + data[0]
        value_len = (data[1] & 0xe0) >> 5
        shift = data[1] & 0x1f
        delay_len = (data[2] & 0xe0) >> 5
        count_m1 = data[2] & 0x1f

        data = mustread(buf, value_len + delay_len)
        value_sft = int.from_bytes(data[:value_len], 'big')
        delay = int.from_bytes(data[value_len:], 'big')

        return cls(
            addr, value_sft << shift, ((2 << count_m1) - 1) << shift, delay,
            False), None


class RegModuleType(IntEnum):
    __slots__ = ()

    NORMAL = 0
    SPI = 1
    NAND = 2
    EMMC = 3
    SD = 4

    def __str__(self):
        return self.name


class RegModule(NamedTuple):
    """Represent a register table, corresponding to a xlsm worksheet."""
    type: RegModuleType
    "module type, :class:`RegModuleType`"
    boot: bool
    "whether module should be executed in normal boot"
    wakeup: bool
    "whether module should be executed when woken up from standby"
    chip_normal: bool
    "whether module should be executed in non-CA chips"
    chip_ca: bool
    "whether module should be executed in CA chips"
    regs: list[Register]

    def to_ini(self):
        ret = OrderedDict[str, str]()
        ret['type'] = str(self.type).lower()
        ret['boot'] = str(+self.boot)
        ret['wakeup'] = str(+self.wakeup)
        ret['chip_normal'] = str(+self.chip_normal)
        ret['chip_ca'] = str(+self.chip_ca)
        a_regs = ['']
        a_regs.extend(reg.to_ini() for reg in self.regs)
        ret['regs'] = '\n'.join(a_regs)
        return ret

    def base_cfg(self):
        if not self.regs:
            return 0
        # it might be possible that we can use any base, but be safe here
        return min(reg.addr for reg in self.regs) & ~0xff

    def find_block_v120(self, start=0):
        base = self.regs[start].addr & ~0xff
        i = start
        for i in range(start + 1, len(self.regs)):
            if base != self.regs[i].addr & ~0xff:
                i -= 1
                break
        return i + 1

    def len_reg(self):
        return sum(reg.len_reg() for reg in self.regs)

    def len_cfg(self, base: int = -1):
        if base < 0:
            base = self.base_cfg()
        return 8 + sum(reg.len_cfg(base) for reg in self.regs)

    def len_v120(self):
        size = 4
        base = -1
        for reg in self.regs:
            new_base = reg.addr & ~0xff
            if base != new_base:
                base = new_base
                size += 5
            size += reg.len_v120()
        return size

    def dump_reg(self, stream: BinaryIO):
        flags = self.boot << 1 | self.wakeup
        return sum(reg.dump_reg(stream, flags) for reg in self.regs)

    def dump_cfg(self, stream: BinaryIO):
        flags = self.boot << 1 | self.wakeup
        base = self.base_cfg()
        size = self.len_cfg(base)

        ret = 0
        ret += stream.write(flags.to_bytes())
        ret += stream.write(b'\0')
        ret += stream.write((size - 8).to_bytes(2, 'big'))
        ret += stream.write(base.to_bytes(4, 'big'))
        assert ret == 8

        ret += sum(reg.dump_cfg(stream, base) for reg in self.regs)
        assert ret == size

        return ret

    def dump_v120(self, stream: BinaryIO):
        flags = \
            self.type << 4 | self.boot << 3 | self.wakeup << 2 | \
            self.chip_normal << 1 | self.chip_ca
        size = self.len_v120()

        ret = 0
        ret += stream.write(b'\0')
        ret += stream.write(flags.to_bytes())
        ret += stream.write((size - 4).to_bytes(2, 'big'))
        assert ret == 4

        base = -1
        for i in range(len(self.regs)):
            reg = self.regs[i]
            new_base = reg.addr & ~0xff
            if base != new_base:
                base = new_base
                ret += stream.write(base.to_bytes(4, 'big'))
                ret += stream.write(sum(
                    self.regs[j].len_v120() for j in range(
                        i, self.find_block_v120(i))).to_bytes())
            ret += reg.dump_v120(stream)
        assert ret == size

        return ret

    @classmethod
    def from_ini(cls, obj: Mapping[str, str]):
        regs = list[Register]()
        for l in obj['regs'].split('\n'):
            l = l.lstrip()
            if l:
                regs.append(Register.from_ini(l))

        return cls(
            RegModuleType[obj.get('type', 'NORMAL').upper()],
            to_bool(obj.get('boot'), True), to_bool(obj.get('wakeup'), True),
            to_bool(obj.get('chip_normal'), True),
            to_bool(obj.get('chip_ca'), True), regs)

    @staticmethod
    def has_more_reg(buf: BufferedReader):
        return Register.has_more_reg(buf)

    @staticmethod
    def has_more_cfg(buf: BufferedReader):
        flags = buf.peek(1)
        return flags and 1 <= flags[0] <= 3

    @staticmethod
    def has_more_v120(buf: BufferedReader):
        return bool(int.from_bytes(buf.peek(4)[:4]))

    @classmethod
    def load_block_v120(cls, buf: BufferedReader):
        data = mustread(buf, 5)
        base = int.from_bytes(data[:4], 'big')
        size = data[4]

        return [
            Register.load_v120(buf, base)[0] for _ in mustwithin(buf, size)
        ], None

    @classmethod
    def load_reg(cls, buf: BufferedReader):
        reg, flags = Register.load_reg(buf)
        regs = [reg]

        while True:
            data = buf.peek(0x10)
            if not (
                    len(data) >= 0xf and (data[0xe] & 6) >> 1 == flags or
                    len(data) >= 0xd and (data[0xc] & 6) >> 1 == flags):
                break

            reg, new_flags = Register.load_reg(buf)
            assert new_flags == flags
            regs.append(reg)

        return cls(
            RegModuleType.NORMAL, bool(flags & 2), bool(flags & 1),
            True, False, regs), None

    @classmethod
    def load_cfg(cls, buf: BufferedReader):
        flags = mustread(buf)[0]
        mustread(buf)
        size = int.from_bytes(mustread(buf, 2), 'big')
        base = int.from_bytes(mustread(buf, 4), 'big')

        regs = list[Register]()
        for _ in mustwithin(buf, size):
            op = buf.peek(1)[0]
            if op == 1:
                addr, value, mask, delay, readonly = regs[-1]
                mustread(buf)
                delay += mustread(buf)[0]
                regs[-1] = Register(addr, value, mask, delay, readonly)
            else:
                regs.append(Register.load_cfg(buf, base)[0])

        return cls(
            RegModuleType.NORMAL, bool(flags & 2), bool(flags & 1),
            False, True, regs), None

    @classmethod
    def load_v120(cls, buf: BufferedReader):
        data = mustread(buf, 4)
        flags = data[1]
        size = int.from_bytes(data[2:4], 'big')

        regs = list[Register]()
        for _ in mustwithin(buf, size):
            regs.extend(cls.load_block_v120(buf)[0])

        if size & 3:
            buf.read(4 - size & 3)

        return cls(
            RegModuleType(flags >> 4), bool(flags & 0x8), bool(flags & 0x4),
            bool(flags & 0x2), bool(flags & 0x1), regs), None


class RegBinFormat(IntEnum):
    __slots__ = ()

    REG = 0
    CFG = 1
    V120 = 2

    def __str__(self):
        return self.name


class RegBin(NamedTuple):
    """
    Represent a complete register initialization file, corresponding to a xlsm
    file.
    """
    version: str
    "xlsm template version"
    datetime: str
    "build date and time"
    name: str
    "original file name"
    modules: list[RegModule]

    def to_ini(self):
        ret = OrderedDict[str, OrderedDict[str, str]]()

        meta = OrderedDict[str, str]()
        meta['version'] = self.version
        meta['datetime'] = self.datetime
        meta['name'] = self.name
        ret['Info'] = meta

        for i, module in enumerate(self.modules):
            ret[f'Module {i}'] = module.to_ini()

        return ret

    def len_reg(self):
        size = 0xa0 + sum(module.len_reg() for module in self.modules)
        size += 31
        size = size & ~31
        return size

    def len_cfg(self):
        return sum(module.len_cfg() for module in self.modules) + 8 + \
            len(self.datetime.encode()) + 1 + len(self.name.encode()) + 1

    def len_v120(self):
        size = 0x20 + len(self.name.encode())
        size += 3
        size = size & ~3
        for module in self.modules:
            size += module.len_cfg()
            size += 3
            size = size & ~3
        return size

    def _datetime(self, datetime: bool | str = False):
        if isinstance(datetime, str):
            return datetime
        if datetime:
            return self.now()
        return self.datetime

    def dump_reg(self, stream: BinaryIO, datetime: bool | str = False):
        item1_offset = 0xa0
        item2_offset = item1_offset + sum(
            module.len_reg() for module in self.modules)
        item2_offset = (item2_offset + 31) & ~31
        item2_offset += 32

        ret = 0
        ret += writestrn(stream, self.version, 0x10)
        ret += stream.write(item1_offset.to_bytes(4, 'little'))
        ret += stream.write(item2_offset.to_bytes(4, 'little'))
        ret += stream.write(b'\0' * 0x28)
        ret += writestrn(stream, self._datetime(datetime), 0x14)
        ret += writestrn(stream, self.name, 0x4c)
        assert ret == item1_offset

        for module in self.modules:
            ret += module.dump_reg(stream)
        if ret & 31:
            ret += stream.write(b'\0' * (32 - (ret & 31)))
        ret += stream.write(b'\0' * 32)  # reserved 1
        assert ret == item2_offset

        ret += stream.write(b'\0' * 32)  # item 2
        ret += stream.write(b'\0' * 32)  # reserved 2

        return ret

    def dump_cfg(self, stream: BinaryIO, datetime: bool | str = False):
        ret = sum(module.dump_cfg(stream) for module in self.modules)
        ret += stream.write(b'\xff' * 8)
        ret += stream.write(self._datetime(datetime).encode())
        ret += stream.write(b'\xff')
        ret += stream.write(self.name.encode())
        ret += stream.write(b'\xff')
        return ret

    def dump_v120(self, stream: BinaryIO, datetime: bool | str = False):
        ret = 0
        ret += stream.write(b'v120')
        ret += writestrn(stream, self.version, 8)
        ret += writestrn(stream, self._datetime(datetime), 20)
        assert ret == 0x20

        s = self.name.encode()
        ret += stream.write(s)
        ret += stream.write(b'\0')
        if ret & 3:
            ret += stream.write(b'\0' * (4 - (ret & 3)))

        for module in self.modules:
            ret += module.dump_v120(stream)
            if ret & 3:
                ret += stream.write(b'\0' * (4 - (ret & 3)))

        ret += stream.write(b'\0' * 4)
        return ret

    def dump(
            self, stream: BinaryIO, format: RegBinFormat,
            datetime: bool | str = False):
        if format == RegBinFormat.V120:
            return self.dump_v120(stream, datetime)
        elif format == RegBinFormat.REG:
            return self.dump_reg(stream, datetime)
        elif format == RegBinFormat.CFG:
            return self.dump_cfg(stream, datetime)
        else:
            raise ValueError('unknown reg file format')

    @staticmethod
    def now():
        """Get current datetime string."""
        return datetime.now().strftime('%Y/%m/%d %H:%M:%S')

    @classmethod
    def from_ini(
            cls, config: Mapping[str, Mapping[str, str]], filename='<unknown>'):
        meta = config['Info']
        return cls(
            meta.get('version', 'unknown'), meta.get('datetime') or cls.now(),
            meta.get('name', filename), [
                RegModule.from_ini(module) for name, module in config.items()
                if name.startswith('Module ')])

    @staticmethod
    def has_more(buf: BufferedReader):
        return bool(int.from_bytes(buf.peek(4)[:4]))

    @classmethod
    def load_reg(cls, buf: BufferedReader):
        version = bytes(mustread(buf, 0x10).rstrip(b'\0')).decode()
        item1_offset = int.from_bytes(mustread(buf, 4), 'little')
        assert item1_offset == 0xa0
        item2_offset = int.from_bytes(mustread(buf, 4), 'little')
        mustread(buf, 0x28)
        datatime = bytes(mustread(buf, 0x14).rstrip(b'\0')).decode()
        name = bytes(mustread(buf, 0x4c).rstrip(b'\0')).decode()

        # item 1
        start = buf.tell()
        modules = list[RegModule]()
        while RegModule.has_more_reg(buf):
            modules.append(RegModule.load_reg(buf)[0])
        size = buf.tell() - start

        if size & 31:
            mustread(buf, 32 - (size & 31))
        mustread(buf, 32)  # reserved space
        assert buf.tell() - start == item2_offset - item1_offset

        # item 2
        size = 32
        mustread(buf, size)

        if size & 31:
            buf.read(32 - (size & 31))
        buf.read(32)  # reserved space

        return cls(version, datatime, name, modules), None

    @classmethod
    def load_cfg(cls, buf: BufferedReader):
        modules = list[RegModule]()
        while RegModule.has_more_cfg(buf):
            modules.append(RegModule.load_cfg(buf)[0])

        mustread(buf, 8)  # b'\xff' * 8
        datatime = readuntil(buf, 0xff).decode()
        name = readuntil(buf, 0xff).decode()

        return cls('', datatime, name, modules), None

    @classmethod
    def load_v120(cls, buf: BufferedReader):
        mustread(buf, 4)
        version = bytes(mustread(buf, 8).rstrip(b'\0')).decode()
        datatime = bytes(mustread(buf, 0x14).rstrip(b'\0')).decode()
        name_a = readuntil(buf)
        name = bytes(name_a).decode()

        size = len(name_a) + 1
        if size & 3:
            mustread(buf, 4 - (size & 3))

        modules: list[RegModule] = []
        while RegModule.has_more_v120(buf):
            modules.append(RegModule.load_v120(buf)[0])

        return cls(version, datatime, name, modules), None

    @classmethod
    def load(cls, buf: BufferedReader, format: RegBinFormat):
        if format == RegBinFormat.V120:
            return cls.load_v120(buf)
        elif format == RegBinFormat.REG:
            return cls.load_reg(buf)
        elif format == RegBinFormat.CFG:
            return cls.load_cfg(buf)
        else:
            raise ValueError('unknown reg file format')

    @classmethod
    def guess_format(cls, data: bytes | bytearray | memoryview):
        if data[:4] == b'v120':
            return RegBinFormat.V120
        elif data[:3] == b'v1.':
            return RegBinFormat.REG
        elif data[-5:] == b'.cfg\xff':
            return RegBinFormat.CFG
        else:
            raise ValueError('unknown reg file format')

    @classmethod
    def parse(
            cls, data: bytes | bytearray | memoryview,
            format: RegBinFormat | None = None):
        if format is None:
            format = cls.guess_format(data)
        return cls.load(
            BufferedReader(BytesIO(data)), format)[0], format  # type: ignore


def main():
    import argparse
    from configparser import ConfigParser

    parser = argparse.ArgumentParser(
        description='Parse or compile HiSTB bootrom system register initialization file.')

    parser.add_argument(
        '-o', '--output', metavar='PATH', type=argparse.FileType('wb'),
        help='output binary reg file')
    parser.add_argument(
        '-m', '--modify', action='store_true',
        help='set current build datetime in output reg file')
    parser.add_argument(
        '-O', '--output-ini', metavar='PATH', type=argparse.FileType('w'),
        help='output editable ini file')
    parser.add_argument(
        'file', metavar='chip.reg', type=argparse.FileType('rb'),
        help='binary reg file or ini file to parse')

    args = parser.parse_args()

    data = args.file.read()
    if data[:1] == b'[':
        config = ConfigParser()
        config.read_string(data.decode())
        format = RegBinFormat[config['Bin']['format'].upper()]
        regbin = RegBin.from_ini(config, args.file.name)
    else:
        regbin, format = RegBin.parse(data)

    if not args.output and not args.output_ini:
        print(f'Format: {format}')
        print('Version: {0.version}\nTime: {0.datetime}\nName: {0.name}'
              .format(regbin))
        print(
            '============================================================')

        for module in regbin.modules:
            print(
                f'Type {module.type}, '
                f'Normal Boot ({"+" if module.boot else "-"}) '
                f'Standby Wakeup ({"+" if module.wakeup else "-"}) '
                f'Normal ({"+" if module.chip_normal else "-"}) '
                f'CA ({"+" if module.chip_ca else "-"})')
            for reg in module.regs:
                print(
                    '  {0.addr:#010x}  {0.value:#10x}  {0.mask:#10x}  '
                    '{0.delay:4}{1}'.format(reg, '  r' if reg.readonly else ''))
            print(
                '============================================================')
    else:
        if args.output:
            regbin.dump(
                args.output, format, args.modify and RegBin.now())

        if args.output_ini:
            config = ConfigParser()
            config.add_section('Bin')
            config['Bin']['format'] = str(format).lower()
            config.read_dict(regbin.to_ini())
            config.write(args.output_ini)


if __name__ == '__main__':
    exit(main())
