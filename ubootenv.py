#!/usr/bin/env python3

"""U-Boot fw-utils fw_printenv / fw_setenv replacement, but more permissive."""

import binascii
from collections import OrderedDict
from typing import TYPE_CHECKING, Mapping

if TYPE_CHECKING:
    from _typeshed import SupportsRead, SupportsWrite


__all__ = ['UBootEnvError', 'readenv', 'writeenv']


class UBootEnvError(Exception):
    __slots__ = ()


def readenv(stream: 'SupportsRead[bytes]', size=0):
    """Read the U-Boot environment variables from a file into a dict."""
    if 0 < size < 6:
        raise UBootEnvError('size too small')

    crc = int.from_bytes(stream.read(4), 'little')
    data = stream.read(size - 4 if size > 0 else -1)

    real_crc = binascii.crc32(data)

    environ = OrderedDict[bytes, bytes]()
    for kv in data.split(b'\0'):
        if not kv:
            break
        key, value = kv.split(b'=', 1)
        environ[key] = value

    return environ, len(data) + 4, crc == real_crc


def writeenv(
        stream: 'SupportsWrite[bytes]', environ: Mapping[bytes, bytes],
        size: int):
    """Write the U-Boot environment variables from a dict into a file."""
    chunks = [b'%s=%s\0' % (key, environ[key]) for key in environ]
    length = sum(len(i) for i in chunks)

    if length > size - 5:
        raise UBootEnvError('size too small')

    chunks.append(b'\0' * (size - length - 4))
    crc = 0
    for i in chunks:
        crc = binascii.crc32(i, crc)

    stream.write(crc.to_bytes(4, 'little'))
    for i in chunks:
        stream.write(i)
    return size


def main():
    import argparse
    import sys
    import os.path

    def printerr(*args, **kwargs):
        print(*args, file=sys.stderr, **kwargs)

    parser = argparse.ArgumentParser(
        description='Read, set or generate U-Boot environ file.')
    parser.add_argument(
        '--offset', metavar='OFFSET', dest='in_offset', default=0, type=int,
        help='offset in input file (default: 0)')
    parser.add_argument(
        '--size', metavar='SIZE', dest='in_size', default=0, type=int,
        help='size of input environ (default: till end of file)')
    parser.add_argument(
        '--verify', action='store_true',
        help='raise error if CRC mismatched')
    parser.add_argument(
        '--ignore', action='store_true',
        help='do not show error message if CRC mismatched')
    parser.add_argument(
        '--get', metavar='KEY', nargs='+', type=lambda x: x.encode(),
        help='show values to these keys')
    parser.add_argument(
        '-s', '--script', type=argparse.FileType('rb'),
        help='read variables to be set from a script')
    parser.add_argument(
        '-o', metavar='file', dest='out_path',
        help='output file')
    parser.add_argument(
        '--out-offset', metavar='OFFSET', dest='out_offset', default=0,
        type=int,
        help='offset in output file (default: 0)')
    parser.add_argument(
        '--out-size', metavar='SIZE', dest='out_size', type=int,
        help='size of output environ (default: size of input environ, or 0x10000)')
    parser.add_argument(
        'in_file', metavar='FILE', nargs='?', type=argparse.FileType('rb'),
        help='input file')
    parser.add_argument(
        'set', metavar='KEY=VALUE', nargs='*', type=lambda x: x.encode(),
        help='the variables to be set')

    args = parser.parse_args()

    if not args.in_file and not args.out_path:
        printerr('Error: No action specified, use -h to see help')
        return 1

    if args.in_file:
        args.in_file.seek(args.in_offset)
        (environ, size, crc_ok) = readenv(args.in_file, args.in_size)
        if not crc_ok:
            if args.verify:
                printerr('Error: Bad CRC')
                return 2
            elif not args.ignore:
                printerr('Warning: Bad CRC')

        if args.get:
            for key in args.get:
                sys.stdout.buffer.write(environ.get(key, b''))
                sys.stdout.buffer.write(b'\n')
        elif not args.out_path:
            for key in environ:
                sys.stdout.buffer.write(key)
                sys.stdout.buffer.write(b'=')
                sys.stdout.buffer.write(environ[key])
                sys.stdout.buffer.write(b'\n')
        sys.stdout.buffer.flush()
    else:
        environ = OrderedDict[bytes, bytes]()
        size = 0x10000

    if args.out_path:
        if args.script:
            for kv in args.script.read().splitlines():
                if not kv or kv.startswith(b'#'):
                    continue
                key, value = kv.split(b'=', 1)
                environ[key] = value
        if args.set:
            for kv in args.set:
                key, value = kv.split(b'=', 1)
                environ[key] = value
        if os.path.isfile(args.out_path):
            out_file = open(args.out_path, 'r+b')
            out_file.seek(args.out_offset)
        else:
            out_file = open(args.out_path, 'wb')
            if args.out_offset:
                out_file.write(b'\0' * args.out_offset)
        writeenv(out_file, environ, args.out_size or size)

    return 0


if __name__ == '__main__':
    exit(main())
