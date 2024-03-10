#!/usr/bin/env python3

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from configparser import ConfigParser
import hashlib


PASSPHASE = b'HiReg-5D765B15-8F5B-46DC-9B7C-80322B8F74E4'
KEY = hashlib.md5(PASSPHASE).digest()
CIPHER = AES.new(KEY, AES.MODE_ECB)


def decrypt(data: bytes | bytearray | memoryview):
    return unpad(CIPHER.decrypt(data), AES.block_size)


def load(data: bytes | bytearray):
    config = ConfigParser()
    if not data.startswith(b'[Type]'):
        data = decrypt(data)
    config.read_string(data.decode('GBK'))
    return config


def decode_frame(config: str):
    return bytes(int(i, 0) for i in config.split(',') if i)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Decrypt Resources/Common/ChipProperties/*.chip.')

    parser.add_argument(
        'file', metavar='type.chip', type=argparse.FileType('rb'),
        help='file to decrypt')

    args = parser.parse_args()

    data = args.file.read()
    print(decrypt(data).decode('GBK'))
    return 0


if __name__ == '__main__':
    exit(main())
