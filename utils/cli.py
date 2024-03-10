import logging
import sys
from typing import cast
import serial.tools.list_ports
import serial_asyncio


__all__ = ['detect_serial', 'open_serial']


def detect_serial():
    infos = [
        info for info in serial.tools.list_ports.comports()
        if info.subsystem == 'usb-serial']
    if len(infos) == 0:
        print(
            'ERROR: No serial ports detected, use "-p PATH" to specify the '
            'path manually', file=sys.stderr)
        return
    elif len(infos) > 1:
        print(
            'ERROR: Multiple serial ports found, use "-p PATH" to specify '
            'one to use:', file=sys.stderr)
        for info in infos:
            print(
                f'       {info.name}: {info.device_path}', file=sys.stderr)
        return
    ser_path = infos[0].device
    print('Auto-select USB serial port: %s' % ser_path, file=sys.stderr)
    return ser_path


async def open_serial(
        path: str | None = None, baudrate: int | None = None,
        logger: logging.Logger | None = None):
    if path is None:
        path = detect_serial()
        if path is None:
            return

    try:
        reader, writer = await serial_asyncio.open_serial_connection(
            url=path, baudrate=baudrate)
    except Exception as e:
        print(
            'ERROR: Error when opening serial port, %s' % e, file=sys.stderr)
        return
    ser = cast(serial.Serial, cast(
        serial_asyncio.SerialTransport, writer.transport).serial)
    if logger is not None:
        logger.info('Use serial port %s @ %d', ser.name, ser.baudrate)
    return reader, writer, ser
