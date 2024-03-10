# HiLoot

Scripts for booting HiSTB SoCs, Open-source HiTool replacement.

## hiloot

Dependency: `pyserial`, `pyserial-asyncio`, `tqdm` (optional)

Usage: `./hiloot.py <fastboot.bin>`

Boot HiSTB devices via (USB-)serial port.

## bootimg

Usage: `./bootimg.py <fastboot.bin> <bootparm-ver>`

Parse, split, or shrink `fastboot.bin`.

## hireg

Usage: `./hireg.py -O <output.ini> -o <output.reg> <input.reg | input.ini>`

Display HiSTB bootrom reg file, or convert to / from editable ini file.

## uboot-env

Usage: `./uboot-env.py <bootargs.bin>`

Display or compile U-Boot environ file.

## License

GPL-2.0-or-later
