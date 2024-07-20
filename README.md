# HiLoot

Open-source HiTool replacement, scripts for booting and mainpulating bootloader images for HiSTB SoCs.

## hiloot

* Dependency: `pyserial`, `pyserial-asyncio`, `tqdm` (optional)
* Usage: `./hiloot.py <fastboot.bin>`

Boot HiSTB devices via (USB-)serial port.

### Bootstrap procedure

 1. Connect your device via USB UART port. Run `./hiloot.py fastboot.bin`, where `fastboot.bin` is the bootloader image of your device extracted from applicable update zip files;
 2. If you see

    ```
    ERROR: You have not specified chip properties file, but the boot image doesn't
           seem to be a Libbootrom image.
    ```

    then you will need `ChipProperties` file for your board, located in `Resources/Common/ChipProperties` of vendor HiTool. If you don't have HiTool installed, you can find extracted `ini` properties files from `snippets` repository.

    Run `./hiloot.py fastboot.bin <properties file>` again;
 3. A progress bar appears, indicating the program has started uploading the bootloader. After the upload is finished, you will see

    ```Bootstrap finished.```

    and you now have access to TTL UART console;
 4. Press `Ctrl+C` or any applicable key to interrupt U-Boot automatic boot process and enter U-Boot command line. Follow U-Boot manuals to boot or flash your device from U-disk or via tftp.

    Here is an example to boot existing kernel from internal eMMC:

    ```
    mmc read 0 0x1FFBFC0 0x2F000 0x5000
    bootm 0x1FFBFC0
    ```

## bootimg

* Usage: `./bootimg.py <fastboot.bin> <bootparm-ver>`

Parse, split, or shrink `fastboot.bin`.

## hireg

* Usage: `./hireg.py -O <output.ini> -o <output.reg> <input.reg | input.ini>`

Display HiSTB bootrom reg files (usually located in `<SDK>/source/boot/sysreg/`), or convert them from / to editable ini files.

## ubootenv

* Usage: `./ubootenv.py <bootargs.bin>`

Display or compile U-Boot environ file.

U-Boot fw-utils `fw_printenv` / `fw_setenv` replacement, but more permissive.

## License

GPL-2.0-or-later
