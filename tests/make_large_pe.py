#!/usr/bin/python3
"""Create a minimal valid sparse PE32+ file of a given size (in bytes)."""

import struct
import sys

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
HEADERS_SIZE = 0x200


def make_pe(path: str, size: int, overlay: bool = False) -> int:
    """Write a PE32+ file with one .text section, return its final size.

    The section fills the file, or only 1 MB of it when overlay is set: the rest
    is then data appended after the last section, as in large installers."""
    raw = (1 << 20) if overlay else size - HEADERS_SIZE
    raw -= raw % FILE_ALIGNMENT
    if not overlay:
        size = HEADERS_SIZE + raw

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 60, 64)  # e_lfanew
    opt_size = 240
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, opt_size, 0x22)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 16, SECTION_ALIGNMENT)  # entry point
    struct.pack_into("<Q", opt, 24, 0x140000000)  # image base
    struct.pack_into("<I", opt, 32, SECTION_ALIGNMENT)
    struct.pack_into("<I", opt, 36, FILE_ALIGNMENT)
    struct.pack_into("<H", opt, 40, 6)
    struct.pack_into("<H", opt, 48, 6)
    image_size = SECTION_ALIGNMENT + ((raw + SECTION_ALIGNMENT - 1) & ~(SECTION_ALIGNMENT - 1))
    struct.pack_into("<I", opt, 56, min(image_size, 0xFFFFF000))
    struct.pack_into("<I", opt, 60, HEADERS_SIZE)
    struct.pack_into("<H", opt, 68, 3)  # subsystem
    struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes
    sect = struct.pack("<8sIIIIIIHHI", b".text", raw, SECTION_ALIGNMENT, raw,
                       HEADERS_SIZE, 0, 0, 0, 0, 0x60000020)

    head = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + sect
    head += bytes(HEADERS_SIZE - len(head))
    with open(path, "wb") as file:
        file.write(head)
        file.truncate(size)
        file.seek(HEADERS_SIZE)
        file.write(b"\x90" * 4096)
        file.seek(size - 4096)
        file.write(b"\xCC" * 4096)  # last bytes: section data or overlay
    return size


def main() -> None:
    """Parse the command line."""
    if len(sys.argv) not in (3, 4):
        print("Usage:\n\t{} FILE SIZE [overlay]".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    make_pe(sys.argv[1], int(sys.argv[2]), len(sys.argv) == 4)


if __name__ == "__main__":
    main()


# pylint: disable=pointless-string-statement
"""Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: nil
End:
    vim: set ts=4 expandtab:
"""
