#!/usr/bin/python3
"""Check the CheckSum field of a PE file against an independent computation."""

import struct
import sys


def pe_checksum(data: bytes) -> int:
    """Compute the PE checksum as documented for the CheckSum field.

    Add the 16-bit little-endian words of the file, without the CheckSum field,
    with an end-around carry, then add the length of the file."""
    pe_offset = struct.unpack_from("<I", data, 60)[0]
    field = pe_offset + 24 + 64  # OptionalHeader.CheckSum
    total = 0
    for pos in range(0, len(data) - 1, 2):
        if pos in (field, field + 2):
            continue
        total += data[pos] | (data[pos + 1] << 8)
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return total + len(data)


def check(path: str) -> int:
    """Return 0 when the stored checksum is correct."""
    with open(path, "rb") as file:
        data = file.read()
    pe_offset = struct.unpack_from("<I", data, 60)[0]
    stored = struct.unpack_from("<I", data, pe_offset + 24 + 64)[0]
    expected = pe_checksum(data)
    if stored != expected:
        print("{}: checksum 0x{:08X}, expected 0x{:08X}".format(path, stored, expected),
              file=sys.stderr)
        return 1
    return 0


def make(src: str, dst: str, size: int, fill: int) -> None:
    """Append size bytes with the value fill to a PE file, as an overlay."""
    with open(src, "rb") as file:
        data = file.read()
    with open(dst, "wb") as file:
        file.write(data + bytes([fill]) * size)


def main() -> None:
    """Parse the command line."""
    if len(sys.argv) == 3 and sys.argv[1] == "check":
        sys.exit(check(sys.argv[2]))
    if len(sys.argv) == 6 and sys.argv[1] == "make":
        make(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]))
        return
    print("Usage:\n\t{0} check FILE\n\t{0} make IN OUT SIZE FILL".format(sys.argv[0]),
          file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()


# pylint: disable=pointless-string-statement
"""Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: no
End:
    vim: set ts=4 expandtab:
"""
