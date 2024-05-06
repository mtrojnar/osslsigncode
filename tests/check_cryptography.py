#!/usr/bin/python3
"""Check cryptography module."""

import sys

try:
    import cryptography
    print(cryptography.__version__, end="")
except ModuleNotFoundError:
    print("Python3-cryptography module is not installed", end="")
    sys.exit(1)


class UnsupportedVersion(Exception):
    """Unsupported version"""

def main() -> None:
    """Check python3-cryptography version"""
    try:
        version = tuple(int(num) for num in cryptography.__version__.split('.'))
        if version < (37, 0, 2):
            raise UnsupportedVersion("unsupported python3-cryptography version")
    except UnsupportedVersion as err:
        print(" {}".format(err), end="")
        sys.exit(1)


if __name__ == '__main__':
    main()

# pylint: disable=pointless-string-statement
"""Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: nil
End:
    vim: set ts=4 expandtab:
"""
