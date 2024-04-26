#!/usr/bin/python3
"""Check cryptography module."""

import sys
try:
    import cryptography
    print(cryptography.__version__, end="")
except ModuleNotFoundError:
    print("Python3 cryptography module is not installed", end="")
    sys.exit(1)


# pylint: disable=pointless-string-statement
"""Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: nil
End:
    vim: set ts=4 expandtab:
"""
