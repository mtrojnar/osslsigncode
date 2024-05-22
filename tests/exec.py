#!/usr/bin/python3
"""Implementation of a single ctest script."""

import sys
import subprocess


def parse(value):
    """Read parameter from file."""
    prefix = 'FILE '
    if value.startswith(prefix):
        with open(value[len(prefix):], mode="r", encoding="utf-8") as file:
            return file.read().strip()
    return value


def main() -> None:
    """Run osslsigncode with its options."""
    if len(sys.argv) > 1:
        try:
            params = map(parse, sys.argv[1:])
            proc = subprocess.run(params, check=True)
            sys.exit(proc.returncode)
        except Exception as err: # pylint: disable=broad-except
            # all exceptions are critical
            print(err, file=sys.stderr)
    else:
        print("Usage:\n\t{} COMMAND [ARG]...'".format(sys.argv[0]), file=sys.stderr)
    sys.exit(1)


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
