#!/usr/bin/python3
"""Implementation of a single ctest script."""

import sys
import subprocess


def parameter(value):
    """Read parameter from file."""
    prefix = 'FILE '
    if value.startswith(prefix):
        with open(value[len(prefix):], mode="r", encoding="utf-8") as file:
            return file.read().strip()
    return value


def main() -> None:
    """Run osslsigncode with its options."""
    try:
        print(sys.argv)
        params = map(parameter, sys.argv[1:])
        proc = subprocess.run(params, check=True)
        sys.exit(proc.returncode)
    except subprocess.CalledProcessError as err:
        print("Error during command execution:", err)
    except Exception as err: # pylint: disable=broad-except
        print("Error: {}".format(err))
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
