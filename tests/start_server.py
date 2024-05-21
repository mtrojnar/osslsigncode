#!/usr/bin/python3
"""Wait for all tests certificate, compute leafhash"""

import argparse
import binascii
import hashlib
import os
import pathlib
import platform
import subprocess
import sys
import time

RESULT_PATH = os.getcwd()
CERTS_PATH = os.path.join(RESULT_PATH, "./Testing/certs/")
LOGS_PATH = os.path.join(RESULT_PATH, "./Testing/logs/")
SERVER_LOG = os.path.join(LOGS_PATH, "./server.log")
if platform.system() == 'Windows':
    DEFAULT_PYTHON = "C:/Program Files/Python/Python311/pythonw.exe"
    DEFAULT_PROG =  os.path.join(RESULT_PATH, "./Testing/server_http.pyw")
else:
    DEFAULT_PYTHON = "/usr/bin/python3"
    DEFAULT_PROG =  os.path.join(RESULT_PATH, "./Testing/server_http.py")


def compute_sha256(file_name) -> str:
    """Compute a SHA256 hash of the leaf certificate (in DER form)"""

    sha256_hash = hashlib.sha256()
    file_path = os.path.join(CERTS_PATH, file_name)
    with open(file_path, mode="rb") as file:
        for bajt in iter(lambda: file.read(4096),b""):
            sha256_hash.update(bajt)
    return sha256_hash.hexdigest()

def clear_catalog(certs_path) -> None:
    """"Clear a test certificates catalog."""

    if os.path.exists(certs_path):
        #Remove old test certificates
        for root, _, files in os.walk(certs_path):
            for file in files:
                os.remove(os.path.join(root, file))
    else:
        os.mkdir(certs_path)

    # Generate 16 random bytes and convert to hex
    random_hex = binascii.b2a_hex(os.urandom(16)).decode()
    serial = os.path.join(certs_path, "./tsa-serial")
    with open(serial, mode="w", encoding="utf-8") as file:
        file.write(random_hex)

def main() -> None:
    """Wait for all tests certificate, compute leafhash"""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--exe",
        type=pathlib.Path,
        default=DEFAULT_PYTHON,
        help=f"the path to the python3 executable to use"
        f"(default: {DEFAULT_PYTHON})",
    )
    parser.add_argument(
        "--script",
        type=pathlib.Path,
        default=DEFAULT_PROG,
        help=f"the path to the python script to run"
        f"(default: {DEFAULT_PROG})",
    )
    args = parser.parse_args()
    try:
        clear_catalog(CERTS_PATH)
        #pylint: disable=consider-using-with
        subprocess.Popen([str(args.exe), str(args.script)])

        cert_log = os.path.join(CERTS_PATH, "./cert.log")
        while not (os.path.exists(cert_log) and os.path.getsize(cert_log) > 0):
            time.sleep(1)

        leafhash = compute_sha256("cert.der")
        file_path = os.path.join(CERTS_PATH, "./leafhash.txt")
        with open(file_path, mode="w", encoding="utf-8") as file:
            file.write("SHA256:{}".format(leafhash))

    except OSError as err:
        with open(SERVER_LOG, mode="w", encoding="utf-8") as file:
            file.write("OSError: {}".format(err))
        sys.exit(1)

    except Exception as err: # pylint: disable=broad-except
        with open(SERVER_LOG, mode="w", encoding="utf-8") as file:
            file.write("Error: {}".format(err))
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
