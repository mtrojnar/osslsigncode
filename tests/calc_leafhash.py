#!/usr/bin/python3
"""Wait for all tests certificate, compute leafhash"""

import hashlib
import time
import os

RESULT_PATH = os.getcwd()
CERTS_PATH = os.path.join(RESULT_PATH, "./Testing/certs/")
LOGS_PATH = os.path.join(RESULT_PATH, "./Testing/logs/")


def compute_sha256(file_name) -> str:
    """Compute a SHA256 hash of the leaf certificate (in DER form)"""

    sha256_hash = hashlib.sha256()
    file_path = os.path.join(CERTS_PATH, file_name)
    with open(file_path, mode="rb") as file:
        for bajt in iter(lambda: file.read(4096),b""):
            sha256_hash.update(bajt)
    return sha256_hash.hexdigest()


def main() -> None:
    """Wait for all tests certificate, compute leafhash"""

    try:
        cert_log = os.path.join(CERTS_PATH, "./cert.log")
        while not (os.path.exists(cert_log) and os.path.getsize(cert_log) > 0):
            time.sleep(1)

        leafhash = compute_sha256("cert.der")
        file_path = os.path.join(CERTS_PATH, "./leafhash.txt")
        with open(file_path, mode="w", encoding="utf-8") as file:
            file.write("SHA256:{}".format(leafhash))

    except Exception as err: # pylint: disable=broad-except
        logs = os.path.join(LOGS_PATH, "./server.log")
        with open(logs, mode="a", encoding="utf-8") as file:
            file.write("Error: {}".format(err))


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
