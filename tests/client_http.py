#!/usr/bin/python3
"""Implementation of a HTTP client"""

import os
import sys
import http.client

RESULT_PATH = os.getcwd()


def main() -> None:
    """Creating a POST Request"""
    ret = 0
    try:
        file_path = os.path.join(RESULT_PATH, "./Testing/logs/url.log")
        with open(file_path, mode="r", encoding="utf-8") as file:
            url = file.readline()
        host, port = url.split(":")
        conn = http.client.HTTPConnection(host, port)
        conn.request('POST', '/kill_server')
        response = conn.getresponse()
        print("HTTP status code:", response.getcode(), end=', ')
        try:
            text = response.read()
            print(text.decode("UTF-8"), end='', flush=True)
        except OSError as err:
            print(f"Warning: {err}")
        conn.close()
    except OSError as err:
        print(f"OSError: {err}")
        ret = err.errno
    except Exception as err: # pylint: disable=broad-except
        print(f"HTTP client error: {err}")
        ret = err
    finally:
        sys.exit(ret)


if __name__ == '__main__':
    main()


# pylint: disable=pointless-string-statement
"""
Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: nil
End:
    vim: set ts=4 expandtab:
"""
