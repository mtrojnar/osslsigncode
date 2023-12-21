"""Implementation of a HTTP client"""

import os
import sys
import http.client

RESULT_PATH = os.getcwd()
LOGS_PATH = os.path.join(RESULT_PATH, "./Testing/logs/")
PORT_LOG = os.path.join(LOGS_PATH, "./port.log")


def main() -> None:
    """Creating a POST Request"""
    ret = 0
    try:
        with open(PORT_LOG, 'r') as file:
            port = file.readline()
        conn = http.client.HTTPConnection('127.0.0.1', port)
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
