"""Implementation of a Time Stamping Authority HTTP server"""

import argparse
import contextlib
import os
import pathlib
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

RESULT_PATH = os.getcwd()
FILES_PATH = os.path.join(RESULT_PATH, "./Testing/files/")
CERTS_PATH = os.path.join(RESULT_PATH, "./Testing/certs/")
DEFAULT_PATH = os.path.join(RESULT_PATH, "./osslsigncode")
DEFAULT_IN = os.path.join(FILES_PATH, "./unsigned.exe")
DEFAULT_OUT = os.path.join(FILES_PATH, "./ts.exe")
DEFAULT_CERT = os.path.join(CERTS_PATH, "./cert.pem")
DEFAULT_KEY = os.path.join(CERTS_PATH, "./key.pem")
DEFAULT_CROSSCERT = os.path.join(CERTS_PATH, "./crosscert.pem")
OPENSSL_CONF = os.path.join(CERTS_PATH, "./openssl_tsa.cnf")
REQUEST = os.path.join(FILES_PATH, "./jreq.tsq")
RESPONS = os.path.join(FILES_PATH, "./jresp.tsr")

DEFAULT_OPENSSL = ["openssl", "ts",
    "-reply", "-config", OPENSSL_CONF,
    "-passin", "pass:passme",
    "-queryfile", REQUEST,
    "-out", RESPONS]


class RequestHandler(BaseHTTPRequestHandler):
    """Handle the HTTP POST request that arrive at the server"""

    def do_POST(self):
        """"Serves the POST request type"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            with open(REQUEST, mode="wb") as file:
                file.write(post_data)
            openssl = subprocess.run(DEFAULT_OPENSSL, check=True, text=True)
            openssl.check_returncode()
            self.send_response(200)
            self.send_header("Content-type", "application/timestamp-reply")
            self.end_headers()
            resp_data = None
            with open(RESPONS, mode="rb") as file:
                resp_data = file.read()
            self.wfile.write(resp_data)
        except Exception as err: # pylint: disable=broad-except
            print(f"HTTP POST request error: {err}")


class HttpServerThread():
    """TSA server thread handler"""

    def __init__(self):
        self.server = None
        self.server_thread = None

    def start_server(self) -> (str, int):
        """Starting TSA server on localhost and a first available port"""
        self.server = HTTPServer(("127.0.0.1", 0), RequestHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()
        hostname, port = self.server.server_address[:2]
        print(f"Timestamp server started, URL: http://{hostname}:{port}")
        return hostname, port

    def shut_down(self):
        """Shutting down the server"""
        if self.server:
            self.server.shutdown()
            self.server_thread.join()
        print("Server is down")


def parse_args() -> str:
    """Parse the command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        type=pathlib.Path,
        default=DEFAULT_IN,
        help="input file"
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=DEFAULT_OUT,
        help="output file"
    )
    parser.add_argument(
        "--certs",
        type=pathlib.Path,
        default=DEFAULT_CERT,
        help="signing certificate"
    )
    parser.add_argument(
        "--key",
        type=pathlib.Path,
        default=DEFAULT_KEY,
        help="private key"
    )
    parser.add_argument(
        "--crosscert",
        type=pathlib.Path,
        default=DEFAULT_CROSSCERT,
        help="additional certificates"
    )
    args = parser.parse_args()
    program = [DEFAULT_PATH, "sign", "-in", args.input, "-out", args.output,
        "-certs", args.certs, "-key", args.key,
        "-addUnauthenticatedBlob", "-add-msi-dse", "-comm", "-ph", "-jp", "low",
        "-h", "sha384", "-st", "1556668800", "-i", "https://www.osslsigncode.com/",
        "-n", "osslsigncode", "-ac", args.crosscert, "-ts"]
    return program

def main() -> None:
    """Main program"""
    ret = 0
    program = parse_args()
    server = HttpServerThread()
    hostname, port = server.start_server()
    program.append(f"{hostname}:{port}")
    try:
        osslsigncode = subprocess.run(program, check=True, text=True)
        osslsigncode.check_returncode()
    except subprocess.CalledProcessError as err:
        ret = err.returncode
    except Exception as err: # pylint: disable=broad-except
        print(f"osslsigncode error: {err}")
    finally:
        server.shut_down()
        sys.exit(ret)


if __name__ == '__main__':
    main()
