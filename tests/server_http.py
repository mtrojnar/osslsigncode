"""Implementation of a HTTP server"""

import argparse
import os
import subprocess
import sys
import threading
from urllib.parse import urlparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

RESULT_PATH = os.getcwd()
FILES_PATH = os.path.join(RESULT_PATH, "./Testing/files/")
CERTS_PATH = os.path.join(RESULT_PATH, "./Testing/certs/")
CONF_PATH = os.path.join(RESULT_PATH, "./Testing/conf/")
LOGS_PATH = os.path.join(RESULT_PATH, "./Testing/logs/")
REQUEST = os.path.join(FILES_PATH, "./jreq.tsq")
RESPONS = os.path.join(FILES_PATH, "./jresp.tsr")
CACRL = os.path.join(CERTS_PATH, "./CACertCRL.der")
TSACRL = os.path.join(CERTS_PATH, "./TSACertCRL.der")
OPENSSL_CONF = os.path.join(CONF_PATH, "./openssl_tsa.cnf")
PORT_LOG = os.path.join(LOGS_PATH, "./port.log")


OPENSSL_TS = ["openssl", "ts",
    "-reply", "-config", OPENSSL_CONF,
    "-passin", "pass:passme",
    "-queryfile", REQUEST,
    "-out", RESPONS]


class RequestHandler(SimpleHTTPRequestHandler):
    """Handle the HTTP POST request that arrive at the server"""

    def __init__(self, request, client_address, server):
        # Save the server handle
        self.server = server
        SimpleHTTPRequestHandler.__init__(self, request, client_address, server)

    def do_GET(self): # pylint: disable=invalid-name
        """"Serves the GET request type"""
        try:
            url = urlparse(self.path)
            self.send_response(200)
            self.send_header("Content-type", "application/crl")
            self.end_headers()
            # Read the file and send the contents
            if url.path == "/intermediateCA":
                with open(CACRL, 'rb') as file:
                    resp_data = file.read()
            if url.path == "/TSACA":
                with open(TSACRL, 'rb') as file:
                    resp_data = file.read()
            self.wfile.write(resp_data)
        except Exception as err: # pylint: disable=broad-except
            print(f"HTTP GET request error: {err}")

    def do_POST(self): # pylint: disable=invalid-name
        """"Serves the POST request type"""
        try:
            url = urlparse(self.path)
            self.send_response(200)
            if url.path == "/kill_server":
                self.log_message(f"Deleting file: {PORT_LOG}")
                os.remove(f"{PORT_LOG}")
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(bytes('Shutting down HTTP server', 'utf-8'))
                self.server.shutdown()
            else:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                with open(REQUEST, mode="wb") as file:
                    file.write(post_data)
                openssl = subprocess.run(OPENSSL_TS,
                    check=True, universal_newlines=True)
                openssl.check_returncode()
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
    # pylint: disable=too-few-public-methods

    def __init__(self):
        self.server = None
        self.server_thread = None

    def start_server(self, port) -> (int):
        """Starting HTTP server on localhost and a random available port for binding"""
        self.server = ThreadingHTTPServer(('localhost', port), RequestHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()
        hostname, port = self.server.server_address[:2]
        print(f"HTTP server started, URL http://{hostname}:{port}")
        return port


def main() -> None:
    """Start HTTP server"""
    ret = 0
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="port number"
    )
    args = parser.parse_args()
    try:
        server = HttpServerThread()
        port = server.start_server(args.port)
        with open(PORT_LOG, mode="w") as file:
            file.write("{}".format(port))
    except OSError as err:
        print(f"OSError: {err}")
        ret = err.errno
    finally:
        sys.exit(ret)


if __name__ == '__main__':
    try:
        fpid = os.fork()
        if fpid > 0:
            sys.exit(0)
    except OSError as ferr:
        print(f"Fork #1 failed: {ferr.errno} {ferr.strerror}")
        sys.exit(1)

    try:
        fpid = os.fork()
        if fpid > 0:
            sys.exit(0)
    except OSError as ferr:
        print(f"Fork #2 failed: {ferr.errno} {ferr.strerror}")
        sys.exit(1)

    # Start the daemon main loop
    main()


# pylint: disable=pointless-string-statement
"""Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: nil
End:
    vim: set ts=4 expandtab:
"""
