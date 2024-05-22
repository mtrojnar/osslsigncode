#!/usr/bin/python3
"""Windows: Implementation of a HTTP server"""

import argparse
import os
import subprocess
import sys
import threading
from urllib.parse import urlparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from make_certificates import CertificateMaker

RESULT_PATH = os.getcwd()
FILES_PATH = os.path.join(RESULT_PATH, "./Testing/files/")
CERTS_PATH = os.path.join(RESULT_PATH, "./Testing/certs/")
CONF_PATH = os.path.join(RESULT_PATH, "./Testing/conf/")
LOGS_PATH = os.path.join(RESULT_PATH, "./Testing/logs/")
REQUEST = os.path.join(FILES_PATH, "./jreq.tsq")
RESPONS = os.path.join(FILES_PATH, "./jresp.tsr")
OPENSSL_CONF = os.path.join(CONF_PATH, "./openssl_tsa.cnf")
SERVER_LOG = os.path.join(LOGS_PATH, "./server.log")
URL_LOG = os.path.join(LOGS_PATH, "./url.log")


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
            self.send_header("Content-type", "application/pkix-crl")
            self.end_headers()
            resp_data = b''
            # Read the file and send the contents
            if url.path == "/intermediateCA":
                file_path = os.path.join(CERTS_PATH, "./CACertCRL.der")
                with open(file_path, 'rb') as file:
                    resp_data = file.read()
            if url.path == "/TSACA":
                file_path = os.path.join(CERTS_PATH, "./TSACertCRL.der")
                with open(file_path, 'rb') as file:
                    resp_data = file.read()
            self.wfile.write(resp_data)
        except Exception as err: # pylint: disable=broad-except
            print("HTTP GET request error: {}".format(err))


    def do_POST(self): # pylint: disable=invalid-name
        """"Serves the POST request type"""
        try:
            url = urlparse(self.path)
            self.send_response(200)
            if url.path == "/kill_server":
                self.log_message(f"Deleting file: {URL_LOG}")
                os.remove(f"{URL_LOG}")
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
                resp_data = b''
                with open(RESPONS, mode="rb") as file:
                    resp_data = file.read()
                self.wfile.write(resp_data)
        except Exception as err: # pylint: disable=broad-except
            print("HTTP POST request error: {}".format(err))


class HttpServerThread():
    """TSA server thread handler"""
    # pylint: disable=too-few-public-methods

    def __init__(self):
        self.server = None
        self.server_thread = None

    def start_server(self, port) -> (int):
        """Starting HTTP server on 127.0.0.1 and a random available port for binding"""
        self.server = ThreadingHTTPServer(('127.0.0.1', port), RequestHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()
        hostname, port = self.server.server_address[:2]
        print("HTTP server started, URL http://{}:{}".format(hostname, port))
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
        sys.stdout = open(SERVER_LOG, "w")
        sys.stderr = open(SERVER_LOG, "a")
        server = HttpServerThread()
        port = server.start_server(args.port)
        with open(URL_LOG, mode="w") as file:
            file.write("127.0.0.1:{}".format(port))
        tests = CertificateMaker(port, SERVER_LOG)
        tests.make_certs()
    except OSError as err:
        print("OSError: {}".format(err))
        ret = err.errno
    finally:
        sys.exit(ret)


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
