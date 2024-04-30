#!/usr/bin/python3
"""Implementation of a HTTP server"""

import argparse
import os
import subprocess
import sys
import threading
from urllib.parse import urlparse
from http.server import SimpleHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
try:
    from make_certificates import MakeTestCertificates
except ModuleNotFoundError as ierr:
    print("Module not installed: ".format(ierr))
    sys.exit(1)
except ImportError as ierr:
    print("Module not found: ".format(ierr))
    sys.exit(1)

RESULT_PATH = os.getcwd()
FILES_PATH = os.path.join(RESULT_PATH, "./Testing/files/")
CERTS_PATH = os.path.join(RESULT_PATH, "./Testing/certs/")
CONF_PATH = os.path.join(RESULT_PATH, "./Testing/conf/")
LOGS_PATH = os.path.join(RESULT_PATH, "./Testing/logs/")
REQUEST = os.path.join(FILES_PATH, "./jreq.tsq")
RESPONS = os.path.join(FILES_PATH, "./jresp.tsr")
OPENSSL_CONF = os.path.join(CONF_PATH, "./openssl_tsa.cnf")
URL_LOG = os.path.join(LOGS_PATH, "./url.log")

OPENSSL_TS = ["openssl", "ts",
    "-reply", "-config", OPENSSL_CONF,
    "-passin", "pass:passme",
    "-queryfile", REQUEST,
    "-out", RESPONS]


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """This variant of HTTPServer creates a new thread for every connection"""
    daemon_threads = True


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
                openssl = subprocess.run(OPENSSL_TS, check=True, universal_newlines=True)
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
    """Start HTTP server, make test certificates."""

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
        with open(URL_LOG, mode="w", encoding="utf-8") as file:
            file.write("127.0.0.1:{}".format(port))
        MakeTestCertificates(port)
    except OSError as err:
        print("OSError: {}".format(err))
        ret = err.errno
    except Exception as err: # pylint: disable=broad-except
        print("Error: {}".format(err))
        ret = 1
    finally:
        sys.exit(ret)


if __name__ == '__main__':
    try:
        fpid = os.fork()
        if fpid > 0:
            sys.exit(0)
        log_path = os.path.join(LOGS_PATH, "./server.log")
        with open(log_path, mode='w', encoding='utf-8') as log:
            os.dup2(log.fileno(), sys.stdout.fileno())
            os.dup2(log.fileno(), sys.stderr.fileno())
    except OSError as ferr:
        print("Fork #1 failed: {} {}".format(ferr.errno, ferr.strerror))
        sys.exit(1)

    try:
        fpid = os.fork()
        if fpid > 0:
            sys.exit(0)
    except OSError as ferr:
        print("Fork #2 failed: {} {}".format(ferr.errno, ferr.strerror))
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
