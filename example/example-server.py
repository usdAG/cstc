#!/usr/bin/python3

import logging
import gzip
import base64
from sys import argv
from http.server import BaseHTTPRequestHandler, HTTPServer

class S(BaseHTTPRequestHandler):

    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()
        self.wfile.write("GET request for {}".format(self.path).encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        try:
            result = base64.b64decode(post_data)
        except:
            self._set_response()
            self.wfile.write(b"Error 1021: Server expects Base64 encoded and gzip compressed data.")
            return

        try: 
            result = gzip.decompress(result)
        except:
            self._set_response()
            self.wfile.write(b"Error 1022: Server expects Base64 encoded and gzip compressed data.")
            return

        self._set_response()
        self.wfile.write(b"<h1>Processing Input: '" + result + b"'...</h1>")


def run(server_class=HTTPServer, handler_class=S, port=8000):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting CSTC Example Server.\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping CSTC Example Server...\n')


if __name__ == '__main__':
    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
