#!/bin/python3
import argparse
import logging
from socketserver import ThreadingMixIn, TCPServer
from request_handler import RequestHandler

logging.basicConfig(level=logging.DEBUG)


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--address', help='address to bind to',
                        default='127.0.0.1')
    parser.add_argument('--port', help='port to bind to',
                        default=1081)
    args = parser.parse_args()
    with ThreadingTCPServer((args.address, int(args.port)), RequestHandler) \
            as server:
        server.serve_forever()
