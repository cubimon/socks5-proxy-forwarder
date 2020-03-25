#!/bin/python3
import argparse
import logging
from socketserver import ThreadingMixIn, TCPServer
from requesthandler import RequestHandler


logging.basicConfig(level=logging.DEBUG)


def router(self, address, port):
    # static route
    return 'enp0s31f6'


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--address', help='address to bind to',
                        default='127.0.0.1')
    parser.add_argument('--port', help='port to bind to',
                        default=1080)
    args = parser.parse_args()
    # limit 5 mbit download/2 mbit upload
    # division by 8 to convert bytes to bits
    # bits is used by most isps or speedtest.net
    RequestHandler.process_bandwidth_monitor.limitations = {
        'curl': [50, 50],
        'chrome': [5 * 1000 * 1000 / 8, 2 * 1000 * 1000 / 8],
        'chromium': [5 * 1000 * 1000 / 8, 2 * 1000 * 1000 / 8],
        'firefox': [5 * 1000 * 1000 / 8, 2 * 1000 * 1000 / 8]
    }
    RequestHandler.router = router
    with ThreadingTCPServer((args.address, int(args.port)), RequestHandler) \
            as server:
        server.serve_forever()

