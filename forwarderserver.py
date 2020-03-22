#!/usr/bin/python3
import argparse
import json
import logging
from ipaddress import IPv4Address, IPv6Address
from socketserver import ThreadingMixIn, TCPServer
from socks import SOCKS4, SOCKS5, HTTP
from requesthandler import RequestHandler

logging.basicConfig(level=logging.DEBUG)

credentials = json.loads(open('credentials.json', 'r').read())

def proxy(self, address, port):
    logging.info('resolving address %s', address)
    if isinstance(address, str):
        # we are resolving a domain
        # internal domains don't require proxy
        if address.endswith('.domain1') or \
                address.endswith('.domain2') or \
                address.endswith('.domain3.net'):
            return None
        if address == 'localhost':
            address = IPv4Address('127.0.0.1')
            return None
    if isinstance(address, IPv4Address):
        # connection to ip address
        if address == IPv4Address('127.0.0.1'):
            return None
    return (SOCKS5, 'proxy.domain', 9119, True, credentials['username'], credentials['password'])


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--address', help='address to bind to',
                        default='127.0.0.1')
    parser.add_argument('--port', help='port to bind to',
                        default=1080)
    args = parser.parse_args()
    RequestHandler.proxy = proxy
    with ThreadingTCPServer((args.address, int(args.port)), RequestHandler) \
            as server:
        server.serve_forever()
