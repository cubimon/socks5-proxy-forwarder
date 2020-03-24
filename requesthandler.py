#!/bin/python3
import logging
import struct
import psutil
from enum import IntEnum
from ipaddress import IPv4Address, IPv6Address
from select import select
from socket import AF_INET, AF_INET6, SOCK_STREAM
from socket import inet_aton
from socketserver import StreamRequestHandler
from socks import socksocket
from bandwidthmonitor import BandwidthMonitor


SOCKS_VERSION = 5


def get_process_name(address, port):
    for connection in psutil.net_connections():
        addr = connection.laddr
        if addr.ip == address and addr.port == port:
            return psutil.Process(connection.pid).name()


class Method(IntEnum):
    NO_AUTH = 0
    USERNAME_PASSWORD = 2


class AddressType(IntEnum):
    IPV4 = 1
    DOMAINNAME = 3
    IPV6 = 4


class Command(IntEnum):
    CONNECT = 1


class RequestHandler(StreamRequestHandler):
    username = None
    password = None
    requires_authentication = False
    proxy = lambda self, address, port: None
    process_bandwidth_monitor = BandwidthMonitor()
    domain_bandwidth_monitor = BandwidthMonitor()
    chunk_size = 4096

    def handle(self):
        process_name = get_process_name(*self.client_address)
        if process_name is None:
            logging.info('accepting connection from %s:%s' % self.client_address)
        else:
            logging.info('accepting connection from %s' % process_name)

        # get version/authentication method count
        version, nmethods = struct.unpack('!BB', self.connection.recv(2))
        if version != SOCKS_VERSION or nmethods <= 0:
            logging.warn('got wrong version from request %d', version)
            return
        if nmethods == 0:
            logging.warn('nmethods is zero')
            return

        # get available authentication methods
        methods = self.get_available_authentication_methods(nmethods)
        method = None
        if self.requires_authentication:
            if Method.USERNAME_PASSWORD not in methods:
                logging.warn('only username/password authentication ' \
                             'supported')
                self.server.close_request(self.request)
            method = Method.USERNAME_PASSWORD
        else:
            if Method.NO_AUTH not in methods:
                logging.warn('no authentication is required')
                self.server.close_request(self.request)
            method = Method.NO_AUTH

        # send chosen authentication method
        self.connection.sendall(struct.pack('!BB', SOCKS_VERSION, method))

        # authentication if required
        if self.requires_authentication and not self.verify_credentials():
            logging.info('invalid credentials')
            return

        # address/port
        version, cmd, _, address_type = \
                struct.unpack('!BBBB', self.connection.recv(4))
        if version != SOCKS_VERSION:
            logging.warn('got wrong version from request %d', version)
            return
        address = None
        if address_type == AddressType.IPV4:
            address = IPv4Address(self.connection.recv(4))
        elif address_type == AddressType.DOMAINNAME:
            domain_length = int(self.connection.recv(1)[0])
            address = self.connection.recv(domain_length).decode('utf-8')
        elif address_type == AddressType.IPV6:
            address = IPv6Address(self.connection.recv(16))
        else:
            logging.warn('unknown address type %d' % address_type)
        port = struct.unpack('!H', self.connection.recv(2))[0]
        logging.info('requested connection to %s %d', address, port)

        # create connection
        try:
            if cmd == Command.CONNECT:
                remote = socksocket()
                proxy = self.proxy(address, port)
                if proxy is not None:
                    remote.set_proxy(*proxy)
                remote.connect((str(address), port))
                logging.info('connected to %s %s', address, port)
            else:
                logging.error('unknown command %d', cmd)
                self.server.close_request(self.request)
                return
            reply = struct.pack('!BBBB', SOCKS_VERSION, 0, 0, address_type)
            if address_type in [AddressType.IPV4, AddressType.IPV6]:
                reply += address.packed
            elif address_type == AddressType.DOMAINNAME:
                reply += struct.pack('!B', len(address))
                reply += address.encode('utf-8')
            reply += struct.pack('!H', port)
        except Exception as err:
            logging.error(err)
            # return connection refused error
            reply = self.generate_failed_reply(address_type, 5)
        self.connection.sendall(reply)

        # establish data exchange
        if reply[1] == 0 and cmd == 1:
            logging.info('exchanging data now')
            self.exchange_loop(self.connection, remote, process_name, address)

        self.server.close_request(self.request)

    def get_available_authentication_methods(self, n):
        methods = []
        for _ in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_credentials(self):
        version = ord(self.connection.recv(1))
        assert version == 1

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:
            # success, status = 0
            response = struct.pack('!BB', version, 0)
            self.connection.sendall(response)
            return True

        # failure, status != 0
        response = struct.pack('!BB', version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack('!BBBBIH', SOCKS_VERSION, error_number, 0,
                           address_type, 0, 0)

    def exchange_loop(self, client, remote, process_name, address):
        while True:
            # wait until client or remote is available for read
            r, w, e = select([client, remote], [], [])

            if client in r:
                # if valves aren't filled, pass data from client to remote
                if not self.process_bandwidth_monitor.upload_is_full(process_name) \
                        and not self.domain_bandwidth_monitor.download_is_full(address):
                    data = client.recv(self.chunk_size)
                    if remote.send(data) <= 0:
                        break

                    # track traffic
                    self.process_bandwidth_monitor.upload_event(
                            process_name, len(data))
                    self.domain_bandwidth_monitor.download_event(
                            address, len(data))

            if remote in r:
                # if valves aren't filled, pass data from remote to client
                if not self.process_bandwidth_monitor.download_is_full(process_name) \
                        and not self.domain_bandwidth_monitor.upload_is_full(address):
                    data = remote.recv(self.chunk_size)
                    if client.send(data) <= 0:
                        break

                    # track traffic
                    self.process_bandwidth_monitor.download_event(
                            process_name, len(data))
                    self.domain_bandwidth_monitor.upload_event(
                            address, len(data))

