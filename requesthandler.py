#!/bin/python3
import logging
from struct import pack, unpack
from base64 import b64encode
from enum import IntEnum
from ipaddress import IPv4Address, IPv6Address
from dnslib import DNSRecord, RR
from select import select
from socketserver import StreamRequestHandler
from socket import socket, AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM
from socks import socksocket
from urllib.parse import urlparse

#from domain import resolve_domain_udp
from process import get_process_exe
from bandwidthmonitor import BandwidthMonitor


# dns cache
dns_cache = {}
# bandwidth monitor for each process
process_bandwidth_monitor = BandwidthMonitor()
# bandwidth monitor for each domain
domain_bandwidth_monitor = BandwidthMonitor()

# Socks5
SOCKS_VERSION = 5

# for tcp forwarding
CHUNK_SIZE = 4096

class Method(IntEnum):
  NO_AUTH = 0
  USERNAME_PASSWORD = 2


class AddressType(IntEnum):
  IPV4 = 1
  DOMAINNAME = 3
  IPV6 = 4


class Command(IntEnum):
  CONNECT = 1
  BIND = 2
  UDP = 3

#class HTTPRequestHandler:
#
#  proxy = lambda self, domain: None

class DNSRequestHandler:
  """
  DNS resolver
  """
  dns = lambda self, domain: '8.8.8.8'

  def resolve(self, request, handler):
    sock = socket(AF_INET, SOCK_DGRAM)
    domain = str(request.q.qname)
    dns = self.dns(domain)
    sock.sendto(request.pack(), (dns[0], dns[1]))
    data, _ = sock.recvfrom(1024)
    response = DNSRecord().parse(data)
    for rr in response.rr:
      ip_address = str(rr.rdata)
      dns_cache[ip_address] = domain
      logging.info('resolved address %s to %s', domain, ip_address)
    reply = request.reply()
    reply.add_answer(*response.rr)
    return reply

class SOCKS5RequestHandler(StreamRequestHandler):
  """
  SOCKS5 request handler
  """
  username = None
  password = None
  requires_authentication = False
  proxy = lambda self, address, port: None

  def handle(self):
    process_exe = get_process_exe(*self.client_address)
    if process_exe is None:
      logging.info('accepting connection from client address %s:%s' % self.client_address)
    else:
      logging.info('accepting connection from process %s' % process_exe)

    # get version/authentication method count
    version, nmethods = unpack('!BB', self.connection.recv(2))
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
    self.connection.sendall(pack('!BB', SOCKS_VERSION, method))

    # authentication if required
    if self.requires_authentication and not self.verify_credentials():
      logging.info('invalid credentials')
      return

    # address/port
    version, cmd, _, address_type = unpack('!BBBB', self.connection.recv(4))
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
    port = unpack('!H', self.connection.recv(2))[0]
    logging.info('requested connection to %s %d', address, port)

    # create connection
    try:
      if cmd == Command.CONNECT:
        remote = None
        if address_type == AddressType.IPV4 \
            or address_type == AddressType.DOMAINNAME:
          remote = socksocket()
        elif address_type == AddressType.IPV6:
          remote = socksocket(AF_INET6, SOCK_STREAM, 0)
        proxy = self.proxy(address, port)
        if proxy is not None:
          logging.info('setting proxy')
          remote.set_proxy(*proxy)
        address_str = str(address)
        if address_str in dns_cache:
          logging.info('using domain from address/dns cache: %s',
                       dns_cache[address_str])
          address = dns_cache[address_str]
          address_type = AddressType.DOMAINNAME
        remote.connect((address_str, port))
        logging.info('connected to %s %s', address, port)
      elif cmd == Command.UDP:
        # TODO: udp
        remote = None
        if address_type == AddressType.IPV4 \
            or address_type == AddressType.DOMAINNAME:
          remote = socksocket(AF_INET, SOCK_DGRAM)
        elif address_type == AddressType.IPV6:
          remote = socksocket(AF_INET6, SOCK_DGRAM, 0)
        proxy = self.proxy(address, port)
        if proxy is not None:
          logging.info('setting proxy')
          remote.set_proxy(*proxy)
        address_str = str(address)
        if address_str in dns_cache:
          logging.info('using domain from address/dns cache: %s',
                       dns_cache[address_str])
          address = dns_cache[address_str]
          address_type = AddressType.DOMAINNAME
        remote.connect((address_str, port))
        logging.info('connected to %s %s', address, port)
      else:
        logging.error('unknown command %d', cmd)
        self.server.close_request(self.request)
        return
      # create reply
      reply = pack('!BBBB', SOCKS_VERSION, 0, 0, address_type)
      if address_type in [AddressType.IPV4, AddressType.IPV6]:
        reply += address.packed
      elif address_type == AddressType.DOMAINNAME:
        reply += pack('!B', len(address))
        reply += address.encode('utf-8')
      reply += pack('!H', port)
    except Exception as err:
      import traceback
      traceback.print_exc()
      #import pdb; pdb.set_trace()
      logging.error(err)
      # return connection refused error
      reply = self.generate_failed_reply(address_type, 5)
    self.connection.sendall(reply)

    # establish data exchange
    if reply[1] == 0 and cmd == 1:
      logging.info('exchanging data now')
      tcp_forwarding(self.connection, remote, process_exe, address)

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
      response = pack('!BB', version, 0)
      self.connection.sendall(response)
      return True

    # failure, status != 0
    response = pack('!BB', version, 0xFF)
    self.connection.sendall(response)
    self.server.close_request(self.request)
    return False

  def generate_failed_reply(self, address_type, error_number):
    return pack('!BBBBIH', SOCKS_VERSION, error_number, 0, address_type, 0, 0)

class HTTPRequestHandler(StreamRequestHandler):
  """
  HTTP request handler
  """
  proxy = lambda self, address, port: None

  def handle(self):
    process_exe = get_process_exe(*self.client_address)
    if process_exe is None:
      logging.info('accepting connection from client address %s:%s' % self.client_address)
    else:
      logging.info('accepting connection from process %s' % process_exe)

    # parse first request from client
    logging.info('http request handle call')
    fd_client = self.connection.makefile('wrb')
    request = b''
    while True:
      line = fd_client.readline()
      request += line
      if len(line.strip()) == 0:
        break
    logging.info('response from client')
    logging.info(request)
    address, port, is_connect = self.parse_request(request)
    logging.info('accessing domain/port: ' + address + ':' + str(port))

    # remote connection
    remote = socksocket(AF_INET, SOCK_STREAM, 0)
    proxy = self.proxy(address, port)
    if proxy is None:
      remote.connect((address, port))
    else:
      remote.connect((proxy[0], proxy[1]))

    # process first request
    fd_remote = remote.makefile('wrb')
    if is_connect and proxy is None:
      logging.info('writing connect response to client')
      fd_client.write(b'HTTP/1.1 200 OK\r\n\r\n')
      fd_client.flush()
    else:
      logging.info('writing response from client to remote')
      if proxy is not None and len(proxy) >= 4:
        logging.info('appending proxy authentication')
        lines = request.split(b'\r\n')
        credentials = proxy[2].encode('ascii') + b':' + proxy[3].encode('ascii')
        proxy_authentication_line = b'Proxy-Authorization: Basic ' + b64encode(credentials)
        lines.insert(1, proxy_authentication_line)
        request = b'\r\n'.join(lines)
      fd_remote.write(request)
      fd_remote.flush()

    tcp_forwarding(self.connection, remote, process_exe, address)

  def parse_request(self, request):
    """
    Parses request to get domain of address and port.
    Also determines if request is CONNECT request.
    """
    status_row = request.split(b'\r\n')[0]
    http_method, url, _ = status_row.split(b' ')
    address = None
    port = None
    is_connect = (http_method == b'CONNECT')
    if is_connect:
      logging.info('http method is connect')
      address = url.decode('ascii')
    else:
      logging.info('http method is something else')
      url = urlparse(url)
      address = url.netloc.decode('ascii')
      if url.scheme == 'https':
        logging.info('port 443')
        port = 443
      else:
        logging.info('port 80')
        port = 80
    if ':' in address:
      logging.info('using port from url')
      address, port = address.split(':')
      port = int(port)
    if address in dns_cache:
      address = dns_cache[address]
    return address, port, is_connect

def tcp_forwarding(client, remote, process_exe, address):
  """
  Tcp forwarding from client <-> remote.
  Client is from process_exe, remote is address.
  """
  while True:
    # wait until client or remote is available for read
    r, _, _ = select([client, remote], [], [])
    try:
      if client in r:
        # if valves aren't filled, pass data from client to remote
        if not process_bandwidth_monitor.upload_is_full(process_exe) \
            and not domain_bandwidth_monitor.download_is_full(address):
          data = client.recv(CHUNK_SIZE)
          if remote.send(data) <= 0:
            return
          # track traffic
          process_bandwidth_monitor.upload_event(process_exe, len(data))
          domain_bandwidth_monitor.download_event(address, len(data))
      if remote in r:
        # if valves aren't filled, pass data from remote to client
        if not process_bandwidth_monitor.download_is_full(process_exe) \
            and not domain_bandwidth_monitor.upload_is_full(address):
          data = remote.recv(CHUNK_SIZE)
          if client.send(data) <= 0:
            return
          # track traffic
          process_bandwidth_monitor.download_event(process_exe, len(data))
          domain_bandwidth_monitor.upload_event(address, len(data))
    except ConnectionResetError as err:
      if err.errno == 104:
        logging.info('connection reset by peer')
      else:
        logging.error(err)
      return
