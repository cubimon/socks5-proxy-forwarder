import logging
from signal import pause
from ipaddress import IPv4Address
from dnslib.server import DNSServer
from socketserver import ThreadingTCPServer
from threading import Thread

from requesthandler import SOCKS5RequestHandler, DNSRequestHandler, HTTPRequestHandler

ThreadingTCPServer.allow_reuse_address = True

class Server:

  def __init__(self, address='0.0.0.0', dns_port=53, socks5_port=1080, http_port=8899):
    logging.info('binding dns port to ' + str(dns_port))
    self.dns_server = DNSServer(
      DNSRequestHandler(), address=address, port=dns_port)
    logging.info('binding socks5 port to ' + str(socks5_port))
    self.socks5_server = ThreadingTCPServer(
      (address, socks5_port), SOCKS5RequestHandler)
    logging.info('binding http port to ' + str(http_port))
    self.http_server = ThreadingTCPServer(
      (address, http_port), HTTPRequestHandler)
    self.address = IPv4Address(address)
    #self.socks5_port = socks5_port
    #self.http_port = http_port

  def serve(self):
    self.dns_server.start_thread()
    while True:
      #self.socks5_server.allow_reuse_address = True
      #self.socks5_server.server_bind()
      #self.socks5_server.server_activate()
      #self.http_server.allow_reuse_address = True
      #self.http_server.server_bind()
      #self.http_server.server_activate()
      socks5_thread = Thread(target=self.socks5_server.serve_forever)
      http_thread = Thread(target=self.http_server.serve_forever)
      socks5_thread.start()
      http_thread.start()
      try:
        socks5_thread.join()
        http_thread.join()
      except KeyboardInterrupt as e:
        # TODO: cleanup doesn't work properly
        print('keyboard interrupt')
        self.socks5_server.shutdown()
        self.http_server.shutdown()
        self.socks5_server.server_close()
        self.http_server.server_close()
        return
