import logging
from ipaddress import ip_address
from socket import socket, AF_INET, SOCK_DGRAM
from socks import socksocket
from dnslib import DNSRecord

# TODO: use socks.socksocket

def resolve_domain_udp(domain, dns, proxy):
  """resolve address using dns server and proxy

  Arguments:
    address {} -- domain/address to resolve using dns server
    dns {str} -- dns server address
    proxy {tuple} -- proxy to use to make dns request

  Returns:
    str -- ip address string/domain if couldn't resolve
  """
  try:
    ip_address(domain)
    return domain
  except ValueError:
    pass
  # TODO: use proxy
  query = DNSRecord.question(domain)
  client = socksocket(AF_INET, SOCK_DGRAM)
  if proxy is not None:
    client.set_proxy(*proxy)
  client.sendto(bytes(query.pack()), (dns, 53))
  data, _ = client.recvfrom(1024)
  record = DNSRecord.parse(data)
  if len(record.rr) != 0:
    print(record.rr[0].rdata)
    return str(record.rr[0].rdata)
  logging.error('couldn\'t resolve domain {}'.format(domain))
  return domain
