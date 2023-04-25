from psutil import net_connections, Process

def get_process_exe(address, port):
  """get process name from connection that was made
  by a process of this host

  Arguments:
    address {str} -- localhost/127.0.0.1
    port {int} -- port of connection

  Returns:
    str -- process name or None
  """
  for connection in net_connections():
    addr = connection.laddr
    if addr.ip == address and addr.port == port:
      return Process(connection.pid).exe()

