from time import time
from valve import Valve

class BandwidthMonitor:
  """Monitor bandwidth of named points in a stream.
  """

  def __init__(self, limitations={}, lifetime=1.0):
    """Creates a bandwidth monitor with a given set of limitations
    in the stream.

    Keyword Arguments:
      limitations {dict} -- named point in stream (valve) ->
      (maximum download, maximum upload),
      each limitation tuple creates two valves, for upload/download
      (default: {{}})
      lifetime {float} -- size of each valve in seconds
      (default: {1.0})
    """
    self.limitations = limitations
    self.lifetime = lifetime
    self.download_history = {}
    self.upload_history = {}

  def download_event(self, name, size):
    """Monitor data that went through a given download valve by name.

    Arguments:
      name {str} -- name of valve.
      size {int} -- amount of traffic that went through named valve.
    """
    if name not in self.limitations:
      return
    if name not in self.download_history:
        self.download_history[name] = \
            Valve(self.limitations[name][0], self.lifetime)
    self.download_history[name].add(size)

  def upload_event(self, name, size):
    """Monitor data that went through a given upload valve by name.

    Arguments:
      name {str} -- name of valve.
      size {int} -- amount of traffic that went through named valve.
    """
    if name not in self.limitations:
      return
    if name not in self.upload_history:
        self.upload_history[name] = \
            Valve(self.limitations[name][1], self.lifetime)
    self.upload_history[name].add(size)

  def download_is_full(self, name):
    """Check if download valve (by name) is full.

    Arguments:
      name {str} -- name of valve.

    Returns:
      bool -- True if download valve is full, False otherwise.
    """
    if name in self.download_history:
      return self.download_history[name].is_full()
    return False

  def upload_is_full(self, name):
    """Check if upload valve (by name) is full.

    Arguments:
      name {str} -- name of valve.

    Returns:
      bool -- True if upload valve is full, False otherwise.
    """
    if name in self.upload_history:
      return self.upload_history[name].is_full()
    return False
