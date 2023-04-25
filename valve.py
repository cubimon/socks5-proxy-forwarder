from operator import itemgetter
from time import time as get_time

class Valve:
  """Manage network traffic in a single point like a water valve.
  Monitors the amount of traffic that passes this valve and determines
  if this valve is full depending on a given bandwidth.
  """

  def __init__(self, bandwidth, lifetime=1.0):
    """Creates valve.

    Arguments:
      bandwidth {int} -- bandwidth in bytes per second
      but in theory every unit is possible depending on user.

    Keyword Arguments:
      lifetime {float} -- time span to look in past 
      in seconds to ensure bandwidth.
      Traffic passed this valve after lifetime
      (default: {1.0})
    """
    self.bandwidth = bandwidth
    self.lifetime = lifetime
    self.history = []

  def add(self, value):
    """Adds traffic that went through this valve.

    Arguments:
      value {int} -- amount of traffic that passed this valve
    """
    self.check()
    self.history.append((get_time(), value))

  def get(self):
    """Return amount of traffic in this valve.
    
    Returns:
      int -- amount of traffic in this valve.
    """
    self.check()
    return sum(map(itemgetter(1), self.history))

  def get_remaining(self):
    """Get remaining traffic before valve is full.
    
    Returns:
      int -- amount of traffic before valve is full.
    """
    return self.bandwidth - self.get()

  def is_full(self):
    """Check if valve is full.
    
    Returns:
      bool -- return True if valve is full, False otherwise.
    """
    return self.get_remaining() <= 0

  def check(self):
    """Check if traffic passed this valve and remove if from history
    """
    current_time = get_time()
    self.history = [(time, value) \
        for time, value in self.history \
        if current_time - time < self.lifetime]

