from time import time
from valve import Valve

class BandwidthMonitor:

    def __init__(self, limitations={}, lifetime=1.0):
        self.limitations = limitations
        self.lifetime = lifetime
        self.download_history = {}
        self.upload_history = {}

    def download_event(self, name, size):
        if name not in self.limitations:
            return
        if name not in self.download_history:
                self.download_history[name] = \
                        Valve(self.limitations[name][0], self.lifetime)
        self.download_history[name].add(size)

    def upload_event(self, name, size):
        if name not in self.limitations:
            return
        if name not in self.upload_history:
                self.upload_history[name] = \
                        Valve(self.limitations[name][1], self.lifetime)
        self.upload_history[name].add(size)

    def download_is_full(self, name):
        if name in self.download_history:
            return self.download_history[name].is_full()
        return False

    def upload_is_full(self, name):
        if name in self.upload_history:
            return self.upload_history[name].is_full()
        return False

