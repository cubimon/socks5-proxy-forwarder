from time import time
from valve import Valve

class ProcessBandwidthMonitor:

    def __init__(self, limitations={}, lifetime=1.0):
        self.limitations = limitations
        self.lifetime = lifetime
        self.download_history = {}
        self.upload_history = {}

    def download_event(self, process_name, size):
        if process_name not in self.limitations:
            return
        if process_name not in self.download_history:
                self.download_history[process_name] = \
                        Valve(self.limitations[process_name][0], self.lifetime)
        self.download_history[process_name].add(size)

    def upload_event(self, process_name, size):
        if process_name not in self.limitations:
            return
        if process_name not in self.upload_history:
                self.upload_history[process_name] = \
                        Valve(self.limitations[process_name][1], self.lifetime)
        self.upload_history[process_name].add(size)

    def download_is_full(self, process_name):
        if process_name in self.download_history:
            return self.download_history[process_name].is_full()
        return False

    def upload_is_full(self, process_name):
        if process_name in self.upload_history:
            return self.upload_history[process_name].is_full()
        return False

