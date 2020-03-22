from operator import itemgetter
from time import time as get_time

class Valve:

    def __init__(self, bandwidth, lifetime=1.0):
        self.bandwidth = bandwidth
        self.lifetime = lifetime
        self.history = []

    def add(self, value):
        self.check()
        self.history.append((get_time(), value))

    def get(self):
        self.check()
        return sum(map(itemgetter(1), self.history))

    def get_remaining(self):
        return self.bandwidth - self.get()

    def is_full(self):
        return self.get_remaining() <= 0

    def check(self):
        current_time = get_time()
        self.history = [(time, value) \
                for time, value in self.history \
                if current_time - time < self.lifetime]

