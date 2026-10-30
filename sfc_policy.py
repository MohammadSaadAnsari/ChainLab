"""Small, testable policy model shared by the controller and its HTTP API."""

from collections import deque
from ipaddress import ip_address
import time


class PolicyState:
    """Classify h1 -> h2 flows and retain short-lived IDS quarantines."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.trusted_tcp_ports = {8080}
        self.quarantined = {}  # source IP -> monotonic expiry
        self.events = deque(maxlen=40)

    def record(self, kind, detail):
        self.events.appendleft({"time": time.strftime("%H:%M:%S"),
                                "kind": kind, "detail": detail})

    def expire(self):
        now = self.clock()
        for source, deadline in list(self.quarantined.items()):
            if deadline <= now:
                del self.quarantined[source]
                self.record("release", f"{source} quarantine expired")

    def classify_tcp(self, source, destination_port):
        self.expire()
        if source in self.quarantined:
            return "drop"
        return "direct" if destination_port in self.trusted_tcp_ports else "chain"

    def set_tcp_policy(self, destination_port, action):
        if type(destination_port) is not int or not 1 <= destination_port <= 65535:
            raise ValueError("dst_port must be an integer from 1 to 65535")
        if action not in ("direct", "chain"):
            raise ValueError("action must be 'direct' or 'chain'")
        if action == "direct":
            self.trusted_tcp_ports.add(destination_port)
        else:
            self.trusted_tcp_ports.discard(destination_port)
        self.record("policy", f"TCP/{destination_port} -> {action}")

    def quarantine(self, source, seconds=60):
        ip_address(source)  # Reject malformed addresses before touching the dataplane.
        if type(seconds) is not int or not 1 <= seconds <= 3600:
            raise ValueError("seconds must be an integer from 1 to 3600")
        self.quarantined[source] = self.clock() + seconds
        self.record("alert", f"{source} quarantined for {seconds}s")

    def clear_quarantine(self, source=None):
        if source is None:
            sources = list(self.quarantined)
            self.quarantined.clear()
        else:
            sources = [source] if source in self.quarantined else []
            self.quarantined.pop(source, None)
        for item in sources:
            self.record("release", f"{item} released by operator")
        return sources

    def snapshot(self):
        self.expire()
        now = self.clock()
        return {
            "trusted_tcp_ports": sorted(self.trusted_tcp_ports),
            "default_tcp_action": "chain",
            "quarantined": {source: max(0, round(deadline - now, 1))
                            for source, deadline in self.quarantined.items()},
            "events": list(self.events),
        }
