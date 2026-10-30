"""Demo IDS: inspect HTTP payloads and alert Ryu over eth0 management LAN.

This intentionally uses a small, explainable signature rather than pretending
to perform general intrusion detection. Replace inspect() with Snort/Suricata
alert ingestion when extending the project.
"""

import json
import os
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from scapy.all import IP, Raw, TCP, sniff
from signature import is_attack


API = os.environ.get("SFC_CONTROLLER_URL", "http://host.docker.internal:8080")
TOKEN = os.environ["SFC_API_TOKEN"]
last_alert = {}


def deliver(source):
    body = json.dumps({"src_ip": source,
                       "signature": "demo HTTP /attack signature"}).encode()
    request = Request(f"{API}/sfc/alerts", data=body,
                      headers={"Content-Type": "application/json",
                               "X-SFC-Token": TOKEN}, method="POST")
    for attempt in range(3):
        try:
            with urlopen(request, timeout=3) as response:
                print(f"[IDS] Alert accepted by controller: HTTP {response.status}",
                      flush=True)
                return
        except (HTTPError, URLError, TimeoutError) as exc:
            print(f"[IDS] Alert attempt {attempt + 1} failed: {exc}", flush=True)
            time.sleep(0.5)


def inspect(pkt):
    if IP not in pkt or TCP not in pkt or Raw not in pkt:
        return
    ip, segment = pkt[IP], pkt[TCP]
    if segment.dport != 80:
        return
    payload = bytes(pkt[Raw].load)
    if not is_attack(payload):
        return
    now = time.monotonic()
    if now - last_alert.get(ip.src, 0) < 3:
        return
    last_alert[ip.src] = now
    print(f"[IDS] Signature hit from {ip.src}; alerting controller", flush=True)
    # Let the triggering request complete so the presenter can show the
    # subsequent request being blocked. Forwarding does not wait on sniff().
    timer = threading.Timer(0.7, deliver, args=(ip.src,))
    timer.daemon = True
    timer.start()


if __name__ == "__main__":
    sniff(iface="eth1", prn=inspect, store=False)
