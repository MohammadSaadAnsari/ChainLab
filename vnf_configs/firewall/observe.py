"""Log selected first-stage packets while nftables enforces the firewall."""

from scapy.all import IP, Raw, TCP, sniff


seen = set()


def inspect(pkt):
    if IP not in pkt or TCP not in pkt:
        return
    ip, seg = pkt[IP], pkt[TCP]
    key = (ip.src, seg.sport, ip.dst, seg.dport)
    if seg.flags & 0x02 and key not in seen:
        seen.add(key)
        if len(seen) > 2000:
            seen.clear()
        print(f"[FIREWALL] Inspect {ip.src}:{seg.sport} -> {ip.dst}:{seg.dport}",
              flush=True)
    if Raw in pkt and bytes(pkt[Raw].load).startswith(b"GET "):
        line = bytes(pkt[Raw].load).split(b"\r\n", 1)[0][:100]
        print(f"[FIREWALL] HTTP {line.decode('ascii', errors='replace')}",
              flush=True)


if __name__ == "__main__":
    sniff(iface="eth1", prn=inspect, store=False)
