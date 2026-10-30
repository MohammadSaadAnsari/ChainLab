#!/usr/bin/env python3
"""Generate measured h1 traffic without depending on curl or iperf."""

import argparse
import http.client
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("get", "upload", "attack"))
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--size-kib", type=int, default=1024)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 1 <= args.size_kib <= 4096:
        parser.error("port must be 1..65535 and size-kib must be 1..4096")

    connection = http.client.HTTPConnection("10.0.0.2", args.port, timeout=35)
    method = "POST" if args.mode == "upload" else "GET"
    path = "/upload" if args.mode == "upload" else "/attack" if args.mode == "attack" else "/"
    body = b"X" * (args.size_kib * 1024) if args.mode == "upload" else None
    started = time.monotonic()
    try:
        connection.request(method, path, body=body)
        response = connection.getresponse()
        text = response.read().decode("utf-8", errors="replace")
        elapsed = time.monotonic() - started
        print(f"TCP/{args.port} {method} {path}: HTTP {response.status}, "
              f"{elapsed:.2f}s, {text.strip()[:100]}")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
