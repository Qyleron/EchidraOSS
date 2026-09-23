#!/usr/bin/env python3
"""Sends a sustained HTTP request flood at a running Echidra honeypot.

Used to reproduce the load test from:
https://qyleron.com/blog/defending-botnet-floods-container-cpu/

Usage:
    python3 benchmarks/flood_test.py
    python3 benchmarks/flood_test.py --url http://127.0.0.1:8080/ --rate 100 --duration 10
"""

import argparse
import asyncio
import time

import aiohttp


async def request(session, url):
    try:
        async with session.get(url) as r:
            await r.read()
    except Exception:
        pass


async def run(url, rate, duration):
    connector = aiohttp.TCPConnector(limit=200)
    async with aiohttp.ClientSession(connector=connector) as session:
        start = time.monotonic()
        sent = 0

        while time.monotonic() - start < duration:
            batch_start = time.monotonic()

            tasks = [request(session, url) for _ in range(rate)]
            await asyncio.gather(*tasks)
            sent += rate

            elapsed = time.monotonic() - batch_start
            if elapsed < 1:
                await asyncio.sleep(1 - elapsed)

        actual = sent / (time.monotonic() - start)
        print(f"Sent: {sent} requests")
        print(f"Average rate: {actual:.1f} requests/sec")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8080/", help="Target honeypot HTTP URL")
    parser.add_argument("--rate", type=int, default=100, help="Requests per second")
    parser.add_argument("--duration", type=int, default=10, help="Flood duration in seconds")
    args = parser.parse_args()

    asyncio.run(run(args.url, args.rate, args.duration))


if __name__ == "__main__":
    main()
