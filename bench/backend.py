#!/usr/bin/env python3
"""Tiny HTTP backend that simulates a server with `c` workers and a FCFS queue.

Service time per request is drawn from a distribution (or forced via ?ms=N),
then "executed" by holding one of `c` worker slots for that long. Sleeping
while holding a slot models a CPU-bound worker pool without burning CPU, so
many backends can run on one laptop.

usage: backend.py PORT [--workers C] [--dist fixed:5 | exp:5 | bimodal:2,80,0.1]
                       [--speed 1.0]
"""
import argparse
import asyncio
import random
import time


def make_dist(spec):
    kind, _, args = spec.partition(":")
    if kind == "fixed":
        v = float(args)
        return lambda: v
    if kind == "exp":
        m = float(args)
        return lambda: random.expovariate(1.0 / m)
    if kind == "bimodal":
        a, b, p = (float(x) for x in args.split(","))
        return lambda: random.expovariate(1.0 / (b if random.random() < p else a))
    raise SystemExit(f"bad dist {spec}")


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", type=int)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--dist", default="fixed:5")
    ap.add_argument("--speed", type=float, default=1.0,
                    help="capacity multiplier; service time is divided by this")
    o = ap.parse_args()
    dist = make_dist(o.dist)
    sem = asyncio.Semaphore(o.workers)

    async def handle(reader, writer):
        try:
            line = await reader.readline()
            while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                pass
            path = line.split(b" ")[1].decode() if b" " in line else "/"
            ms = None
            if "ms=" in path:
                ms = float(path.split("ms=")[1].split("&")[0])
            svc = (ms if ms is not None else dist()) / o.speed
            t0 = time.monotonic()
            async with sem:
                t1 = time.monotonic()
                await asyncio.sleep(svc / 1000.0)
            body = (f"port={o.port} svc_ms={svc:.2f} "
                    f"wait_ms={(t1 - t0) * 1000:.2f}\n").encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                         b"X-Port: %d\r\nConnection: close\r\n\r\n%s"
                         % (len(body), o.port, body))
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", o.port, backlog=4096)
    async with srv:
        await srv.serve_forever()


asyncio.run(main())
