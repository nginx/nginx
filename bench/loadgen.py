#!/usr/bin/env python3
"""Open-loop Poisson load generator (avoids coordinated omission).

Requests are scheduled at Poisson arrival times regardless of whether earlier
ones have completed; latency is measured from the *scheduled* send time.

usage: loadgen.py URL --rate RPS --duration S [--paths /a,/b --weights 9,1]
prints JSON summary; per-request CSV with --csv FILE
"""
import argparse
import asyncio
import json
import random
import time
from urllib.parse import urlparse


def pct(xs, p):
    if not xs:
        return float("nan")
    xs = sorted(xs)
    k = min(len(xs) - 1, int(p / 100.0 * len(xs)))
    return xs[k]


async def one(host, port, path, sched, results):
    try:
        r, w = await asyncio.open_connection(host, port)
        w.write(f"GET {path} HTTP/1.0\r\nHost: x\r\n\r\n".encode())
        await w.drain()
        data = await r.read()
        w.close()
        status = int(data.split(b" ", 2)[1]) if data else 0
        xp = b""
        if b"X-Port: " in data:
            xp = data.split(b"X-Port: ", 1)[1].split(b"\r\n", 1)[0]
        results.append((sched, time.monotonic() - sched, status,
                        xp.decode(), path))
    except Exception:
        results.append((sched, time.monotonic() - sched, 0, "", path))


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--rate", type=float, required=True)
    ap.add_argument("--duration", type=float, default=10)
    ap.add_argument("--warmup", type=float, default=0.2,
                    help="fraction of requests discarded from stats")
    ap.add_argument("--paths", default="/")
    ap.add_argument("--weights", default=None)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--csv")
    o = ap.parse_args()
    random.seed(o.seed)
    u = urlparse(o.url)
    paths = o.paths.split(",")
    weights = [float(x) for x in o.weights.split(",")] if o.weights else None

    results, tasks = [], []
    start = time.monotonic()
    t = start
    while t - start < o.duration:
        t += random.expovariate(o.rate)
        delay = t - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)
        path = random.choices(paths, weights)[0]
        tasks.append(asyncio.create_task(one(u.hostname, u.port, path, t,
                                             results)))
    await asyncio.gather(*tasks)

    results.sort()
    keep = results[int(len(results) * o.warmup):]
    lat = [x[1] * 1000 for x in keep if x[2] == 200]
    by_port = {}
    for x in keep:
        by_port[x[3]] = by_port.get(x[3], 0) + 1
    print(json.dumps({
        "n": len(keep), "ok": len(lat),
        "mean": sum(lat) / max(1, len(lat)),
        "p50": pct(lat, 50), "p95": pct(lat, 95), "p99": pct(lat, 99),
        "by_port": by_port}))
    if o.csv:
        with open(o.csv, "w") as f:
            f.write("sched,lat_ms,status,port,path\n")
            for x in results:
                f.write(f"{x[0]:.6f},{x[1]*1000:.3f},{x[2]},{x[3]},{x[4]}\n")


asyncio.run(main())
