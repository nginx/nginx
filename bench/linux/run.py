#!/usr/bin/env python3
"""Paired, randomized real-nginx benchmark (runs inside the bench container).

Every repetition r runs all variants back to back, in an order shuffled with
seed r, each against fresh backends and the same load (loadgen -seed r: same
arrival times and per-request costs).  Scenarios mirror sim/experiments.py.

CPU layout (12 vCPUs): nginx 0-3, backends 4-7, load generator 8-11.

  python3 run.py --scenarios fast3,bimodal4 --utils 0.7,0.85 --reps 10 \
                 --out /w/results/linux_pr.jsonl
"""
import argparse
import json
import math
import os
import random
import signal
import socket
import subprocess
import sys
import time

BIN = "/build/bin"
RUN = "/tmp/ltbench"

CPU_NGINX = "0-3"
CPU_BACKENDS = "4-7"
CPU_LOADGEN = "8-11"

HETERO8 = [2, 2, 1, 1, 1, 1, 0.5, 0.5]

# name: backends (speed list), dist, extra
SCENARIOS = {
    "fast3":        dict(speeds=[1, 1 / 3, 2 / 15], dist="exp:2"),
    "slow3":        dict(speeds=[1, 1 / 3, 2 / 15], dist="exp:20", duration=90),
    "hetero8":      dict(speeds=HETERO8, dist="exp:10"),
    "lognorm_het":  dict(speeds=HETERO8, dist="lognormal:5,1"),
    "bimodal4":     dict(speeds=[1] * 4, dist="bimodal:2,80,0.1"),
    "bimodal4_het": dict(speeds=[2, 1, 1, 0.5], dist="bimodal:2,80,0.1"),
    "homog8":       dict(speeds=[1] * 8, dist="exp:10"),
    "slowdown":     dict(speeds=[1] * 4, dist="exp:10", duration=60,
                         slow="25:20:0.25", window="20:40"),
}

# name: (binary, balancing directive)
VARIANTS = {
    "least_conn":  ("stock", "least_conn"),
    "lt":          ("stock", "least_time header"),
    "p1":          ("p1", "least_time header"),
    "p12_b5":      ("p12", "least_time header bucket=5ms"),
    "p123_b5_s3":  ("p123", "least_time header bucket=5ms smooth=3s"),
    "p13_s3":      ("p123", "least_time header smooth=3s"),
}

NGINX_CONF = """
worker_processes {workers};
pid {run}/nginx.pid;
error_log {run}/error.log warn;
worker_rlimit_nofile 65536;

events {{
    worker_connections 16384;
}}

http {{
    access_log off;
    keepalive_requests 1000000;

    upstream u {{
        {zone}
        {directive};
{servers}
    }}

    server {{
        listen 127.0.0.1:8899 backlog=8192{reuseport};

        location / {{
            proxy_pass http://u;
            proxy_next_upstream off;
            proxy_connect_timeout 5s;
            proxy_read_timeout 60s;
            add_header X-Upstream $upstream_addr;
        }}
    }}
}}
"""


def mean_cost(dist):
    kind, args = dist.split(":")
    a = [float(x) for x in args.split(",")]
    if kind == "exp":
        return a[0]
    if kind == "bimodal":
        return (1 - a[2]) * a[0] + a[2] * a[1]
    if kind == "lognormal":
        return a[0] * math.exp(a[1] ** 2 / 2)
    raise ValueError(dist)


def capacity_rps(sc):
    return sum(sc["speeds"]) / mean_cost(sc["dist"]) * 1000.0


def wait_port(port, timeout=5.0):
    t = time.time() + timeout
    while time.time() < t:
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError(f"port {port} not listening")


def start_backends(sc):
    procs = []
    for i, s in enumerate(sc["speeds"]):
        port = 9001 + i
        cmd = ["taskset", "-c", CPU_BACKENDS, f"{BIN}/backend",
               "-port", str(port), "-workers", "1", "-speed", repr(s)]
        if sc.get("slow") and i == 0:
            cmd += ["-slow", sc["slow"]]
        procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL))
    for i in range(len(sc["speeds"])):
        wait_port(9001 + i)
    return procs


def start_nginx(variant, sc, workers, zone):
    binary, directive = VARIANTS[variant]
    os.makedirs(RUN, exist_ok=True)
    servers = "\n".join(f"        server 127.0.0.1:{9001 + i} max_fails=0;"
                        for i in range(len(sc["speeds"])))
    conf = NGINX_CONF.format(
        workers=workers, run=RUN, directive=directive, servers=servers,
        zone="zone u 1m;" if zone else "",
        reuseport=" reuseport" if workers > 1 else "")
    with open(f"{RUN}/nginx.conf", "w") as f:
        f.write(conf)
    p = subprocess.Popen(["taskset", "-c", CPU_NGINX, f"{BIN}/nginx-{binary}",
                          "-p", RUN, "-c", f"{RUN}/nginx.conf",
                          "-g", "daemon off;"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    wait_port(8899)
    return p


def stop(procs):
    for p in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
    for p in procs:
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()


def run_one(variant, scname, util, rep, args):
    sc = SCENARIOS[scname]
    rate = util * capacity_rps(sc)
    duration = sc.get("duration", args.duration)
    backends = start_backends(sc)
    nginx = None
    try:
        nginx = start_nginx(variant, sc, args.workers, args.zone)
        cmd = ["taskset", "-c", CPU_LOADGEN, f"{BIN}/loadgen",
               "-url", "http://127.0.0.1:8899/", "-rate", f"{rate:.3f}",
               "-duration", f"{duration}s", "-warmup", f"{args.warmup}s",
               "-dist", sc["dist"], "-seed", str(rep)]
        if sc.get("window"):
            cmd += ["-window", sc["window"]]
        out = subprocess.run(cmd, capture_output=True, text=True, check=True,
                             env=dict(os.environ, GOGC="400"))
        res = json.loads(out.stdout)
    finally:
        stop(([nginx] if nginx else []) + backends)
    res.update(scenario=scname, util=util, variant=variant, rep=rep,
               workers=args.workers, zone=args.zone,
               directive=VARIANTS[variant][1], binary=VARIANTS[variant][0])
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default="fast3,hetero8,bimodal4")
    ap.add_argument("--utils", default="0.7,0.85")
    ap.add_argument("--variants", default=",".join(VARIANTS))
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--rep-start", type=int, default=1)
    ap.add_argument("--duration", type=int, default=30)
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--zone", action="store_true")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    variants = a.variants.split(",")
    cells = [(s, float(u)) for s in a.scenarios.split(",")
             for u in a.utils.split(",")]
    total = len(cells) * a.reps * len(variants)
    done = 0
    t0 = time.time()
    with open(a.out, "a") as f:
        for rep in range(a.rep_start, a.rep_start + a.reps):
            for scname, util in cells:
                order = variants[:]
                random.Random(rep * 7919 + sum(map(ord, scname))).shuffle(order)
                for v in order:
                    res = run_one(v, scname, util, rep, a)
                    f.write(json.dumps(res) + "\n")
                    f.flush()
                    done += 1
                    el = time.time() - t0
                    print(f"[{done}/{total} {el / 60:.0f}m, eta "
                          f"{el / done * (total - done) / 60:.0f}m] {scname} "
                          f"u={util} {v} rep={rep}: p99={res['p99']:.1f} "
                          f"err={res['errors']}", flush=True)


if __name__ == "__main__":
    main()
