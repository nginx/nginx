#!/usr/bin/env python3
"""Start backends + nginx with a given balancer, drive load, collect results.

usage: run_scenario.py --balancer "least_time header" \
          --backend 9001:1:fixed:2 --backend 9002:1:fixed:15 \
          --rate 100 --duration 20 [--workers 1] [--zone] [--trace OUT]

--backend PORT:WORKERS:DIST[:SPEED]   (DIST as in backend.py, e.g. exp:5)
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
NGINX = os.environ.get("NGINX_BIN", os.path.join(ROOT, "nginx/objs-debug/nginx"))

CONF = """
worker_processes {workers};
daemon off;
master_process on;
error_log {prefix}/error.log notice;
pid {prefix}/nginx.pid;
events {{ worker_connections 4096; }}
http {{
    access_log off;
    upstream u {{
        {zone}
        {balancer};
{servers}
    }}
    server {{
        listen 127.0.0.1:{port};
        location / {{
            proxy_pass http://u;
            proxy_next_upstream off;
            add_header X-Port $upstream_addr always;
        }}
    }}
}}
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--balancer", default="least_conn")
    ap.add_argument("--backend", action="append", required=True)
    ap.add_argument("--rate", type=float, default=50)
    ap.add_argument("--duration", type=float, default=10)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--zone", action="store_true")
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--paths", default="/")
    ap.add_argument("--weights")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--trace", help="copy error.log (lt-trace lines) here")
    ap.add_argument("--csv")
    o = ap.parse_args()

    prefix = tempfile.mkdtemp(prefix="ngxbench-")
    procs, servers = [], []
    try:
        for spec in o.backend:
            parts = spec.split(":")
            port, workers = parts[0], parts[1]
            dist = parts[2] + ":" + parts[3]
            speed = parts[4] if len(parts) > 4 else "1"
            procs.append(subprocess.Popen(
                [sys.executable, os.path.join(HERE, "backend.py"), port,
                 "--workers", workers, "--dist", dist, "--speed", speed]))
            servers.append(f"        server 127.0.0.1:{port} max_fails=0;")
        conf = CONF.format(workers=o.workers, prefix=prefix, port=o.port,
                           zone="zone u 1m;" if o.zone else "",
                           balancer=o.balancer, servers="\n".join(servers))
        with open(os.path.join(prefix, "nginx.conf"), "w") as f:
            f.write(conf)
        os.makedirs(os.path.join(prefix, "logs"), exist_ok=True)
        ngx = subprocess.Popen([NGINX, "-p", prefix, "-c",
                                os.path.join(prefix, "nginx.conf")],
                               stderr=subprocess.DEVNULL)
        procs.append(ngx)
        time.sleep(1.0)
        cmd = [sys.executable, os.path.join(HERE, "loadgen.py"),
               f"http://127.0.0.1:{o.port}/", "--rate", str(o.rate),
               "--duration", str(o.duration), "--paths", o.paths,
               "--seed", str(o.seed)]
        if o.weights:
            cmd += ["--weights", o.weights]
        if o.csv:
            cmd += ["--csv", o.csv]
        out = subprocess.run(cmd, capture_output=True, text=True).stdout
        res = json.loads(out)
        res["balancer"] = o.balancer
        res["workers"] = o.workers
        res["zone"] = o.zone
        print(json.dumps(res))
        if o.trace:
            shutil.copy(os.path.join(prefix, "error.log"), o.trace)
    finally:
        for p in reversed(procs):
            p.send_signal(signal.SIGTERM if p is not procs[-1] else signal.SIGQUIT)
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(prefix, ignore_errors=True)


if __name__ == "__main__":
    main()
