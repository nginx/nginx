"""Headroom: patched least_time vs a clairvoyant oracle (run first; writes results/sim_headroom.json)."""
import sys, json, math, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
OUT = os.path.join(os.path.dirname(os.path.dirname(HERE)), "results", "sim_headroom.json")
from multiprocessing import Pool
from experiments import run_job
SC = ["fast3", "slow3", "hetero8", "big16", "lognorm_het", "bimodal4", "bimodal4_het", "homog8"]
BALS = ["least_conn", "lt", "p123_b5_s3", "oracle"]
jobs = [dict(scenario=s, util=u, balancer=b, seed=k, n=200000)
        for s in SC for u in (0.7, 0.85) for b in BALS for k in range(1, 11)]
if __name__ == "__main__":
    with Pool() as p:
        rows = p.map(run_job, jobs, chunksize=1)
    json.dump(rows, open(OUT, "w"))
    by = {}
    for r in rows:
        by.setdefault((r["scenario"], r["util"], r["balancer"]), {})[r["seed"]] = r["p99"]
    print("scenario util | p99: least_conn stock patched oracle | patched/oracle")
    for s in SC:
        for u in (0.7, 0.85):
            v = {b: sum(by[(s, u, b)].values()) / 10 for b in BALS}
            g = math.exp(sum(math.log(by[(s,u,"p123_b5_s3")][k]/by[(s,u,"oracle")][k]) for k in range(1,11))/10)
            print(f"{s:13s} {u:.2f} | {v['least_conn']:7.1f} {v['lt']:7.1f} {v['p123_b5_s3']:7.1f} {v['oracle']:7.1f} | {g:.2f}x")
