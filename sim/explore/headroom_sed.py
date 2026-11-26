"""Headroom, part 2: adds shortest expected delay with the true server speeds (run after headroom.py)."""
import sys, json, math, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
OUT = os.path.join(os.path.dirname(os.path.dirname(HERE)), "results", "sim_headroom.json")
from multiprocessing import Pool
import experiments
from lbsim import RoundRobin

class SEDTrue(RoundRobin):
    """Shortest expected delay with the TRUE server speeds (non-clairvoyant on request cost)."""
    name = "sed_true"
    def select(self, sim, peers, req, now):
        return min(peers, key=lambda p: ((p.conns + 1) / sim.backends[p.idx].speed, sim.rng.random()))

experiments.BAL["sed_true"] = lambda: SEDTrue()
from experiments import run_job
SC = ["fast3", "slow3", "hetero8", "big16", "lognorm_het", "bimodal4", "bimodal4_het", "homog8"]
jobs = [dict(scenario=s, util=u, balancer="sed_true", seed=k, n=200000)
        for s in SC for u in (0.7, 0.85) for k in range(1, 11)]
if __name__ == "__main__":
    with Pool() as p:
        rows = p.map(run_job, jobs, chunksize=1)
    old = json.load(open(OUT))
    json.dump(old + rows, open(OUT, "w"))
    by = {}
    for r in old + rows:
        by.setdefault((r["scenario"], r["util"], r["balancer"]), {})[r["seed"]] = r["p99"]
    gm = lambda a, b, s, u: math.exp(sum(math.log(by[(s,u,a)][k]/by[(s,u,b)][k]) for k in range(1,11))/10)
    print("scenario util | p99 patched  sed_true  oracle | patched/sed_true  sed_true/oracle")
    for s in SC:
        for u in (0.7, 0.85):
            m = lambda b: sum(by[(s,u,b)].values())/10
            print(f"{s:13s} {u:.2f} | {m('p123_b5_s3'):7.1f} {m('sed_true'):8.1f} {m('oracle'):7.1f} | {gm('p123_b5_s3','sed_true',s,u):.2f}x  {gm('sed_true','oracle',s,u):.2f}x")
