import sys, time
sys.path.insert(0, '.')
from lbsim import *
def bks(): return [Backend(0, 1, 1.0), Backend(1, 1, 1/3), Backend(2, 1, 2/15)]
wl = exp_workload(2.0)
r = rate_for(0.6, bks(), wl)
print("rate", r)
for b in [RoundRobin(), LeastConn(), Random(True), LeastTime(), LeastTime(bucket=1), LeastTime(inflight=True), ServiceTimeSED(), PeakEWMA(), LeastWork(learn_speed=True), Oracle()]:
    t=time.time(); s = Sim(bks(), b, wl, r, 50000, seed=1).run()
    print(f"{b.name:28s} mean={s['mean']:7.2f} p99={s['p99']:8.2f} share={s['share']} ({time.time()-t:.1f}s)")
