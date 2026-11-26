"""Why does least_time lose to least_conn on bimodal service times?"""
import sys; sys.path.insert(0, '.')
from lbsim import *
from experiments import stat
def bks(): return [Backend(i, 1, 1.0) for i in range(4)]
wl = classes_workload([(0.9, 2.0), (0.1, 80.0)])
for util in (0.5, 0.85):
    r = rate_for(util, bks(), wl)
    print(f"util={util}")
    for mk in [lambda: LeastConn(), lambda: LeastTime(), lambda: LeastTime(alpha=0.01),
               lambda: LeastTime(alpha=0.002), lambda: LeastTime(bucket=100),
               lambda: LeastTime(bucket=1000)]:
        p99 = [Sim(bks(), mk(), wl, r, 100000, seed=s).run()['p99'] for s in range(1, 6)]
        m, ci = stat(p99); print(f"  {mk().name:24s} p99={m:7.1f} ±{ci:.1f}")
