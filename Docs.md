# least_time evidence

Evidence for two proposed changes to the nginx `least_time` upstream balancer:

1. Fixed-point averages, a bug fix. Averages are kept in whole milliseconds, so they can be
   off by up to 10 ms, and fast servers converge to about 10 ms.
2. The `bucket=time` and `smooth=time` parameters of `least_time`.

The code lives on other branches of this fork:

| branch | content |
| --- | --- |
| `lt-fixed-point` | change 1 (one commit on nginx master) |
| `lt-smooth` | change 1, then `bucket`, then `smooth` (three commits) |
| `lt-bucket` | change 1, then `bucket` (intermediate, used by the benchmarks) |
| `lt-trace` | experiment-only prototype with trace logging and compile-time knobs |
| `least-time-evidence` | only the files described here, no nginx code |
| `least-time-work` | `lt-smooth` plus these files: everything in one place |

## Reports

- [results/sim_pr.md](results/sim_pr.md): simulation, 12 scenarios × 4 loads, 20 paired
  seeds × 300,000 requests per cell, plus a bucket × smooth sweep (10 seeds × 200,000).
- [results/sim_validation.md](results/sim_validation.md): the simulator checked against exact
  queueing-theory formulas (also at the end of `sim_pr.md`).
- [results/linux_pr.md](results/linux_pr.md): real nginx on Linux, 18 configurations ×
  6 variants × 5 paired repetitions, with a simulator-vs-real comparison.
- [pr/PR1.md](pr/PR1.md), [pr/PR2.md](pr/PR2.md): pull request descriptions;
  [pr/](pr/) also holds the commit messages.
- [PLAN.md](PLAN.md): working notes, with the earlier hypotheses (H1 to H6) and
  prototype measurements.

## Layout

| path | content |
| --- | --- |
| `sim/lbsim.py` | discrete-event simulator of nginx balancers. `LeastTime` is stock; `LeastTimePatch` reproduces the patched C arithmetic. |
| `sim/experiments.py` | scenarios and job sets (`pr`, `sweep`, and the earlier `h1`... sets) |
| `sim/report_pr.py` | builds `results/sim_pr.md` and the simulation figures |
| `sim/validate.py` | checks the simulator against queueing-theory formulas (M/M/1, M/M/c, M/G/1, PS) |
| `bench/linux/` | real-nginx benchmark: Dockerfile, Go backend and open-loop load generator, `run.py`, `matrix.sh`, `report_linux.py` |
| `bench/*.py`, `bench/exp_*.sh` | earlier macOS harness (Python backends, `-O0` builds), superseded by `bench/linux/` |
| `build/mkvariant.sh` | builds `lt-trace` variants for the macOS harness |
| `patches/` | the three nginx patches, the nginx-tests change and the nginx.org docs change |
| `results/` | raw results (`*.json`, `*.jsonl`), reports and figures |

## Reproducing

### Simulation

Python 3, no dependencies. From this branch's root:

    python3 sim/experiments.py pr --seeds 20 --n 300000
    python3 sim/experiments.py sweep --seeds 10 --n 200000
    python3 sim/validate.py          # about a minute
    python3 sim/report_pr.py

Jobs run in parallel on all cores (`--jobs` to change it).

### Real nginx (Linux)

The benchmark expects a workspace where this branch sits next to the nginx sources:

    git clone -b least-time-evidence https://github.com/psygo/nginx_plus.git work
    cd work
    git clone https://github.com/psygo/nginx_plus.git nginx
    git -C nginx worktree add ../nginx-fp     lt-fixed-point
    git -C nginx worktree add ../nginx-bucket lt-bucket
    git -C nginx worktree add ../nginx-smooth lt-smooth

`nginx/` must have `master` (the stock build is taken from it with `git archive`). Then:

    docker build -t ltbench bench/linux
    docker run -d --name ltbench -v "$PWD:/w" ltbench sleep infinity
    docker exec ltbench sh /w/bench/linux/build.sh
    docker exec ltbench sh /w/bench/linux/matrix.sh      # about 6.5 h
    python3 bench/linux/report_linux.py

The runs used Docker Desktop on an Apple M2 Max with 12 vCPUs. CPU sets are nginx 0-3,
backends 4-7 and load generator 8-11, so the VM needs at least 12 CPUs. Keep the host
idle while the matrix runs.

### nginx-tests

The test changes are in `patches/tests-pr2-least_time-bucket-smooth.patch`. Apply it to
nginx/nginx-tests, build `lt-smooth` with default modules plus `--with-stream`, and run:

    TEST_NGINX_BINARY=/path/to/nginx prove upstream*.t stream_upstream*.t

When running as root, add `TEST_NGINX_GLOBALS="user root;"`.
