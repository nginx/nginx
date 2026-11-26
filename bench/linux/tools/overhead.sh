#!/bin/sh
# Latency of a direct request to one backend (no nginx), with and without
# SCHED_IDLE spinners keeping the vCPUs awake.  Usage: overhead.sh [spin]
B=/build/bin
if [ "$1" = spin ]; then
  for c in $(seq 0 11); do taskset -c $c chrt --idle 0 sh -c 'while :; do :; done' & done
fi
taskset -c 4-7 $B/backend -port 9101 -workers 64 >/dev/null 2>&1 &
BK=$!
sleep 0.5
for d in exp:0.001 exp:2; do
  printf "%s %s: " "${1:-nospin}" $d
  taskset -c 8-11 $B/loadgen -url http://127.0.0.1:9101/ -rate 200 -duration 8s -warmup 1s -dist $d \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print('lat p50 %.3f mean %.3f p99 %.3f | lag p50 %.3f p99 %.3f' % (d['p50'], d['mean'], d['p99'], d['send_lag_p50'], d['send_lag_p99']))"
done
kill $BK
[ "$1" = spin ] && kill $(jobs -p) 2>/dev/null
wait 2>/dev/null
true
