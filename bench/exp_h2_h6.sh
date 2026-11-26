#!/bin/sh
# Real-nginx checks for H2 (workers without zone) and H6 (least_time vs
# least_conn under bimodal service times).
export NGINX_BIN=../build/bin/nginx-b20
tag() { python3 -c "import json,sys; d=json.load(sys.stdin); d.update($1); print(json.dumps(d))"; }

OUT=../results/h2_real.jsonl; : > $OUT
B=""; for p in 9001 9002 9003 9004 9005 9006 9007 9008; do B="$B --backend $p:1:exp:10"; done
for seed in 1 2 3; do
  for bal in least_conn "least_time header"; do
    python3 run_scenario.py --balancer "$bal" $B --rate 560 --duration 20 --seed $seed --workers 1 \
      | tag "dict(seed=$seed)" >> $OUT
    for z in "" "--zone"; do
      python3 run_scenario.py --balancer "$bal" $B --rate 560 --duration 20 --seed $seed --workers 8 $z \
        --trace /tmp/h2_trace_$seed.log | tag "dict(seed=$seed)" >> $OUT
    done
  done
done

OUT=../results/h6_real.jsonl; : > $OUT
B=""; for p in 9001 9002 9003 9004; do B="$B --backend $p:1:bimodal:2,80,0.1"; done
for rate in 205 285; do
  for seed in 1 2 3; do
    for bal in least_conn "least_time header"; do
      python3 run_scenario.py --balancer "$bal" $B --rate $rate --duration 30 --seed $seed \
        | tag "dict(seed=$seed, rate=$rate)" >> $OUT
    done
  done
done
