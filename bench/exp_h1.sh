#!/bin/sh
# H1: sub-20ms backends, least_time bucket size. Real nginx, laptop-scale.
OUT=../results/h1_real.jsonl
: > $OUT
B="--backend 9001:1:exp:2 --backend 9002:1:exp:6 --backend 9003:1:exp:15"
for rate in 250 450; do
  for seed in 1 2 3; do
    for v in "b20:least_conn" "b20:least_time header" "b5:least_time header" "b1:least_time header"; do
      bin=${v%%:*}; bal=${v#*:}
      NGINX_BIN=../build/bin/nginx-$bin python3 run_scenario.py --balancer "$bal" $B \
        --rate $rate --duration 20 --seed $seed \
        | python3 -c "import json,sys; d=json.load(sys.stdin); d.update(variant='$bin', rate=$rate, seed=$seed); print(json.dumps(d))" >> $OUT
    done
  done
done
