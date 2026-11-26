// loadgen: open-loop Poisson load generator.
//
// Requests are scheduled in advance (exponential inter-arrival times) and
// each one is sent at its scheduled time on its own goroutine, whether or not
// earlier requests have completed.  Latency is measured from the scheduled
// time, so a stalled server cannot hide its queueing (no coordinated
// omission).
//
// The cost of each request (ms) is drawn here from -dist with -seed and sent
// as ?c=, so every balancer under test sees exactly the same arrivals and
// costs for a given seed.
//
//	loadgen -url http://127.0.0.1:8899/ -rate 500 -duration 30s -warmup 5s \
//	        -dist bimodal:2,80,0.1 -seed 1 [-raw lat.txt]
//
// dist: exp:MEAN | bimodal:A,B,P (exponential with mean B with prob P, else A)
//
//	| lognormal:MEDIAN,SIGMA
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type sampler func(r *rand.Rand) float64

// waitUntil sleeps until shortly before t, then spins: on a VM, timer
// wake-ups arrive up to several ms late, which would add to every measured
// latency (loadgen) or service time (backend).
func waitUntil(t time.Time) {
	if d := time.Until(t) - 2*time.Millisecond; d > 0 {
		time.Sleep(d)
	}
	for time.Now().Before(t) {
		runtime.Gosched()
	}
}

func pick(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	i := int(p * float64(len(xs)))
	if i >= len(xs) {
		i = len(xs) - 1
	}
	return xs[i]
}

func parseDist(s string) (sampler, error) {
	kind, args, _ := strings.Cut(s, ":")
	var a []float64
	for _, x := range strings.Split(args, ",") {
		v, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return nil, err
		}
		a = append(a, v)
	}
	switch kind {
	case "exp":
		return func(r *rand.Rand) float64 { return r.ExpFloat64() * a[0] }, nil
	case "bimodal":
		return func(r *rand.Rand) float64 {
			if r.Float64() < a[2] {
				return r.ExpFloat64() * a[1]
			}
			return r.ExpFloat64() * a[0]
		}, nil
	case "lognormal":
		mu := math.Log(a[0])
		return func(r *rand.Rand) float64 { return math.Exp(mu + a[1]*r.NormFloat64()) }, nil
	}
	return nil, fmt.Errorf("unknown dist %q", s)
}

type result struct {
	at   time.Duration // scheduled time from start
	lat  float64       // ms
	lag  float64       // ms between scheduled and actual send
	port string
	err  bool
}

func main() {
	url := flag.String("url", "http://127.0.0.1:8899/", "target")
	rate := flag.Float64("rate", 100, "requests per second (Poisson)")
	duration := flag.Duration("duration", 30*time.Second, "measured duration")
	warmup := flag.Duration("warmup", 5*time.Second, "discarded warm-up")
	dist := flag.String("dist", "exp:10", "cost distribution (ms)")
	seed := flag.Int64("seed", 1, "seed for arrivals and costs")
	raw := flag.String("raw", "", "write measured latencies (ms) here")
	window := flag.String("window", "", "a:b report an extra summary for requests scheduled in [a,b) s after warm-up")
	flag.Parse()

	smp, err := parseDist(*dist)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	total := *warmup + *duration
	rng := rand.New(rand.NewSource(*seed))

	type req struct {
		at   time.Duration
		cost float64
	}
	var plan []req
	for t := 0.0; ; {
		t += rng.ExpFloat64() / *rate
		at := time.Duration(t * float64(time.Second))
		if at >= total {
			break
		}
		plan = append(plan, req{at, smp(rng)})
	}

	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		MaxIdleConns:        4096,
		MaxIdleConnsPerHost: 4096,
		IdleConnTimeout:     60 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	results := make([]result, len(plan))
	var wg sync.WaitGroup
	start := time.Now()

	for i, p := range plan {
		waitUntil(start.Add(p.at))
		wg.Add(1)
		go func(i int, p req) {
			defer wg.Done()
			sched := start.Add(p.at)
			u := fmt.Sprintf("%s?c=%.3f", *url, p.cost)
			lag := float64(time.Since(sched)) / float64(time.Millisecond)
			resp, err := client.Get(u)
			res := result{at: p.at, lag: lag}
			if err != nil {
				res.err = true
			} else {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				res.port = resp.Header.Get("X-Port")
				res.err = resp.StatusCode != 200
			}
			res.lat = float64(time.Since(sched)) / float64(time.Millisecond)
			results[i] = res
		}(i, p)
	}
	wg.Wait()

	summarize := func(from, to time.Duration) map[string]any {
		var lat, lags []float64
		ports := map[string]int{}
		errs := 0
		for _, r := range results {
			if r.at < from || r.at >= to {
				continue
			}
			if r.err {
				errs++
				continue
			}
			lat = append(lat, r.lat)
			lags = append(lags, r.lag)
			ports[r.port]++
		}
		sort.Float64s(lat)
		sort.Float64s(lags)
		q := func(p float64) float64 {
			if len(lat) == 0 {
				return math.NaN()
			}
			i := int(p * float64(len(lat)))
			if i >= len(lat) {
				i = len(lat) - 1
			}
			return lat[i]
		}
		sum := 0.0
		for _, v := range lat {
			sum += v
		}
		mean := math.NaN()
		if len(lat) > 0 {
			mean = sum / float64(len(lat))
		}
		return map[string]any{
			"n": len(lat), "errors": errs, "mean": mean,
			"p50": q(0.5), "p90": q(0.9), "p95": q(0.95), "p99": q(0.99),
			"p999": q(0.999), "by_port": ports,
			"send_lag_p50": pick(lags, 0.5), "send_lag_p99": pick(lags, 0.99),
		}
	}

	out := summarize(*warmup, total)
	out["rate"] = *rate
	out["seed"] = *seed
	out["dist"] = *dist
	out["achieved_s"] = time.Since(start).Seconds()

	if *window != "" {
		a, b, _ := strings.Cut(*window, ":")
		fa, _ := strconv.ParseFloat(a, 64)
		fb, _ := strconv.ParseFloat(b, 64)
		out["window"] = summarize(*warmup+time.Duration(fa*float64(time.Second)),
			*warmup+time.Duration(fb*float64(time.Second)))
	}

	if *raw != "" {
		f, err := os.Create(*raw)
		if err == nil {
			for _, r := range results {
				if r.at >= *warmup && !r.err {
					fmt.Fprintf(f, "%.3f\n", r.lat)
				}
			}
			f.Close()
		}
	}

	json.NewEncoder(os.Stdout).Encode(out)
}
