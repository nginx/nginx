// backend: an HTTP server that models a backend with a fixed number of
// workers and a FCFS queue in front of them.
//
// Each request carries its cost in ms (?c=); the server holds one of
// -workers slots for c / speed ms (sleeping), then answers.  Waiters on a Go
// channel are served in FIFO order, so the queue is FCFS.
//
//	backend -port 9001 -workers 1 -speed 0.5
//	backend -port 9001 -slow 40:20:0.25   # from t=40s, 20s at speed x0.25
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

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

func main() {
	port := flag.Int("port", 9001, "listen port")
	workers := flag.Int("workers", 1, "concurrent service slots")
	speed := flag.Float64("speed", 1.0, "service speed (cost is divided by it)")
	slow := flag.String("slow", "", "start_s:dur_s:factor speed change, from first request")
	flag.Parse()

	slots := make(chan struct{}, *workers)
	var start atomic.Int64

	var slowAt, slowFor time.Duration
	slowFactor := 1.0
	if *slow != "" {
		f := strings.Split(*slow, ":")
		a, _ := strconv.ParseFloat(f[0], 64)
		d, _ := strconv.ParseFloat(f[1], 64)
		slowFactor, _ = strconv.ParseFloat(f[2], 64)
		slowAt = time.Duration(a * float64(time.Second))
		slowFor = time.Duration(d * float64(time.Second))
	}

	hdr := strconv.Itoa(*port)

	h := func(w http.ResponseWriter, r *http.Request) {
		c, _ := strconv.ParseFloat(r.URL.Query().Get("c"), 64)

		now := time.Now().UnixNano()
		start.CompareAndSwap(0, now)

		slots <- struct{}{}

		s := *speed
		if slowFor > 0 {
			t := time.Duration(time.Now().UnixNano() - start.Load())
			if t >= slowAt && t < slowAt+slowFor {
				s *= slowFactor
			}
		}

		waitUntil(time.Now().Add(time.Duration(c / s * float64(time.Millisecond))))
		<-slots

		w.Header().Set("X-Port", hdr)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok\n")
	}

	srv := &http.Server{
		Addr:        fmt.Sprintf("127.0.0.1:%d", *port),
		Handler:     http.HandlerFunc(h),
		IdleTimeout: 60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
