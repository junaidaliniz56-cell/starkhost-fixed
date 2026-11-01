package main

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

type usage struct {
	MemMB float64 // real RAM in use
	CPU   float64 // percent of one core (docker style)
}

var (
	stMu  sync.RWMutex
	stats = map[string]usage{}
)

func parseMem(s string) float64 {
	s = strings.TrimSpace(s)
	units := []struct {
		u string
		m float64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"GB", 1e9}, {"MB", 1e6}, {"kB", 1e3}, {"B", 1}}
	for _, x := range units {
		if strings.HasSuffix(s, x.u) {
			v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(s, x.u)), 64)
			if err != nil {
				return 0
			}
			return v * x.m / (1 << 20)
		}
	}
	return 0
}

func parsePct(s string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%")), 64)
	return v
}

// samples the real RAM / CPU of every running app every few seconds
func statsLoop() {
	for {
		m := map[string]usage{}
		if out, err := docker("stats", "--no-stream", "--format", "{{.Name}}|{{.MemUsage}}|{{.CPUPerc}}"); err == nil {
			for _, l := range strings.Split(out, "\n") {
				f := strings.Split(strings.TrimSpace(l), "|")
				if len(f) != 3 || !strings.HasPrefix(f[0], "host_") {
					continue
				}
				mem := f[1]
				if i := strings.Index(mem, "/"); i >= 0 {
					mem = mem[:i]
				}
				m[f[0]] = usage{MemMB: parseMem(mem), CPU: parsePct(f[2])}
			}
		}
		stMu.Lock()
		stats = m
		stMu.Unlock()
		time.Sleep(3 * time.Second)
	}
}

func statsOf(container string) usage {
	stMu.RLock()
	defer stMu.RUnlock()
	return stats[container]
}

// live totals of one user (RAM in MB, CPU in cores)
func liveOf(owner string) (float64, float64) {
	var ram, cpu float64
	for _, p := range store.projectsOf(owner) {
		u := statsOf(cname(p))
		ram += u.MemMB
		cpu += u.CPU / 100
	}
	return ram, cpu
}
