package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

/* ---------- login brute-force protection ---------- */

type attempt struct {
	fails int
	first time.Time
	until time.Time
}

var (
	atMu     sync.Mutex
	attempts = map[string]*attempt{}
)

const (
	maxFails   = 5
	failWindow = 15 * time.Minute
	lockFor    = 15 * time.Minute
)

// Real client IP. X-Forwarded-For is trusted only when the request comes from
// a private/loopback address (i.e. from our own Caddy), so it cannot be spoofed from the internet.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			first := strings.TrimSpace(strings.Split(xf, ",")[0])
			if net.ParseIP(first) != nil {
				return first
			}
		}
	}
	return host
}

func locked(ip string) (bool, time.Duration) {
	atMu.Lock()
	defer atMu.Unlock()
	if a := attempts[ip]; a != nil && time.Now().Before(a.until) {
		return true, time.Until(a.until)
	}
	return false, 0
}

func lockMsg(wait time.Duration) string {
	return fmt.Sprintf("too many wrong attempts — try again in %d min", int(wait.Minutes())+1)
}

func recordFail(ip string) {
	atMu.Lock()
	defer atMu.Unlock()
	now := time.Now()
	if len(attempts) > 5000 {
		for k, a := range attempts {
			if now.After(a.until) && now.Sub(a.first) > failWindow {
				delete(attempts, k)
			}
		}
	}
	a := attempts[ip]
	if a == nil || (now.After(a.until) && now.Sub(a.first) > failWindow) {
		a = &attempt{first: now}
		attempts[ip] = a
	}
	a.fails++
	if a.fails >= maxFails {
		a.until = now.Add(lockFor)
	}
}

func recordOK(ip string) {
	atMu.Lock()
	delete(attempts, ip)
	atMu.Unlock()
}

/* ---------- cross-site request blocking ---------- */

// splitHostPortLoose returns the host and port of a Host header value.
// A missing port is returned as "" (not an error).
func splitHostPortLoose(s string) (string, string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return strings.Trim(h, "[]"), p
	}
	return strings.Trim(s, "[]"), ""
}

func sameOrigin(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	// behind our own reverse proxy the Host header may be rewritten; prefer the
	// original host, but only trust that header when the request comes from localhost
	rh := r.Host
	rhost, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(rhost); ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		if xh := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); xh != "" {
			rh = xh
		}
	}
	if strings.EqualFold(u.Host, rh) {
		return true
	}
	// proxies often strip a non-standard port from Host (and browsers send it in
	// Origin), so compare the hostnames and only enforce the port when both have one
	oh, op := splitHostPortLoose(u.Host)
	rhop, rp := splitHostPortLoose(rh)
	if !strings.EqualFold(oh, rhop) {
		return false
	}
	if op == "" || rp == "" {
		return true
	}
	return op == rp
}

/* ---------- security headers (panel only, not your apps) ---------- */

func secHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.Header.Get("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

/* ---------- generic rate limiter ---------- */

var (
	rlMu sync.Mutex
	rl   = map[string][]time.Time{}
)

// allow returns false when key was used `max` times within `window`
func allow(key string, max int, window time.Duration) bool {
	rlMu.Lock()
	defer rlMu.Unlock()
	now := time.Now()
	var keep []time.Time
	for _, t := range rl[key] {
		if now.Sub(t) < window {
			keep = append(keep, t)
		}
	}
	if len(keep) >= max {
		rl[key] = keep
		return false
	}
	rl[key] = append(keep, now)
	if len(rl) > 20000 {
		rl = map[string][]time.Time{key: rl[key]}
	}
	return true
}
