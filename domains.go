package main

import (
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var fqdnRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func randSub(name string) string { return name + "-" + newToken()[:4] }

/* ---------- public ip / base domain ---------- */

var (
	ipMu     sync.RWMutex
	cachedIP string
)

func publicIP() string {
	if v := strings.TrimSpace(cfg().PublicIP); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("PUBLIC_IP")); v != "" {
		return v
	}
	ipMu.RLock()
	defer ipMu.RUnlock()
	return cachedIP
}

func refreshIP() {
	for {
		c := http.Client{Timeout: 6 * time.Second}
		for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"} {
			resp, err := c.Get(u)
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
			resp.Body.Close()
			ip := strings.TrimSpace(string(b))
			if net.ParseIP(ip) != nil {
				ipMu.Lock()
				cachedIP = ip
				ipMu.Unlock()
				break
			}
		}
		if publicIP() == "" {
			time.Sleep(30 * time.Second)
		} else {
			time.Sleep(time.Hour)
		}
	}
}

// BASE_DOMAIN is your own wildcard domain, e.g. apps.example.com
func baseDomain() string {
	if b := strings.TrimSpace(cfg().BaseDomain); b != "" {
		return b
	}
	if b := strings.ToLower(strings.TrimSpace(os.Getenv("BASE_DOMAIN"))); b != "" {
		return b
	}
	return ""
}

func hostOf(p Project) string {
	b := baseDomain()
	if b == "" || p.Sub == "" {
		return ""
	}
	return p.Sub + "." + b
}

func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.TrimSuffix(h, ".")
}

/* ---------- reverse proxy (Railway-style) ---------- */

const downHTML = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>App not running</title>
<body style="font-family:system-ui;background:#070b14;color:#e8ecf5;display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center;margin:0">
<div><div style="font-size:46px">⚡</div><h2>{{NAME}} is not reachable</h2>
<p style="color:#8b95ad">The app is stopped, still starting, or crashed.<br>Open Nova Host → Logs to see why.</p></div></body>`

type ipEntry struct {
	ip  string
	exp time.Time
}

var ipCache sync.Map

// containerIP resolves a container name to its IP. A panel running on the host
// (not inside a container) cannot use Docker's embedded DNS, so look it up.
func containerIP(name string) string {
	if v, ok := ipCache.Load(name); ok {
		e := v.(ipEntry)
		if time.Now().Before(e.exp) {
			return e.ip
		}
	}
	ip := ""
	if out, err := docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name); err == nil {
		for _, f := range strings.Fields(out) {
			if net.ParseIP(f) != nil {
				ip = f
				break
			}
		}
	}
	ttl := 20 * time.Second
	if ip == "" {
		ttl = 3 * time.Second
	}
	ipCache.Store(name, ipEntry{ip: ip, exp: time.Now().Add(ttl)})
	return ip
}

func writeDown(w http.ResponseWriter, p Project) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = io.WriteString(w, strings.ReplaceAll(downHTML, "{{NAME}}", html.EscapeString(p.Name)))
}

func proxyTo(p Project, w http.ResponseWriter, r *http.Request) {
	var target string
	if publish && os.Getenv("DIRECT_PORTS") == "true" {
		target = fmt.Sprintf("http://127.0.0.1:%d", p.Port)
	} else {
		host := cname(p)
		ip := containerIP(host)
		if ip == "" {
			writeDown(w, p)
			return
		}
		host = ip
		target = fmt.Sprintf("http://%s:%d", host, innerPort(p))
	}
	u, _ := url.Parse(target)
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		writeDown(w, p)
	}
	rp.ServeHTTP(w, r)
}

func hostRouter(panel http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := store.byHost(normHost(r.Host)); ok {
			proxyTo(p, w, r)
			return
		}
		panel.ServeHTTP(w, r)
	})
}

// Caddy "ask" endpoint: only issue HTTPS certificates for domains we host
func handleAsk(w http.ResponseWriter, r *http.Request) {
	d := normHost(r.URL.Query().Get("domain"))
	if d != "" {
		if _, ok := store.byHost(d); ok {
			w.WriteHeader(200)
			return
		}
		if pd := strings.ToLower(strings.TrimSpace(os.Getenv("PANEL_DOMAIN"))); pd != "" && (d == pd || d == "www."+pd) {
			w.WriteHeader(200)
			return
		}
	}
	w.WriteHeader(404)
}

/* ---------- domain handlers ---------- */

func handleDomainGen(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	var in struct {
		Sub string `json:"sub"`
	}
	_ = jsonDecode(r, &in)
	sub := strings.ToLower(strings.TrimSpace(in.Sub))
	if sub == "" {
		sub = randSub(p.Name)
	} else if !nameRe.MatchString(sub) {
		jsonErr(w, 400, "subdomain: 2-31 chars, only a-z, 0-9 and -")
		return
	}
	for _, x := range store.snapshot() {
		if x.ID != p.ID && x.Sub == sub {
			jsonErr(w, 409, "this subdomain is already taken")
			return
		}
	}
	store.update(p.ID, func(x *Project) { x.Sub = sub })
	jsonOut(w, 200, map[string]string{"sub": sub})
}

func handleDomainAdd(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	var in struct {
		Domain string `json:"domain"`
	}
	_ = jsonDecode(r, &in)
	if u, _ := curUser(r); !limitsFor(u).Custom {
		jsonErr(w, 403, "custom domains are available on paid plans — upgrade to use your own domain")
		return
	}
	d := normHost(in.Domain)
	if !fqdnRe.MatchString(d) {
		jsonErr(w, 400, "enter a valid domain like app.example.com")
		return
	}
	if _, taken := store.byHost(d); taken {
		jsonErr(w, 409, "this domain is already used")
		return
	}
	store.update(p.ID, func(x *Project) { x.Custom = append(append([]string(nil), x.Custom...), d) })
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func handleDomainDel(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	d := normHost(r.URL.Query().Get("domain"))
	store.update(p.ID, func(x *Project) {
		var keep []string
		for _, c := range x.Custom {
			if c != d {
				keep = append(keep, c)
			}
		}
		x.Custom = keep
	})
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func handleDomainCheck(w http.ResponseWriter, r *http.Request) {
	if _, ok := getProject(w, r); !ok {
		return
	}
	d := normHost(r.URL.Query().Get("domain"))
	want := publicIP()
	ips, err := net.LookupHost(d)
	good := false
	for _, ip := range ips {
		if ip == want {
			good = true
		}
	}
	msg := ""
	if err != nil {
		msg = "DNS record not found yet"
	}
	if ips == nil {
		ips = []string{}
	}
	jsonOut(w, 200, map[string]any{"ok": good, "ips": ips, "expect": want, "error": msg})
}
