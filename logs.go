package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"
)

func handleLogs(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	out, _ := docker("logs", "--tail", "300", cname(p))
	if out == "" {
		out = "(no logs yet)"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

func handleDeployLog(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	b, err := os.ReadFile(deployLogPath(p))
	if err != nil || len(b) == 0 {
		b = []byte("(no deploy log yet)")
	}
	if len(b) > 200000 {
		b = b[len(b)-200000:]
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(b)
}

func sseLine(w http.ResponseWriter, fl http.Flusher, s string) {
	b, _ := json.Marshal(s)
	fmt.Fprintf(w, "data: %s\n\n", b)
	fl.Flush()
}

func streamOnce(ctx context.Context, w http.ResponseWriter, fl http.Flusher, args []string) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		return
	}
	go func() {
		_ = cmd.Wait()
		_ = pw.Close()
	}()
	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		sseLine(w, fl, sc.Text())
	}
}

// Live logs (Server-Sent Events). Keeps streaming, and re-attaches after restarts/crashes.
func handleLogStream(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		jsonErr(w, 500, "streaming not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	ctx := r.Context()
	first, notified := true, false
	since := ""
	for ctx.Err() == nil {
		if _, err := docker("inspect", "-f", "{{.Id}}", cname(p)); err != nil {
			if !notified {
				sseLine(w, fl, "(app is not running yet — logs will appear here as soon as it starts)")
				notified = true
			}
		} else {
			notified = false
			args := []string{"logs", "-f"}
			if first {
				args = append(args, "--tail", "200")
			} else {
				args = append(args, "--since", since)
			}
			since = time.Now().UTC().Format(time.RFC3339Nano)
			first = false
			args = append(args, cname(p))
			streamOnce(ctx, w, fl, args)
		}
		fmt.Fprint(w, ": ping\n\n")
		fl.Flush()
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
}
