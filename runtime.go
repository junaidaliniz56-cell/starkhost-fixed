package main

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Runtime struct {
	Label  string
	Image  string
	Cmd    string
	Port   int
	Static bool
	MemMB  int
	Env    []string
}

var runtimes = map[string]Runtime{
	"node": {Label: "Node.js", Image: "node:20-slim", Port: 3000, Cmd: `if [ -f package.json ]; then npm install --no-audit --no-fund && npm run build --if-present; fi || exit 1
if [ -f package.json ] && grep -q '"start"' package.json; then exec npm start
elif [ -f server.js ]; then exec node server.js
elif [ -f app.js ]; then exec node app.js
elif [ -f bot.js ]; then exec node bot.js
elif [ -f index.js ]; then exec node index.js
elif [ -n "$(ls *.js 2>/dev/null | head -n1)" ]; then exec node "$(ls *.js | head -n1)"
elif [ -f dist/index.html ]; then exec npx --yes serve -s dist -l $PORT
elif [ -f build/index.html ]; then exec npx --yes serve -s build -l $PORT
else echo "NOVA: no start script or entry file found (package.json start / index.js / server.js / app.js)"; exit 1; fi`},
	"python": {Label: "Python", Image: "python:3.12-slim", Port: 3000, Env: []string{"PYTHONUNBUFFERED=1", "PIP_ROOT_USER_ACTION=ignore", "PIP_DISABLE_PIP_VERSION_CHECK=1"}, Cmd: `if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt || exit 1
elif [ -f pyproject.toml ]; then pip install --no-cache-dir . || exit 1; fi
f=""
for n in main.py app.py bot.py server.py run.py start.py index.py __main__.py; do if [ -f "$n" ]; then f="$n"; break; fi; done
if [ -z "$f" ] && [ -f manage.py ]; then exec python manage.py runserver 0.0.0.0:$PORT; fi
if [ -z "$f" ]; then f=$(grep -l "__main__" *.py 2>/dev/null | head -n1); fi
if [ -z "$f" ]; then f=$(ls *.py 2>/dev/null | head -n1); fi
if [ -z "$f" ]; then f=$(find . -maxdepth 3 -name '*.py' -not -path '*/venv/*' -not -path '*/.venv/*' -not -path '*/site-packages/*' -not -path '*/__pycache__/*' 2>/dev/null | head -n1); fi
if [ -z "$f" ]; then echo "NOVA: no Python (.py) file found - open Files and create one (any name works)"; exit 1; fi
echo "NOVA: starting $f"
cd "$(dirname "$f")" 2>/dev/null
exec python -u "$(basename "$f")"`},
	"go": {Label: "Go", Image: "golang:1.24-alpine", Port: 3000, MemMB: 768, Env: []string{"GOFLAGS=-buildvcs=false"}, Cmd: `apk add --no-cache git >/dev/null 2>&1
if [ -f go.mod ]; then exec go run .; else exec go run *.go; fi`},
	"php": {Label: "PHP", Image: "php:8.3-cli-alpine", Port: 3000, Cmd: `if [ -d public ]; then exec php -S 0.0.0.0:$PORT -t public; else exec php -S 0.0.0.0:$PORT -t /app; fi`},
	"ruby": {Label: "Ruby", Image: "ruby:3.3-alpine", Port: 3000, Cmd: `if [ -f Gemfile ]; then apk add --no-cache build-base git >/dev/null 2>&1; bundle install || exit 1; fi
if [ -f config.ru ]; then exec bundle exec rackup -o 0.0.0.0 -p $PORT
elif [ -f main.rb ]; then exec ruby main.rb
elif [ -f app.rb ]; then exec ruby app.rb
else exec ruby $(ls *.rb | head -n1); fi`},
	"java": {Label: "Java", Image: "maven:3.9-eclipse-temurin-21", Port: 3000, MemMB: 1024, Cmd: `if [ -f pom.xml ]; then mvn -q -B -DskipTests package || exit 1; fi
jar=$(ls target/*.jar *.jar 2>/dev/null | grep -v original | head -n1)
if [ -z "$jar" ]; then echo "NOVA: no pom.xml / .jar found"; exit 1; fi
exec java -Xmx512m -jar "$jar"`},
	"rust": {Label: "Rust", Image: "rust:1-alpine", Port: 3000, MemMB: 1536, Cmd: `apk add --no-cache musl-dev >/dev/null 2>&1
exec cargo run --release`},
	"dotnet": {Label: ".NET", Image: "mcr.microsoft.com/dotnet/sdk:8.0", Port: 3000, MemMB: 1024, Env: []string{"DOTNET_CLI_TELEMETRY_OPTOUT=1", "DOTNET_NOLOGO=1"}, Cmd: `exec dotnet run --urls http://0.0.0.0:$PORT`},
	"deno":   {Label: "Deno", Image: "denoland/deno:alpine", Port: 3000, Cmd: `if [ -f main.ts ]; then exec deno run -A main.ts; elif [ -f main.js ]; then exec deno run -A main.js; else exec deno run -A index.ts; fi`},
	"static": {Label: "HTML / Static", Image: "nginx:alpine", Port: 80, Static: true, MemMB: 128},
	"docker": {Label: "Dockerfile", Port: 3000},
}

/* ---------- detection ---------- */

func detect(dir string) string {
	has := func(n string) bool { return fileExists(filepath.Join(dir, n)) }
	glob := func(pat string) bool {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		return len(m) > 0
	}
	switch {
	case has("Dockerfile"):
		return "docker"
	case has("package.json"):
		return "node"
	case has("requirements.txt") || has("pyproject.toml") || has("manage.py") || glob("*.py"):
		return "python"
	case has("go.mod") || glob("*.go"):
		return "go"
	case has("pom.xml") || glob("*.jar"):
		return "java"
	case has("Cargo.toml"):
		return "rust"
	case glob("*.csproj") || glob("*.sln"):
		return "dotnet"
	case has("composer.json") || glob("*.php"):
		return "php"
	case has("Gemfile") || has("config.ru") || glob("*.rb"):
		return "ruby"
	case has("deno.json") || has("deno.jsonc") || has("main.ts"):
		return "deno"
	case has("index.html") || staticRoot(dir) != dir:
		return "static"
	}
	return ""
}

func staticRoot(dir string) string {
	if fileExists(filepath.Join(dir, "index.html")) {
		return dir
	}
	for _, s := range []string{"dist", "build", "public", "out", "docs"} {
		if fileExists(filepath.Join(dir, s, "index.html")) {
			return filepath.Join(dir, s)
		}
	}
	return dir
}

var exposeRe = regexp.MustCompile(`(?mi)^\s*EXPOSE\s+(\d+)`)

func exposedPort(dir string) int {
	b, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if err == nil {
		if m := exposeRe.FindStringSubmatch(string(b)); m != nil {
			if n, e := strconv.Atoi(m[1]); e == nil && n > 0 {
				return n
			}
		}
	}
	return 3000
}

func effectiveRuntime(p Project) string {
	if p.Runtime != "" && p.Runtime != "auto" {
		return p.Runtime
	}
	return p.Detected
}

func innerPort(p Project) int {
	if p.Inner > 0 {
		return p.Inner
	}
	if rt, ok := runtimes[effectiveRuntime(p)]; ok && rt.Port > 0 {
		return rt.Port
	}
	return 3000
}

/* ---------- docker ---------- */

func docker(args ...string) (string, error) {
	out, err := exec.Command("docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func cname(p Project) string   { return "host_" + p.Name }
func projDir(p Project) string { return filepath.Join(dataDir, "projects", p.Name) }

var (
	phMu   sync.Mutex
	phases = map[string]string{}
)

func setPhase(id, ph string) {
	phMu.Lock()
	defer phMu.Unlock()
	if ph == "" {
		delete(phases, id)
	} else {
		phases[id] = ph
	}
}

func phase(id string) string {
	phMu.Lock()
	defer phMu.Unlock()
	return phases[id]
}

func status(p Project) string {
	if ph := phase(p.ID); ph != "" {
		return ph
	}
	out, err := docker("inspect", "-f", "{{.State.Status}}", cname(p))
	if err != nil {
		return "stopped"
	}
	if out == "exited" || out == "created" || out == "dead" {
		return "stopped"
	}
	return out
}

func buildEnv(p Project, rt Runtime, inner int) []string {
	m := map[string]string{}
	for _, kv := range rt.Env {
		if i := strings.Index(kv, "="); i > 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	for k, v := range p.Env {
		m[k] = v
	}
	m["PORT"] = strconv.Itoa(inner)
	m["NOVA_PROJECT"] = p.Name
	if h := hostOf(p); h != "" {
		m["NOVA_DOMAIN"] = h
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		out = append(out, "-e", k+"="+m[k])
	}
	return out
}

func startProject(p Project) error {
	if err := quotaErr(p.Owner); err != nil {
		dlog(p, "blocked: %v", err)
		return err
	}
	dir := projDir(p)
	if isEmptyProject(dir) {
		dlog(p, "project folder is empty")
		return errors.New("this project has no files yet — upload code, add a Git link, or create a file in Files (any name works, e.g. main.py)")
	}
	rtKey := effectiveRuntime(p)
	if p.Runtime == "" || p.Runtime == "auto" {
		rtKey = detect(dir)
		if rtKey == "" {
			dlog(p, "could not detect language — no known project files found")
			return errors.New("could not detect the language — upload code first, or pick a runtime in Settings")
		}
		store.update(p.ID, func(x *Project) { x.Detected = rtKey })
		p.Detected = rtKey
		dlog(p, "detected language: %s", runtimes[rtKey].Label)
	}
	rt, ok := runtimes[rtKey]
	if !ok {
		return errors.New("unknown runtime: " + rtKey)
	}
	_, _ = docker("rm", "-f", cname(p))
	inner := rt.Port
	image := rt.Image
	if rtKey == "docker" {
		inner = exposedPort(dir)
		image = "nova_" + p.Name
		dlog(p, "building Docker image from your Dockerfile …")
		if err := runLogged(p, dir, 20*time.Minute, "docker", "build", "-t", image, "."); err != nil {
			return errors.New("docker build failed — see Logs → Deploy tab")
		}
	}
	store.update(p.ID, func(x *Project) { x.Inner = inner })
	ram, cpu := p.RAM, p.CPU
	if ram <= 0 {
		ram = 512
	}
	if cpu <= 0 {
		cpu = 0.5
	}
	network := ensureUserNet(p.Owner)
	args := []string{"run", "-d", "--name", cname(p), "--restart", "unless-stopped",
		"--memory", fmt.Sprintf("%dm", ram), "--memory-swap", fmt.Sprintf("%dm", ram), "--cpus", fmt.Sprintf("%.2f", cpu),
		"--pids-limit", "512", "--security-opt", "no-new-privileges",
		"--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID",
		"--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER", "--cap-add", "NET_BIND_SERVICE",
		"--label", "stark.project=" + p.Name, "--label", "stark.owner=" + p.Owner, "--network", network}
	if publish {
		args = append(args, "-p", fmt.Sprintf("%d:%d", p.Port, inner))
	}
	args = append(args, buildEnv(p, rt, inner)...)
	switch {
	case rtKey == "docker":
		args = append(args, image)
	case rt.Static:
		args = append(args, "-v", staticRoot(dir)+":/usr/share/nginx/html:ro", image)
	default:
		cmd := strings.TrimSpace(p.Cmd)
		if cmd == "" {
			cmd = rt.Cmd
		}
		args = append(args, "-v", dir+":/app", "-w", "/app", image, "sh", "-c", cmd)
	}
	dlog(p, "starting container (%s) …", rt.Label)
	out, err := docker(args...)
	if err != nil {
		dlog(p, "start failed: %s", out)
		return errors.New(out)
	}
	dlog(p, "container started ✓  (first run may take a minute while dependencies install — watch Live logs)")
	return nil
}

func deployRepo(p Project) {
	resetDeployLog(p)
	setPhase(p.ID, "deploying")
	defer setPhase(p.ID, "")
	if err := gitSync(p); err != nil {
		dlog(p, "ERROR: %v", err)
		return
	}
	if err := startProject(p); err != nil {
		dlog(p, "ERROR: %v", err)
	}
}

/* ---------- deploy log ---------- */

func deployLogPath(p Project) string { return filepath.Join(dataDir, "logs", p.Name+".log") }

func dlog(p Project, format string, a ...any) {
	f, err := os.OpenFile(deployLogPath(p), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, a...))
}

func resetDeployLog(p Project) { _ = os.WriteFile(deployLogPath(p), nil, 0644) }

type redactW struct {
	w      io.Writer
	secret string
}

func (r redactW) Write(b []byte) (int, error) {
	n := len(b)
	if r.secret != "" {
		b = bytes.ReplaceAll(b, []byte(r.secret), []byte("***"))
	}
	_, err := r.w.Write(b)
	return n, err
}

func runLogged(p Project, dir string, timeout time.Duration, name string, args ...string) error {
	f, err := os.OpenFile(deployLogPath(p), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := redactW{w: f, secret: p.Token}
	fmt.Fprintf(w, "$ %s %s\n", name, strings.Join(args, " "))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Stdout = w
	cmd.Stderr = w
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	return cmd.Run()
}

/* ---------- git ---------- */

// returns clean https url, embedded token (if any), branch (if link had /tree/<branch>)
func normRepo(raw string) (string, string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", nil
	}
	if strings.HasPrefix(raw, "git@") {
		raw = "https://" + strings.Replace(strings.TrimPrefix(raw, "git@"), ":", "/", 1)
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", "", "", errors.New("repo link must be an https:// Git URL, e.g. https://github.com/user/repo")
	}
	if h := u.Hostname(); net.ParseIP(h) != nil || strings.EqualFold(h, "localhost") || !strings.Contains(h, ".") {
		return "", "", "", errors.New("use a normal Git host name like github.com (IP addresses are not allowed)")
	}
	token, branch := "", ""
	if u.User != nil {
		if pw, ok := u.User.Password(); ok {
			token = pw
		} else {
			token = u.User.Username()
		}
		u.User = nil
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) >= 4 && parts[2] == "tree" {
		branch = parts[3]
		u.Path = "/" + parts[0] + "/" + parts[1]
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String(), token, branch, nil
}

func authURL(p Project) string {
	u, err := url.Parse(p.Repo)
	if err != nil || p.Token == "" {
		return p.Repo
	}
	user := "x-access-token"
	if strings.Contains(u.Host, "gitlab") {
		user = "oauth2"
	} else if strings.Contains(u.Host, "bitbucket") {
		user = "x-token-auth"
	}
	u.User = url.UserPassword(user, p.Token)
	return u.String()
}

func gitSync(p Project) error {
	if p.Repo == "" {
		return errors.New("no Git link set for this project")
	}
	dir := projDir(p)
	auth := authURL(p)
	dlog(p, "syncing from %s …", p.Repo)
	if fileExists(filepath.Join(dir, ".git")) {
		ref := p.Branch
		if ref == "" {
			ref = "HEAD"
		}
		if err := runLogged(p, dir, 5*time.Minute, "git", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "fetch", "--depth", "1", auth, ref); err != nil {
			return errors.New("git fetch failed — see Logs → Deploy tab (wrong link, branch, or private repo without token?)")
		}
		if err := runLogged(p, dir, time.Minute, "git", "reset", "--hard", "FETCH_HEAD"); err != nil {
			return errors.New("git reset failed")
		}
		dlog(p, "code updated ✓")
		return nil
	}
	_ = os.RemoveAll(dir)
	_ = os.MkdirAll(filepath.Dir(dir), 0755)
	args := []string{"-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "clone", "--depth", "1"}
	if p.Branch != "" {
		args = append(args, "--branch", p.Branch)
	}
	args = append(args, "--", auth, dir)
	if err := runLogged(p, "", 5*time.Minute, "git", args...); err != nil {
		return errors.New("git clone failed — see Logs → Deploy tab (wrong link, branch, or private repo without token?)")
	}
	_ = runLogged(p, dir, time.Minute, "git", "remote", "set-url", "origin", p.Repo)
	dlog(p, "repository cloned ✓")
	return nil
}

/* ---------- zip ---------- */

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	base := filepath.Clean(dest) + string(os.PathSeparator)
	const limit = 500 << 20
	var total int64
	for _, f := range r.File {
		if f.Mode()&os.ModeSymlink != 0 || strings.HasPrefix(f.Name, "__MACOSX/") {
			continue
		}
		target := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(target, base) {
			return errors.New("unsafe path in zip")
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		in, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			in.Close()
			return err
		}
		n, err := io.Copy(out, io.LimitReader(in, limit-total+1))
		in.Close()
		out.Close()
		if err != nil {
			return err
		}
		total += n
		if total > limit {
			return errors.New("zip too large after extraction")
		}
	}
	return nil
}

// if the zip has a single top folder, move its contents up
func flatten(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return
	}
	tmp := filepath.Join(dir, ".flat_tmp")
	if os.Rename(filepath.Join(dir, entries[0].Name()), tmp) != nil {
		return
	}
	kids, _ := os.ReadDir(tmp)
	for _, k := range kids {
		_ = os.Rename(filepath.Join(tmp, k.Name()), filepath.Join(dir, k.Name()))
	}
	_ = os.RemoveAll(tmp)
}

func isEmptyProject(dir string) bool {
	es, err := os.ReadDir(dir)
	if err != nil {
		return true
	}
	for _, e := range es {
		if e.Name() != ".git" {
			return false
		}
	}
	return true
}
