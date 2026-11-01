package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$`)
)

type ProjectView struct {
	ID       string            `json:"id"`
	Owner    string            `json:"owner"`
	Name     string            `json:"name"`
	Runtime  string            `json:"runtime"`
	Detected string            `json:"detected"`
	Cmd      string            `json:"cmd"`
	Port     int               `json:"port"`
	RAM      int               `json:"ram"`
	CPU      float64           `json:"cpu"`
	Created  int64             `json:"created"`
	Repo     string            `json:"repo"`
	Branch   string            `json:"branch"`
	HasToken bool              `json:"hasToken"`
	Hook     string            `json:"hook"`
	Env      map[string]string `json:"env"`
	Sub      string            `json:"sub"`
	Host     string            `json:"host"`
	Custom   []string          `json:"custom"`
	Status   string            `json:"status"`
	UsedRAM  float64           `json:"usedRam"`
	UsedCPU  float64           `json:"usedCpu"`
}

func view(p Project) ProjectView {
	e := p.Env
	if e == nil {
		e = map[string]string{}
	}
	c := p.Custom
	if c == nil {
		c = []string{}
	}
	hook := ""
	if p.Repo != "" && p.Hook != "" {
		hook = "/hook/" + p.ID + "/" + p.Hook
	}
	owner := ""
	if u, ok := userByID(p.Owner); ok {
		owner = u.Email
	}
	us := statsOf(cname(p))
	return ProjectView{UsedRAM: us.MemMB, UsedCPU: us.CPU / 100, ID: p.ID, Owner: owner, Name: p.Name, Runtime: p.Runtime, Detected: p.Detected, Cmd: p.Cmd, Port: p.Port,
		RAM: p.RAM, CPU: p.CPU, Created: p.Created, Repo: p.Repo, Branch: p.Branch, HasToken: p.Token != "", Hook: hook, Env: e,
		Sub: p.Sub, Host: hostOf(p), Custom: c, Status: status(p)}
}

// every project handler goes through here: owners see their own projects, admin sees all
func getProject(w http.ResponseWriter, r *http.Request) (Project, bool) {
	u, ok := curUser(r)
	if !ok {
		jsonErr(w, 401, "login required")
		return Project{}, false
	}
	p, found := store.get(r.PathValue("id"))
	if !found || (p.Owner != u.ID && u.Role != "admin") {
		jsonErr(w, 404, "project not found")
		return Project{}, false
	}
	return p, true
}

/* ---------- quotas ---------- */

type dsEntry struct {
	n int64
	t time.Time
}

var (
	dsMu    sync.Mutex
	dsCache = map[string]dsEntry{}
)

func dirSize(path string) int64 {
	dsMu.Lock()
	if c, ok := dsCache[path]; ok && time.Since(c.t) < 45*time.Second {
		dsMu.Unlock()
		return c.n
	}
	dsMu.Unlock()
	var n int64
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if i, e := d.Info(); e == nil {
				n += i.Size()
			}
		}
		return nil
	})
	dsMu.Lock()
	dsCache[path] = dsEntry{n, time.Now()}
	dsMu.Unlock()
	return n
}

func quotaErr(owner string) error {
	u, ok := userByID(owner)
	if !ok {
		return errors.New("owner account not found")
	}
	if u.Banned {
		return errors.New("this account is suspended")
	}
	lim := limitsFor(u)
	ram, cpu, n := allocOf(owner)
	if ram > lim.RAM || cpu > lim.CPU+0.001 || n > lim.Projects {
		return fmt.Errorf("your plan (%s) is exceeded — reduce resources, delete a project, or upgrade", lim.Name)
	}
	if userDisk(owner) > int64(lim.Disk)*(1<<30) {
		return fmt.Errorf("SSD limit reached (%d GB on %s) — delete files or upgrade", lim.Disk, lim.Name)
	}
	return nil
}

func diskErr(p Project, extra int64) error {
	o, ok := userByID(p.Owner)
	if !ok {
		return nil
	}
	if extra < 0 {
		extra = 0
	}
	lim := limitsFor(o)
	if userDisk(o.ID)+extra > int64(lim.Disk)*(1<<30) {
		return fmt.Errorf("SSD limit reached (%d GB on %s plan) — delete files or upgrade", lim.Disk, lim.Name)
	}
	return nil
}

/* ---------- handlers ---------- */

func handleList(w http.ResponseWriter, r *http.Request) {
	u, _ := curUser(r)
	out := []ProjectView{}
	for _, p := range store.projectsOf(u.ID) {
		out = append(out, view(p))
	}
	jsonOut(w, 200, out)
}

func handleCreate(w http.ResponseWriter, r *http.Request) {
	u, _ := curUser(r)
	var in struct {
		Name    string `json:"name"`
		Runtime string `json:"runtime"`
		Cmd     string `json:"cmd"`
		Repo    string `json:"repo"`
		Branch  string `json:"branch"`
		Token   string `json:"token"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 16384)).Decode(&in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	name := strings.ToLower(strings.TrimSpace(in.Name))
	if !nameRe.MatchString(name) {
		jsonErr(w, 400, "name: 2-31 chars, only a-z, 0-9 and -")
		return
	}
	rtKey := in.Runtime
	if rtKey == "" {
		rtKey = "auto"
	}
	rt, known := runtimes[rtKey]
	if !known && rtKey != "auto" {
		jsonErr(w, 400, "unknown runtime")
		return
	}
	repo, tok, br, err := normRepo(in.Repo)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if t := strings.TrimSpace(in.Token); t != "" {
		tok = t
	}
	branch := strings.TrimSpace(in.Branch)
	if branch == "" {
		branch = br
	}
	if branch != "" && !branchRe.MatchString(branch) {
		jsonErr(w, 400, "invalid branch name")
		return
	}
	lim := limitsFor(u)
	usedRAM, usedCPU, n := allocOf(u.ID)
	if n >= lim.Projects {
		jsonErr(w, 409, fmt.Sprintf("your plan (%s) allows %d project(s) — upgrade or delete one", lim.Name, lim.Projects))
		return
	}
	ram := 512
	if known && rt.MemMB > 0 {
		ram = rt.MemMB
	}
	if rem := lim.RAM - usedRAM; ram > rem {
		ram = rem
	}
	cpu := 0.5
	if rem := lim.CPU - usedCPU; cpu > rem {
		cpu = math.Floor(rem*100) / 100
	}
	if ram < 64 || cpu < 0.1 {
		jsonErr(w, 409, "not enough RAM / CPU left on your plan — resize or delete another project, or upgrade")
		return
	}
	p := Project{ID: newToken()[:12], Owner: u.ID, Name: name, Runtime: rtKey, Cmd: strings.TrimSpace(in.Cmd), RAM: ram, CPU: cpu,
		Created: time.Now().Unix(), Repo: repo, Branch: branch, Token: tok, Hook: newToken()[:20]}
	p, err = store.add(p)
	if err != nil {
		jsonErr(w, 409, err.Error())
		return
	}
	if err := os.MkdirAll(projDir(p), 0755); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if repo != "" {
		setPhase(p.ID, "deploying")
		go deployRepo(p)
	}
	jsonOut(w, 201, view(p))
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	if err := diskErr(p, r.ContentLength); err != nil {
		jsonErr(w, 413, err.Error())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 200<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		jsonErr(w, 400, "upload invalid or larger than 200MB")
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		jsonErr(w, 400, "file missing")
		return
	}
	defer f.Close()
	resetDeployLog(p)
	dir := projDir(p)
	if strings.HasSuffix(strings.ToLower(hdr.Filename), ".zip") {
		tmp, err := os.CreateTemp("", "up-*.zip")
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		defer os.Remove(tmp.Name())
		if _, err := io.Copy(tmp, f); err != nil {
			tmp.Close()
			jsonErr(w, 500, err.Error())
			return
		}
		tmp.Close()
		_ = os.RemoveAll(dir)
		_ = os.MkdirAll(dir, 0755)
		if err := unzip(tmp.Name(), dir); err != nil {
			dlog(p, "zip error: %v", err)
			jsonErr(w, 400, "zip error: "+err.Error())
			return
		}
		flatten(dir)
		dlog(p, "zip extracted ✓")
	} else {
		_ = os.MkdirAll(dir, 0755)
		out, err := os.Create(filepath.Join(dir, filepath.Base(hdr.Filename)))
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		_, err = io.Copy(out, f)
		out.Close()
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		dlog(p, "file %s saved ✓", filepath.Base(hdr.Filename))
	}
	if err := startProject(p); err != nil {
		jsonErr(w, 500, "uploaded, but start failed: "+err.Error())
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func handleAction(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	switch r.PathValue("action") {
	case "start", "restart":
		if err := startProject(p); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
	case "stop":
		if out, err := docker("stop", cname(p)); err != nil && !strings.Contains(out, "No such container") {
			jsonErr(w, 500, out)
			return
		}
	case "sync":
		if p.Repo == "" {
			jsonErr(w, 400, "this project has no Git link")
			return
		}
		setPhase(p.ID, "deploying")
		go deployRepo(p)
	default:
		jsonErr(w, 400, "unknown action")
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	var in struct {
		Runtime string  `json:"runtime"`
		Cmd     string  `json:"cmd"`
		Repo    string  `json:"repo"`
		Branch  string  `json:"branch"`
		Token   *string `json:"token"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 16384)).Decode(&in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	if in.Runtime == "" {
		in.Runtime = "auto"
	}
	if _, ok := runtimes[in.Runtime]; !ok && in.Runtime != "auto" {
		jsonErr(w, 400, "unknown runtime")
		return
	}
	repo, tok, br, err := normRepo(in.Repo)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	branch := strings.TrimSpace(in.Branch)
	if branch == "" {
		branch = br
	}
	if branch != "" && !branchRe.MatchString(branch) {
		jsonErr(w, 400, "invalid branch name")
		return
	}
	store.update(p.ID, func(x *Project) {
		x.Runtime = in.Runtime
		x.Cmd = strings.TrimSpace(in.Cmd)
		x.Repo = repo
		x.Branch = branch
		if in.Token != nil {
			x.Token = strings.TrimSpace(*in.Token)
		} else if tok != "" {
			x.Token = tok
		}
		if repo == "" {
			x.Token = ""
		}
	})
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func handleEnv(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	var in struct {
		Env map[string]string `json:"env"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	if len(in.Env) > 200 {
		jsonErr(w, 400, "too many variables (max 200)")
		return
	}
	for k, v := range in.Env {
		if !envKeyRe.MatchString(k) {
			jsonErr(w, 400, "invalid variable name: "+k)
			return
		}
		if len(v) > 8192 {
			jsonErr(w, 400, "value too long: "+k)
			return
		}
	}
	store.update(p.ID, func(x *Project) { x.Env = in.Env })
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func handleResources(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	var in struct {
		RAM int     `json:"ram"`
		CPU float64 `json:"cpu"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	o, _ := userByID(p.Owner)
	lim := limitsFor(o)
	otherRAM, otherCPU := 0, 0.0
	for _, x := range store.projectsOf(p.Owner) {
		if x.ID != p.ID {
			otherRAM += x.RAM
			otherCPU += x.CPU
		}
	}
	cpu := math.Round(in.CPU*100) / 100
	if in.RAM < 64 || cpu < 0.1 {
		jsonErr(w, 400, "minimum is 64 MB RAM and 0.1 CPU")
		return
	}
	if in.RAM+otherRAM > lim.RAM {
		jsonErr(w, 409, fmt.Sprintf("RAM limit of your plan is %d MB in total (other projects use %d MB)", lim.RAM, otherRAM))
		return
	}
	if cpu+otherCPU > lim.CPU+0.001 {
		jsonErr(w, 409, fmt.Sprintf("CPU limit of your plan is %.2f cores in total (other projects use %.2f)", lim.CPU, otherCPU))
		return
	}
	store.update(p.ID, func(x *Project) { x.RAM, x.CPU = in.RAM, cpu })
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func destroyProject(p Project) {
	_, _ = docker("rm", "-f", cname(p))
	_, _ = docker("rmi", "-f", "nova_"+p.Name)
	_ = os.RemoveAll(projDir(p))
	_ = os.Remove(deployLogPath(p))
	store.remove(p.ID)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	destroyProject(p)
	jsonOut(w, 200, map[string]bool{"ok": true})
}

// GitHub / GitLab push webhook: POST /hook/{id}/{secret}
func handleHook(w http.ResponseWriter, r *http.Request) {
	p, ok := store.get(r.PathValue("id"))
	if !ok || p.Hook == "" || p.Repo == "" || r.PathValue("secret") != p.Hook {
		http.NotFound(w, r)
		return
	}
	var in struct {
		Ref string `json:"ref"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in)
	if p.Branch != "" && in.Ref != "" && in.Ref != "refs/heads/"+p.Branch {
		jsonOut(w, 200, map[string]string{"ignored": "other branch"})
		return
	}
	setPhase(p.ID, "deploying")
	go deployRepo(p)
	jsonOut(w, 200, map[string]bool{"ok": true})
}
