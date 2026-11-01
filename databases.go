package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

/* ---------- per-user private networks ---------- */

func userNet(uid string) string { return "stark_" + uid }

func ensureUserNet(uid string) string {
	n := userNet(uid)
	if _, err := docker("network", "inspect", n); err != nil {
		_, _ = docker("network", "create", "--driver", "bridge", n)
	}
	_, _ = docker("network", "connect", n, panelContainer) // errors if already connected — fine
	return n
}

func ensureAllNets() {
	seen := map[string]bool{}
	for _, p := range store.snapshot() {
		if p.Owner != "" && !seen[p.Owner] {
			seen[p.Owner] = true
			ensureUserNet(p.Owner)
		}
	}
}

func dropUserNet(uid string) {
	n := userNet(uid)
	_, _ = docker("network", "disconnect", "-f", n, panelContainer)
	for _, e := range engines {
		_, _ = docker("network", "disconnect", "-f", n, e.Container)
	}
	_, _ = docker("network", "rm", n)
}

/* ---------- managed database engines ---------- */

type engine struct {
	Container string
	Port      int
}

var engines = map[string]engine{
	"mongo":    {"stark_mongo", 27017},
	"postgres": {"stark_postgres", 5432},
	"mysql":    {"stark_mysql", 3306},
}

func rootPass(kind string) string {
	switch kind {
	case "mongo":
		return env("MONGO_ROOT_PASSWORD", "change-me")
	case "postgres":
		return env("POSTGRES_PASSWORD", "change-me")
	}
	return env("MYSQL_ROOT_PASSWORD", "change-me")
}

func engineRunning(kind string) bool {
	e, ok := engines[kind]
	if !ok {
		return false
	}
	out, err := docker("inspect", "-f", "{{.State.Running}}", e.Container)
	return err == nil && out == "true"
}

func createManaged(kind, owner string) (string, string, error) {
	e := engines[kind]
	id := "d" + newToken()[:10]
	pass := newToken()[:24]
	n := ensureUserNet(owner)
	_, _ = docker("network", "connect", n, e.Container)
	var out string
	var err error
	switch kind {
	case "mongo":
		js := fmt.Sprintf(`db.getSiblingDB(%q).createUser({user:%q,pwd:%q,roles:[{role:"readWrite",db:%q}]})`, id, id, pass, id)
		out, err = docker("exec", e.Container, "mongosh", "--quiet", "-u", "root", "-p", rootPass(kind), "--authenticationDatabase", "admin", "--eval", js)
		if err == nil {
			return id, fmt.Sprintf("mongodb://%s:%s@%s:27017/%s?authSource=%s", id, pass, e.Container, id, id), nil
		}
	case "postgres":
		out, err = docker("exec", "-e", "PGPASSWORD="+rootPass(kind), e.Container, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1",
			"-c", fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", id, pass),
			"-c", fmt.Sprintf("CREATE DATABASE %s OWNER %s", id, id),
			"-c", fmt.Sprintf("REVOKE ALL ON DATABASE %s FROM PUBLIC", id))
		if err == nil {
			return id, fmt.Sprintf("postgresql://%s:%s@%s:5432/%s", id, pass, e.Container, id), nil
		}
	case "mysql":
		sql := fmt.Sprintf("CREATE DATABASE `%s`; CREATE USER '%s'@'%%' IDENTIFIED BY '%s'; GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%%'; FLUSH PRIVILEGES;", id, id, pass, id, id)
		out, err = docker("exec", e.Container, "mysql", "-uroot", "-p"+rootPass(kind), "-e", sql)
		if err == nil {
			return id, fmt.Sprintf("mysql://%s:%s@%s:3306/%s", id, pass, e.Container, id), nil
		}
	}
	return "", "", fmt.Errorf("could not create database: %s", out)
}

func dropManaged(db DB) {
	e, ok := engines[db.Kind]
	if !ok || db.Ident == "" {
		return
	}
	id := db.Ident
	switch db.Kind {
	case "mongo":
		js := fmt.Sprintf(`db.getSiblingDB(%q).dropUser(%q); db.getSiblingDB(%q).dropDatabase()`, id, id, id)
		_, _ = docker("exec", e.Container, "mongosh", "--quiet", "-u", "root", "-p", rootPass(db.Kind), "--authenticationDatabase", "admin", "--eval", js)
	case "postgres":
		_, _ = docker("exec", "-e", "PGPASSWORD="+rootPass(db.Kind), e.Container, "psql", "-U", "postgres",
			"-c", fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", id), "-c", fmt.Sprintf("DROP ROLE IF EXISTS %s", id))
	case "mysql":
		sql := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`; DROP USER IF EXISTS '%s'@'%%';", id, id)
		_, _ = docker("exec", e.Container, "mysql", "-uroot", "-p"+rootPass(db.Kind), "-e", sql)
	}
}

/* ---------- handlers ---------- */

var dbNameRe = regexp.MustCompile(`^[A-Za-z0-9 _.\-]{1,40}$`)

func handleDBList(w http.ResponseWriter, r *http.Request) {
	u, _ := curUser(r)
	out := []DB{}
	store.read(func(d *Data) {
		for _, x := range d.DBs {
			if x.Owner == u.ID {
				out = append(out, x)
			}
		}
	})
	avail := map[string]bool{}
	for k := range engines {
		avail[k] = engineRunning(k)
	}
	jsonOut(w, 200, map[string]any{"dbs": out, "engines": avail, "limit": limitsFor(u).DBs})
}

func handleDBCreate(w http.ResponseWriter, r *http.Request) {
	u, _ := curUser(r)
	var in struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
		Mode string `json:"mode"`
		URI  string `json:"uri"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if !dbNameRe.MatchString(in.Name) {
		jsonErr(w, 400, "name: 1–40 chars (letters, numbers, space, - _ .)")
		return
	}
	lim := limitsFor(u)
	if dbCount(u.ID) >= lim.DBs {
		jsonErr(w, 409, fmt.Sprintf("your plan (%s) allows %d database(s) — upgrade or delete one", lim.Name, lim.DBs))
		return
	}
	rec := DB{ID: newToken()[:12], Owner: u.ID, Kind: in.Kind, Name: in.Name, Created: time.Now().Unix()}
	if in.Mode == "managed" {
		if _, ok := engines[in.Kind]; !ok {
			jsonErr(w, 400, "unknown database type")
			return
		}
		if !engineRunning(in.Kind) {
			jsonErr(w, 400, "this database engine is not enabled on the server yet — ask the admin, or connect an external database")
			return
		}
		ident, uri, err := createManaged(in.Kind, u.ID)
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		rec.Managed, rec.Ident, rec.URI = true, ident, uri
	} else {
		prefixes := map[string][]string{
			"mongo": {"mongodb://", "mongodb+srv://"}, "postgres": {"postgres://", "postgresql://"},
			"mysql": {"mysql://", "mariadb://"}, "redis": {"redis://", "rediss://"}, "other": {""},
		}
		pf, ok := prefixes[in.Kind]
		if !ok {
			jsonErr(w, 400, "unknown database type")
			return
		}
		in.URI = strings.TrimSpace(in.URI)
		good := false
		for _, p := range pf {
			if strings.HasPrefix(in.URI, p) {
				good = true
			}
		}
		if !good || len(in.URI) < 8 || len(in.URI) > 2000 || strings.ContainsAny(in.URI, "\r\n ") {
			jsonErr(w, 400, "connection string looks wrong for this database type")
			return
		}
		rec.URI = in.URI
	}
	store.with(func(d *Data) { d.DBs = append(d.DBs, rec) })
	jsonOut(w, 201, rec)
}

func getDB(w http.ResponseWriter, r *http.Request) (DB, bool) {
	u, _ := curUser(r)
	var out DB
	found := false
	store.read(func(d *Data) {
		for _, x := range d.DBs {
			if x.ID == r.PathValue("id") && (x.Owner == u.ID || u.Role == "admin") {
				out, found = x, true
				return
			}
		}
	})
	if !found {
		jsonErr(w, 404, "database not found")
	}
	return out, found
}

func handleDBDelete(w http.ResponseWriter, r *http.Request) {
	db, ok := getDB(w, r)
	if !ok {
		return
	}
	if db.Managed {
		dropManaged(db)
	}
	store.with(func(d *Data) {
		keep := make([]DB, 0, len(d.DBs))
		for _, x := range d.DBs {
			if x.ID != db.ID {
				keep = append(keep, x)
			}
		}
		d.DBs = keep
	})
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func privateHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return true
		}
	}
	return false
}

func handleDBTest(w http.ResponseWriter, r *http.Request) {
	db, ok := getDB(w, r)
	if !ok {
		return
	}
	if db.Managed {
		if engineRunning(db.Kind) {
			jsonOut(w, 200, map[string]any{"ok": true, "msg": "built-in server is running"})
		} else {
			jsonOut(w, 200, map[string]any{"ok": false, "msg": "built-in server is not running"})
		}
		return
	}
	u, err := url.Parse(db.URI)
	if err != nil || u.Hostname() == "" {
		jsonOut(w, 200, map[string]any{"ok": false, "msg": "cannot read the host from this connection string"})
		return
	}
	if u.Scheme == "mongodb+srv" {
		jsonOut(w, 200, map[string]any{"ok": true, "msg": "Atlas SRV link — host can't be TCP-tested, your app will resolve it"})
		return
	}
	host := u.Hostname()
	if privateHost(host) {
		jsonOut(w, 200, map[string]any{"ok": false, "msg": "private / local addresses cannot be tested"})
		return
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"mongodb": "27017", "postgres": "5432", "postgresql": "5432", "mysql": "3306", "mariadb": "3306", "redis": "6379", "rediss": "6379"}[u.Scheme]
	}
	if port == "" {
		jsonOut(w, 200, map[string]any{"ok": false, "msg": "port missing in the connection string"})
		return
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)
	if err != nil {
		jsonOut(w, 200, map[string]any{"ok": false, "msg": "cannot reach " + host + ":" + port + " — check host, port and firewall / IP allow-list"})
		return
	}
	c.Close()
	jsonOut(w, 200, map[string]any{"ok": true, "msg": "server reachable ✓ (login is checked by your app)"})
}

var attachKeys = map[string][]string{
	"mongo": {"MONGODB_URI", "MONGO_URL"}, "postgres": {"DATABASE_URL", "POSTGRES_URL"},
	"mysql": {"MYSQL_URL"}, "redis": {"REDIS_URL"}, "other": {"DB_URL"},
}

// POST /api/projects/{id}/attach  or  /detach   {"dbId":"…"}
func handleAttach(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	var in struct {
		DBID string `json:"dbId"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	var db DB
	found := false
	store.read(func(d *Data) {
		for _, x := range d.DBs {
			if x.ID == in.DBID && x.Owner == p.Owner {
				db, found = x, true
			}
		}
	})
	if !found {
		jsonErr(w, 404, "database not found")
		return
	}
	detach := strings.HasSuffix(r.URL.Path, "/detach")
	store.update(p.ID, func(x *Project) {
		e := map[string]string{}
		for k, v := range x.Env {
			e[k] = v
		}
		for _, k := range attachKeys[db.Kind] {
			if detach {
				if e[k] == db.URI {
					delete(e, k)
				}
			} else {
				e[k] = db.URI
			}
		}
		x.Env = e
	})
	jsonOut(w, 200, map[string]bool{"ok": true})
}
