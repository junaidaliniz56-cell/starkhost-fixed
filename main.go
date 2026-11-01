package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	_ "novahost/dotenv"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

//go:embed static/*
var staticFS embed.FS

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

var (
	dataDir        = env("DATA_DIR", "/srv/hosting")
	panelContainer = env("PANEL_CONTAINER", "stark_panel")
	publish        = env("PUBLISH_PORTS", "false") == "true"
	nameRe         = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}$`)
)

func newToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	jsonOut(w, code, map[string]string{"error": msg})
}

// the admin account is controlled by ADMIN_USER / ADMIN_PASS in .env
func ensureAdmin() {
	login := strings.ToLower(strings.TrimSpace(env("ADMIN_USER", "admin")))
	pass := os.Getenv("ADMIN_PASS")
	f := filepath.Join(dataDir, ".admin_pass")
	if pass == "" {
		syncDown("admin_pass", f)
		if b, err := os.ReadFile(f); err == nil && strings.TrimSpace(string(b)) != "" {
			pass = strings.TrimSpace(string(b))
		} else {
			pass = newToken()[:16]
			_ = os.WriteFile(f, []byte(pass), 0600)
			syncUp("admin_pass", []byte(pass))
		}
		log.Printf("ADMIN LOGIN  user=%s  password=%s", login, pass)
	}
	if len(pass) < 10 {
		log.Println("WARNING: ADMIN_PASS is short — use 12+ characters")
	}
	hash := hashPass(pass)
	store.with(func(d *Data) {
		for i := range d.Users {
			u := &d.Users[i]
			if u.Role == "admin" {
				u.Email = login
				if !checkPass(pass, u.PassHash) {
					u.PassHash = hash
				}
				u.Verified, u.Banned = true, false
				adminID = u.ID
				return
			}
		}
		u := User{ID: newToken()[:12], Email: login, Role: "admin", Verified: true, Created: time.Now().Unix(), Plan: "free", PassHash: hash}
		d.Users = append(d.Users, u)
		adminID = u.ID
	})
	store.with(func(d *Data) {
		for i := range d.Projects {
			if d.Projects[i].Owner == "" {
				d.Projects[i].Owner = adminID
			}
		}
	})
	seedAdminDB("mongo", "MongoDB Atlas", "ADMIN_DB_MONGO")
	seedAdminDB("postgres", "PostgreSQL (Aiven)", "ADMIN_DB_POSTGRES")
	seedAdminDB("mysql", "MySQL (Aiven)", "ADMIN_DB_MYSQL")
}

// puts your own cloud databases (from .env) into the admin account's Databases list
func seedAdminDB(kind, name, envKey string) {
	uri := strings.TrimSpace(os.Getenv(envKey))
	if uri == "" {
		return
	}
	if strings.Contains(uri, "<db_password>") {
		// the Atlas password can live in its own variable, so it never has to be edited inside the URI
		if pw := os.Getenv(envKey + "_PASSWORD"); pw != "" {
			uri = strings.ReplaceAll(uri, "<db_password>", url.QueryEscape(pw))
		}
	}
	if strings.Contains(uri, "<") {
		log.Printf("%s still contains <db_password> — set %s_PASSWORD in .env", envKey, envKey)
		return
	}
	store.with(func(d *Data) {
		for _, x := range d.DBs {
			if x.Owner == adminID && x.URI == uri {
				return
			}
		}
		d.DBs = append(d.DBs, DB{ID: newToken()[:12], Owner: adminID, Kind: kind, Name: name, URI: uri, Created: time.Now().Unix()})
	})
}

func main() {
	if os.Getenv("DATA_DIR") == "" {
		if err := os.MkdirAll(dataDir, 0755); err != nil { // e.g. shared hosts where /srv is read-only
			dataDir = "./data"
			log.Printf("cannot use /srv/hosting, saving data in %s", dataDir)
		}
	}
	for _, d := range []string{"projects", "logs"} {
		if err := os.MkdirAll(filepath.Join(dataDir, d), 0755); err != nil {
			log.Fatal(err)
		}
	}
	mongoInit()
	store = &Store{file: filepath.Join(dataDir, "state.json")}
	store.load()
	loadSettings()
	ensureAdmin()
	go refreshIP()
	go planWatcher()
	go statsLoop()
	go ensureAllNets()

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// public
	mux.HandleFunc("POST /api/auth/signup", handleSignup)
	mux.HandleFunc("POST /api/auth/verify", handleVerify)
	mux.HandleFunc("POST /api/auth/resend", handleResend)
	mux.HandleFunc("POST /api/auth/login", handleLogin)
	mux.HandleFunc("POST /api/auth/forgot", handleForgot)
	mux.HandleFunc("POST /api/auth/reset", handleReset)
	mux.HandleFunc("POST /api/auth/logout", handleLogout)
	mux.HandleFunc("GET /api/plans", handlePlans)
	mux.HandleFunc("POST /api/pay/stripe", handleStripeWebhook)
	mux.HandleFunc("POST /api/pay/webhook", handlePayWebhook)
	mux.HandleFunc("POST /api/pay/cryptomus", handleCryptoWebhook)
	mux.HandleFunc("POST /hook/{id}/{secret}", handleHook)
	mux.HandleFunc("GET /internal/ask", handleAsk)

	// account
	mux.HandleFunc("GET /api/me", handleMe)
	mux.HandleFunc("POST /api/auth/password", protect(handleChangePass))
	mux.HandleFunc("POST /api/redeem", protect(handleRedeem))
	mux.HandleFunc("GET /api/billing/history", protect(handleHistory))
	mux.HandleFunc("POST /api/billing/manual", protect(handleManualPay))
	mux.HandleFunc("POST /api/billing/checkout", protect(handleCheckout))
	mux.HandleFunc("POST /api/billing/crypto", protect(handleCrypto))

	// databases
	mux.HandleFunc("GET /api/dbs", protect(handleDBList))
	mux.HandleFunc("POST /api/dbs", protect(handleDBCreate))
	mux.HandleFunc("POST /api/dbs/{id}/test", protect(handleDBTest))
	mux.HandleFunc("DELETE /api/dbs/{id}", protect(handleDBDelete))

	// projects
	mux.HandleFunc("GET /api/projects", protect(handleList))
	mux.HandleFunc("POST /api/projects", protect(handleCreate))
	mux.HandleFunc("POST /api/projects/{id}/upload", protect(handleUpload))
	mux.HandleFunc("POST /api/projects/{id}/config", protect(handleConfig))
	mux.HandleFunc("POST /api/projects/{id}/env", protect(handleEnv))
	mux.HandleFunc("POST /api/projects/{id}/resources", protect(handleResources))
	mux.HandleFunc("POST /api/projects/{id}/attach", protect(handleAttach))
	mux.HandleFunc("POST /api/projects/{id}/detach", protect(handleAttach))
	mux.HandleFunc("POST /api/projects/{id}/domain", protect(handleDomainGen))
	mux.HandleFunc("POST /api/projects/{id}/domains", protect(handleDomainAdd))
	mux.HandleFunc("DELETE /api/projects/{id}/domains", protect(handleDomainDel))
	mux.HandleFunc("GET /api/projects/{id}/domains/check", protect(handleDomainCheck))
	mux.HandleFunc("GET /api/projects/{id}/logs", protect(handleLogs))
	mux.HandleFunc("GET /api/projects/{id}/logs/stream", protect(handleLogStream))
	mux.HandleFunc("GET /api/projects/{id}/deploylog", protect(handleDeployLog))
	mux.HandleFunc("POST /api/projects/{id}/files/upload", protect(handleFilesUpload))
	mux.HandleFunc("GET /api/projects/{id}/zip", protect(handleZip))
	mux.HandleFunc("GET /api/projects/{id}/files", protect(handleFiles))
	mux.HandleFunc("GET /api/projects/{id}/file", protect(handleFileGet))
	mux.HandleFunc("PUT /api/projects/{id}/file", protect(handleFilePut))
	mux.HandleFunc("DELETE /api/projects/{id}/file", protect(handleFileDel))
	mux.HandleFunc("POST /api/projects/{id}/{action}", protect(handleAction))
	mux.HandleFunc("DELETE /api/projects/{id}", protect(handleDelete))

	// admin
	mux.HandleFunc("GET /api/admin/stats", adminOnly(handleAdminStats))
	mux.HandleFunc("GET /api/admin/users", adminOnly(handleAdminUsers))
	mux.HandleFunc("POST /api/admin/users/{id}", adminOnly(handleAdminUserAct))
	mux.HandleFunc("GET /api/admin/users/{id}/zip", adminOnly(handleAdminUserZip))
	mux.HandleFunc("GET /api/admin/keys", adminOnly(handleAdminKeys))
	mux.HandleFunc("POST /api/admin/keys", adminOnly(handleAdminKeyGen))
	mux.HandleFunc("DELETE /api/admin/keys/{code}", adminOnly(handleAdminKeyDel))
	mux.HandleFunc("GET /api/admin/payments", adminOnly(handleAdminPayments))
	mux.HandleFunc("POST /api/admin/payments/{id}", adminOnly(handleAdminPayAct))
	mux.HandleFunc("GET /api/admin/plans", adminOnly(handlePlansGet))
	mux.HandleFunc("POST /api/admin/plans", adminOnly(handleAdminPlansSave))
	mux.HandleFunc("GET /api/admin/projects", adminOnly(handleAdminProjects))
	mux.HandleFunc("GET /api/admin/settings", adminOnly(handleAdminSettingsGet))
	mux.HandleFunc("POST /api/admin/settings", adminOnly(handleAdminSettingsSave))
	mux.HandleFunc("POST /api/admin/testmail", adminOnly(handleAdminTestMail))

	addr := ":" + env("PORT", "8085")
	log.Println("Stark-Host listening on", addr)
	srv := &http.Server{Addr: addr, Handler: hostRouter(secHeaders(mux)), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
