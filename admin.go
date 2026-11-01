package main

import (
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type userV struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Plan      string `json:"plan"`
	Active    string `json:"active"`
	PlanUntil int64  `json:"planUntil"`
	AutoRenew bool   `json:"autoRenew"`
	Verified  bool   `json:"verified"`
	Banned    bool   `json:"banned"`
	Created   int64  `json:"created"`
	LastLogin int64  `json:"lastLogin"`
	Projects  int    `json:"projects"`
	DBs       int    `json:"dbs"`
}

func handleAdminStats(w http.ResponseWriter, r *http.Request) {
	st := map[string]int{}
	store.read(func(d *Data) {
		st["users"] = len(d.Users)
		for _, u := range d.Users {
			if u.Role != "admin" && activePlanID(u) != "free" {
				st["premium"]++
			}
			if !u.Verified {
				st["unverified"]++
			}
		}
		st["projects"] = len(d.Projects)
		st["dbs"] = len(d.DBs)
		for _, p := range d.Payments {
			if p.Status == "pending" {
				st["pending"]++
			}
		}
		for _, k := range d.Keys {
			if k.UsedBy == "" {
				st["keysFree"]++
			}
		}
	})
	running := 0
	if out, err := docker("ps", "-q", "--filter", "label=stark.project"); err == nil && out != "" {
		running = len(strings.Fields(out))
	}
	st["running"] = running
	jsonOut(w, 200, st)
}

func handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	out := []userV{}
	store.read(func(d *Data) {
		pc, dc := map[string]int{}, map[string]int{}
		for _, p := range d.Projects {
			pc[p.Owner]++
		}
		for _, x := range d.DBs {
			dc[x.Owner]++
		}
		for _, u := range d.Users {
			if q != "" && !strings.Contains(u.Email, q) {
				continue
			}
			out = append(out, userV{ID: u.ID, Email: u.Email, Role: u.Role, Plan: u.Plan, Active: activePlanID(u), PlanUntil: u.PlanUntil,
				AutoRenew: u.AutoRenew, Verified: u.Verified, Banned: u.Banned, Created: u.Created, LastLogin: u.LastLogin, Projects: pc[u.ID], DBs: dc[u.ID]})
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	if len(out) > 500 {
		out = out[:500]
	}
	jsonOut(w, 200, out)
}

func deleteUserCascade(uid string) {
	for _, p := range store.projectsOf(uid) {
		destroyProject(p)
	}
	var dbs []DB
	store.read(func(d *Data) {
		for _, x := range d.DBs {
			if x.Owner == uid {
				dbs = append(dbs, x)
			}
		}
	})
	for _, x := range dbs {
		if x.Managed {
			dropManaged(x)
		}
	}
	store.with(func(d *Data) {
		keepD := make([]DB, 0, len(d.DBs))
		for _, x := range d.DBs {
			if x.Owner != uid {
				keepD = append(keepD, x)
			}
		}
		d.DBs = keepD
		keepU := make([]User, 0, len(d.Users))
		for _, u := range d.Users {
			if u.ID != uid {
				keepU = append(keepU, u)
			}
		}
		d.Users = keepU
	})
	revokeSessions(uid, "")
	dropUserNet(uid)
}

func handleAdminUserAct(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, ok := userByID(id)
	if !ok {
		jsonErr(w, 404, "user not found")
		return
	}
	var in struct {
		Action   string `json:"action"`
		Plan     string `json:"plan"`
		Months   int    `json:"months"`
		Password string `json:"password"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	if t.Role == "admin" && in.Action != "setpass" {
		jsonErr(w, 400, "the admin account cannot be changed here")
		return
	}
	switch in.Action {
	case "setplan":
		if in.Plan == "free" {
			updateUser(id, func(u *User) { u.Plan, u.PlanUntil, u.AutoRenew = "free", 0, false })
		} else {
			if in.Months < 1 || in.Months > 120 {
				jsonErr(w, 400, "months must be 1–120")
				return
			}
			pl := planByID(in.Plan)
			if pl.ID != in.Plan {
				jsonErr(w, 400, "unknown plan")
				return
			}
			until := time.Now().Add(time.Duration(in.Months) * 30 * 24 * time.Hour).Unix()
			updateUser(id, func(u *User) { u.Plan, u.PlanUntil = in.Plan, until })
		}
		go enforceQuota(id)
	case "ban":
		updateUser(id, func(u *User) { u.Banned = true })
		revokeSessions(id, "")
		for _, p := range store.projectsOf(id) {
			_, _ = docker("stop", cname(p))
		}
	case "unban":
		updateUser(id, func(u *User) { u.Banned = false })
	case "verify":
		updateUser(id, func(u *User) { u.Verified = true })
	case "setpass":
		if len(in.Password) < 8 || len(in.Password) > 128 {
			jsonErr(w, 400, "password must be 8–128 characters")
			return
		}
		ph := hashPass(in.Password)
		updateUser(id, func(u *User) { u.PassHash = ph })
		revokeSessions(id, "")
	case "delete":
		deleteUserCascade(id)
	default:
		jsonErr(w, 400, "unknown action")
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}

/* ---------- keys ---------- */

func handleAdminKeys(w http.ResponseWriter, r *http.Request) {
	out := []Key{}
	store.read(func(d *Data) {
		for i := len(d.Keys) - 1; i >= 0; i-- {
			out = append(out, d.Keys[i])
		}
	})
	if len(out) > 1000 {
		out = out[:1000]
	}
	jsonOut(w, 200, out)
}

func handleAdminKeyGen(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Plan       string `json:"plan"`
		Months     int    `json:"months"`
		Uses       int    `json:"uses"`
		ExpireDays int    `json:"expireDays"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	pl := planByID(in.Plan)
	if pl.ID != in.Plan || pl.ID == "free" {
		jsonErr(w, 400, "choose a paid plan")
		return
	}
	if in.Months < 1 || in.Months > 36 {
		jsonErr(w, 400, "months must be 1–36")
		return
	}
	if in.Uses < 1 || in.Uses > 10000 {
		jsonErr(w, 400, "members must be 1–10000")
		return
	}
	if in.ExpireDays < 0 || in.ExpireDays > 3650 {
		jsonErr(w, 400, "expiry days must be 0–3650 (0 = never)")
		return
	}
	var exp int64
	if in.ExpireDays > 0 {
		exp = time.Now().Add(time.Duration(in.ExpireDays) * 24 * time.Hour).Unix()
	}
	code := genKeyCode()
	store.with(func(d *Data) {
		d.Keys = append(d.Keys, Key{Code: code, Plan: in.Plan, Months: in.Months, Uses: in.Uses, ExpiresAt: exp, Created: time.Now().Unix()})
	})
	jsonOut(w, 200, map[string]any{"codes": []string{code}})
}

func handleAdminKeyDel(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	store.with(func(d *Data) {
		keep := make([]Key, 0, len(d.Keys))
		for _, k := range d.Keys {
			if k.Code != code {
				keep = append(keep, k)
			}
		}
		d.Keys = keep
	})
	jsonOut(w, 200, map[string]bool{"ok": true})
}

/* ---------- payments ---------- */

func handleAdminPayments(w http.ResponseWriter, r *http.Request) {
	out := []Payment{}
	store.read(func(d *Data) {
		for i := len(d.Payments) - 1; i >= 0 && len(out) < 300; i-- {
			out = append(out, d.Payments[i])
		}
	})
	jsonOut(w, 200, out)
}

func handleAdminPayAct(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Action string `json:"action"`
	}
	if jsonDecode(r, &in) != nil || (in.Action != "approve" && in.Action != "reject") {
		jsonErr(w, 400, "action must be approve or reject")
		return
	}
	var pay Payment
	found := false
	store.with(func(d *Data) {
		for i := range d.Payments {
			p := &d.Payments[i]
			if p.ID == id && p.Status == "pending" {
				if in.Action == "approve" {
					p.Status = "approved"
				} else {
					p.Status = "rejected"
				}
				p.Decided = time.Now().Unix()
				pay, found = *p, true
				return
			}
		}
	})
	if !found {
		jsonErr(w, 404, "pending payment not found")
		return
	}
	if in.Action == "approve" {
		if err := applyPlan(pay.UserID, pay.Plan, pay.Months); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		paid := pay.Amount
		if paid == "" {
			paid = "Paid"
		}
		notifyPlan(pay.UserID, pay.Plan, paid, pay.ID)
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}

/* ---------- plans / projects / settings ---------- */

func handleAdminPlansSave(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Plans []Plan `json:"plans"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	for _, p := range in.Plans {
		if p.RAM < 64 || p.CPU < 0.1 || p.Disk < 1 || p.Projects < 1 || p.DBs < 0 || p.Price < 0 || strings.TrimSpace(p.Name) == "" {
			jsonErr(w, 400, "invalid values for plan "+p.ID)
			return
		}
	}
	store.with(func(d *Data) {
		for i := range d.Plans {
			for _, n := range in.Plans {
				if n.ID == d.Plans[i].ID {
					n.Name = strings.TrimSpace(n.Name)
					d.Plans[i] = n
				}
			}
		}
	})
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func handleAdminProjects(w http.ResponseWriter, r *http.Request) {
	out := []ProjectView{}
	for _, p := range store.snapshot() {
		out = append(out, view(p))
	}
	jsonOut(w, 200, out)
}

const masked = "***set***"

func mask(s string) string {
	if s == "" {
		return ""
	}
	return masked
}

func handleAdminSettingsGet(w http.ResponseWriter, r *http.Request) {
	c := cfg()
	c.SMTPPass, c.StripeSecret, c.StripeWebhook, c.CryptoKey = mask(c.SMTPPass), mask(c.StripeSecret), mask(c.StripeWebhook), mask(c.CryptoKey)
	jsonOut(w, 200, map[string]any{"settings": c, "autoDomain": baseDomain(), "ip": publicIP(), "panelDomain": os.Getenv("PANEL_DOMAIN")})
}

func handleAdminSettingsSave(w http.ResponseWriter, r *http.Request) {
	var in Settings
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	old := cfg()
	keep := func(n, o string) string {
		if n == masked {
			return o
		}
		return strings.TrimSpace(n)
	}
	in.SMTPPass, in.StripeSecret, in.StripeWebhook = keep(in.SMTPPass, old.SMTPPass), keep(in.StripeSecret, old.StripeSecret), keep(in.StripeWebhook, old.StripeWebhook)
	in.CryptoKey = keep(in.CryptoKey, old.CryptoKey)
	in.CryptoMerchant = strings.TrimSpace(in.CryptoMerchant)
	in.BaseDomain = strings.Trim(strings.ToLower(strings.TrimSpace(in.BaseDomain)), ".*")
	in.PublicIP = strings.TrimSpace(in.PublicIP)
	in.Currency = strings.ToLower(strings.TrimSpace(in.Currency))
	if len(in.Currency) != 3 {
		in.Currency = "usd"
	}
	in.SupportURL = strings.TrimSpace(in.SupportURL)
	if !strings.HasPrefix(in.SupportURL, "https://") {
		in.SupportURL = old.SupportURL
	}
	in.SMTPHost, in.SMTPPort, in.SMTPUser, in.SMTPFrom = strings.TrimSpace(in.SMTPHost), strings.TrimSpace(in.SMTPPort), strings.TrimSpace(in.SMTPUser), strings.TrimSpace(in.SMTPFrom)
	if len(in.PayInstructions) > 2000 {
		in.PayInstructions = in.PayInstructions[:2000]
	}
	in.PayWebhookSecret = strings.TrimSpace(in.PayWebhookSecret)
	if in.PayWebhookSecret == "" {
		in.PayWebhookSecret = old.PayWebhookSecret
	}
	saveSettings(in)
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func handleAdminTestMail(w http.ResponseWriter, r *http.Request) {
	var in struct {
		To string `json:"to"`
	}
	if jsonDecode(r, &in) != nil || !emailRe.MatchString(normEmail(in.To)) {
		jsonErr(w, 400, "enter a valid email")
		return
	}
	if err := sendMail(normEmail(in.To), "StarkHost test email", "If you can read this, your SMTP settings work."); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}
